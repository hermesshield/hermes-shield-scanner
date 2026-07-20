"""S8.95 — the AI-phase live feed (ai_stream) is DISPLAY-ONLY.

The whole-repo finder and the per-file AI tier shell out to the local `claude` CLI, which blocks up to 600s
with no output — the scan LOOKS hung. ai_stream renders a live feed on STDERR (stream-json when the CLI
supports it, else a spinner heartbeat) WITHOUT changing what the caller parses. These tests lock the
contract:

  (1) BYTE-IDENTICAL RESULT — the final text accumulated from a canned stream-json event sequence equals the
      canned blocking `claude -p` stdout, so `_parse` yields the SAME findings either way.
  (2) TTY-GATED — feed_enabled() is False on a non-TTY / NO_COLOR / opt-out; run_claude then takes the plain
      blocking path and emits NOTHING (no stderr progress).
  (3) FAIL-LOUD INTACT — a streamed refusal, a streamed nonzero-exit, and a streamed timeout each still raise
      the finder's AIAgentError exactly as the blocking path did.
  (4) NON-TTY = NO stderr progress — a real run_claude call on a non-TTY stream writes nothing to stderr.
"""
from __future__ import annotations

import io
import subprocess

import pytest

from hermes_shield import ai_stream
from hermes_shield import ai_finder
from hermes_shield.ai_assist import AIAgentError


# A canned finder answer, in BOTH transports. The blocking path prints the array as text-mode stdout (with
# the trailing newline `claude -p` adds); the stream-json path carries the same array in the terminal
# `result` event after two read tool-uses. The two must parse to the SAME findings.
_ARRAY = ('[{"file": "agent.py", "line": 2, "call": "orchestrator.delegate(task)", '
          '"capability": "cross-file-delegation", "why": "LLM-chosen delegate", '
          '"evidence_path": ["agent.py:2"], "confidence": 0.8}]')

_BLOCKING_STDOUT = _ARRAY + "\n"   # what `claude -p` (text mode) writes

_STREAM_LINES = [
    '{"type":"system","subtype":"init","cwd":"/repo","model":"claude-sonnet-5","tools":["Read","Grep","Glob"]}',
    '{"type":"assistant","message":{"content":[{"type":"tool_use","id":"t1","name":"Read","input":{"file_path":"agent.py"}}]}}',
    '{"type":"assistant","message":{"content":[{"type":"tool_use","id":"t2","name":"Grep","input":{"pattern":"delegate"}}]}}',
    '{"type":"assistant","message":{"content":[{"type":"text","text":"' + _ARRAY.replace('"', '\\"') + '"}]}}',
    '{"type":"result","subtype":"success","is_error":false,"result":"' + _ARRAY.replace('"', '\\"') + '"}',
]


# --- (1) byte-identical parsed result: stream-json accumulation == blocking stdout ------------------

def test_stream_result_matches_blocking_stdout_findings():
    """The result text accumulated from the canned stream-json events parses to the EXACT same findings as
    the canned blocking stdout — streaming is display-only, the data is identical."""
    streamed = ai_stream.accumulate_result(_STREAM_LINES)
    # the accumulated result is the array text (byte-identical modulo the trailing newline the blocking
    # path carries — irrelevant to the JSON parse, which both sides run through _json_array).
    assert streamed == _ARRAY
    assert ai_finder._parse(streamed) == ai_finder._parse(_BLOCKING_STDOUT)
    # and the findings are real (not an empty coincidence)
    parsed = ai_finder._parse(streamed)
    assert len(parsed) == 1 and parsed[0]["file"] == "agent.py"


def test_stream_empty_result_matches_blocking_empty():
    """An empty finding set: stream `result":"[]"` accumulates to "[]" and parses identically to blocking
    "[]\\n" — a genuine, non-refusal zero on both transports."""
    empty_stream = [
        '{"type":"system","subtype":"init","model":"claude-sonnet-5"}',
        '{"type":"result","subtype":"success","is_error":false,"result":"[]"}',
    ]
    streamed = ai_stream.accumulate_result(empty_stream)
    assert streamed == "[]"
    assert ai_finder._parse(streamed) == ai_finder._parse("[]\n") == []


def test_describe_event_surfaces_tool_uses_and_result():
    """The event describer turns tool_use events into readable feed lines and captures the final result."""
    perm1, act1, res1 = ai_stream.describe_event(
        {"type": "assistant", "message": {"content": [
            {"type": "tool_use", "name": "Read", "input": {"file_path": "agent/runner.py"}}]}})
    assert perm1 == ["→ Read agent/runner.py"] and res1 is None and act1 == "Read agent/runner.py"

    perm2, _, res2 = ai_stream.describe_event(
        {"type": "result", "subtype": "success", "result": _ARRAY})
    assert perm2 == [] and res2 == _ARRAY


# --- (2) TTY-gating: feed_enabled() honours isatty + opt-outs --------------------------------------

class _FakeTTY(io.StringIO):
    def isatty(self):
        return True


def test_feed_disabled_on_non_tty():
    assert ai_stream.feed_enabled(io.StringIO()) is False       # StringIO.isatty() -> False


def test_feed_enabled_on_tty(monkeypatch):
    # feed_enabled() reads process-wide opt-out env (NO_COLOR / *_NO_BANNER / *_AI_NO_STREAM). A prior
    # --quiet scan in the same session sets HERMES_SHIELD_AI_NO_STREAM process-wide, so clear the opt-outs
    # to test the isatty gate hermetically (order-independent).
    for _v in ("NO_COLOR", "HERMES_SHIELD_NO_BANNER", "HERMES_SHIELD_AI_NO_STREAM"):
        monkeypatch.delenv(_v, raising=False)
    assert ai_stream.feed_enabled(_FakeTTY()) is True


@pytest.mark.parametrize("var", ["NO_COLOR", "HERMES_SHIELD_NO_BANNER", "HERMES_SHIELD_AI_NO_STREAM"])
def test_feed_disabled_by_optout_env(monkeypatch, var):
    monkeypatch.setenv(var, "1")
    assert ai_stream.feed_enabled(_FakeTTY()) is False          # opt-out beats a TTY


# --- (3) run_claude on a non-TTY writes NO stderr progress and returns the blocking triple ----------

def test_run_claude_non_tty_writes_no_stderr_progress(monkeypatch):
    """On a non-TTY stream run_claude takes the plain blocking path: it returns (stdout, rc, stderr) and
    emits NOTHING to the stderr stream (no spinner, no feed)."""
    captured = io.StringIO()   # not a TTY

    class _Proc:
        returncode = 0
        stdout = _BLOCKING_STDOUT
        stderr = ""

    monkeypatch.setattr(ai_stream.subprocess, "run", lambda *a, **k: _Proc())
    out, rc, err = ai_stream.run_claude("/usr/bin/claude", "prompt", model="sonnet",
                                        allowed_tools="Read,Grep,Glob", stream=captured)
    assert (out, rc, err) == (_BLOCKING_STDOUT, 0, "")
    assert captured.getvalue() == "", "a non-TTY run must emit no stderr progress"


def test_run_claude_non_tty_builds_the_historical_finder_argv(monkeypatch):
    """Byte-identical command: the plain path builds the exact historical finder argv (no stream-json flags)."""
    seen = {}

    class _Proc:
        returncode = 0
        stdout = _BLOCKING_STDOUT
        stderr = ""

    def _fake_run(cmd, *a, **k):
        seen["cmd"] = cmd
        return _Proc()

    monkeypatch.setattr(ai_stream.subprocess, "run", _fake_run)
    ai_stream.run_claude("/usr/bin/claude", "PROMPT", model="sonnet",
                         allowed_tools="Read,Grep,Glob", stream=io.StringIO())
    assert seen["cmd"] == ["/usr/bin/claude", "-p", "PROMPT", "--model", "sonnet",
                           "--allowedTools", "Read,Grep,Glob"]


# --- (4) fail-loud preserved through the streamed path ---------------------------------------------
# The finder's _finder_agent diverts to ai_stream.run_claude ONLY on a TTY. We force feed_enabled True and
# stub run_claude to emit each failure shape, proving the finder's guards still raise.

def _finder_run_with_streamed(monkeypatch, out, rc, err):
    monkeypatch.setattr(ai_finder.shutil, "which", lambda _n: "/usr/bin/claude")
    monkeypatch.setattr(ai_finder.ai_stream, "feed_enabled", lambda *a, **k: True)
    monkeypatch.setattr(ai_finder.ai_stream, "run_claude",
                        lambda *a, **k: (out, rc, err))
    return ai_finder._finder_agent("sonnet", 5)


def test_streamed_refusal_still_fails_loud(monkeypatch):
    """A streamed content-refusal (exit 0, refusal prose in the accumulated result) must still raise."""
    refusal = ("API Error: safeguards flagged this message as violating our usage policies. "
               "Claude Code can't respond to this request. https://www.anthropic.com/legal/aup")
    run = _finder_run_with_streamed(monkeypatch, refusal, 0, "")
    with pytest.raises(AIAgentError) as ei:
        run("prompt", "/tmp")
    assert "refused" in str(ei.value).lower()


def test_streamed_nonzero_exit_nonjson_still_fails_loud(monkeypatch):
    """A streamed nonzero exit whose accumulated result is not a top-level JSON array must still raise."""
    run = _finder_run_with_streamed(monkeypatch, "diagnostic chatter, no array", 1, "boom")
    with pytest.raises(AIAgentError):
        run("prompt", "/tmp")


def test_streamed_valid_array_on_nonzero_exit_is_kept(monkeypatch):
    """A streamed nonzero exit that DID carry a valid top-level JSON array is NOT a failure (the carve-out)."""
    run = _finder_run_with_streamed(monkeypatch, _ARRAY, 2, "")
    out = run("prompt", "/tmp")
    assert ai_finder._parse(out) and ai_finder._parse(out)[0]["file"] == "agent.py"


def test_streamed_timeout_still_fails_loud(monkeypatch):
    """A timeout raised from the streamed path surfaces as the finder's AIAgentError timeout message."""
    monkeypatch.setattr(ai_finder.shutil, "which", lambda _n: "/usr/bin/claude")
    monkeypatch.setattr(ai_finder.ai_stream, "feed_enabled", lambda *a, **k: True)

    def _boom(*a, **k):
        raise subprocess.TimeoutExpired(["claude"], 5)

    monkeypatch.setattr(ai_finder.ai_stream, "run_claude", _boom)
    run = ai_finder._finder_agent("sonnet", 5)
    with pytest.raises(AIAgentError) as ei:
        run("prompt", "/tmp")
    assert "timed out" in str(ei.value).lower()


def test_streamed_success_returns_parsed_findings(monkeypatch):
    """The happy path: a streamed success returns the accumulated array which parses to real findings."""
    run = _finder_run_with_streamed(monkeypatch, _ARRAY, 0, "")
    out = run("prompt", "/tmp")
    assert ai_finder._parse(out) == ai_finder._parse(_BLOCKING_STDOUT)
