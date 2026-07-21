"""Close two fail-loud defects in the per-file --ai tier (ai_assist.claude_agent + ai_tier.apply).

The --ai-deep agentic finder (ai_finder) already had this discipline; these lock the SAME contract for the
per-file --ai tier that ai_assist drives:

  DEFECT 1 — silent clean on refusal + cache poison. An exit-0 claude AUP content-refusal used to fall
  through _parse_json as [] -> ai_status="ok" ("(none - AI tier off or nothing found)"), and the empty
  non-result was CACHED under the same key -> the phantom clean replayed forever. Now:
    * an exit-0 content refusal RAISES AIAgentError -> the tier records a VISIBLE ai_status="failed";
    * the refusal is NEVER written to the cache (a later genuine run makes a REAL call, not a cache replay);
    * a nonzero exit without a parseable top-level JSON array is likewise a VISIBLE failure;
    * a genuine findings array IS cached (and replays without a new subprocess call).

  DEFECT 2 — cache-write crash. The FIRST --ai run into a fresh output dir crashed writing
  .hermes_shield_ai_cache.json ([Errno 2] — outputs/ not yet created), discarding the AI findings. Now the
  cache write makedirs(parent) first, so a first run into a fresh dir writes the cache without crashing.

All findings/secrets below are SYNTHETIC; the claude subprocess is mocked — no CLI is launched.
"""
from __future__ import annotations

import json

import pytest

from hermes_shield import ai_assist, ai_tier

# a prod, risk-hinted (subprocess) source with exactly one dangerous call on line 3 -> a valid --ai target
_SRC = (
    "import subprocess\n"          # 1
    "def run(cmd):\n"              # 2
    "    subprocess.run(cmd, shell=True)\n"  # 3
)

_REFUSAL = ("API Error: safeguards flagged this message as violating our usage policies. "
            "Claude Code can't respond to this request. https://www.anthropic.com/legal/aup")

_GENUINE = json.dumps([{"line": 3, "call": "subprocess.run(cmd, shell=True)",
                        "capability": "code_exec", "why": "shell exec", "confidence": 0.9}])


def _proc(returncode: int, stdout: str, stderr: str = ""):
    class _P:
        pass
    _P.returncode = returncode
    _P.stdout = stdout
    _P.stderr = stderr
    return _P()


def _mock_claude(monkeypatch, returncode: int, stdout: str, stderr: str = ""):
    """Present a fake `claude` on PATH whose blocking subprocess returns (returncode, stdout, stderr)."""
    monkeypatch.setattr(ai_assist.shutil, "which", lambda _n: "/usr/bin/claude")
    monkeypatch.setattr(ai_assist.subprocess, "run",
                        lambda *a, **k: _proc(returncode, stdout, stderr))


# --- DEFECT 1: exit-0 content refusal -> VISIBLE failed, NOT a silent clean, NOT cached ----------------

def test_exit0_refusal_fails_loud_and_is_not_cached(monkeypatch, tmp_path):
    (tmp_path / "agent_app.py").write_text(_SRC)
    cache_path = tmp_path / "cache.json"
    _mock_claude(monkeypatch, 0, _REFUSAL)

    out = ai_tier.apply(tmp_path, [], budget=5, cache_path=cache_path)

    # VISIBLE failure, never the silent-zero "(none - AI tier off or nothing found)"
    assert out["ai_status"] == "failed"
    assert out["ai_surfaces_added"] == 0
    assert "ai_failure" in out and "refus" in out["ai_failure"].lower()
    # the empty non-result was NOT persisted (calls==0 -> no write) — no phantom `[]` on disk
    assert not cache_path.exists()


def test_exit0_refusal_not_cached_so_a_later_genuine_run_makes_a_real_call(monkeypatch, tmp_path):
    """The refusal must NOT poison the cache: a subsequent genuine run under the SAME key makes a REAL call
    and finds the surface — it does NOT replay a cached [] and report a phantom clean forever."""
    (tmp_path / "agent_app.py").write_text(_SRC)
    cache_path = tmp_path / "cache.json"

    _mock_claude(monkeypatch, 0, _REFUSAL)
    out1 = ai_tier.apply(tmp_path, [], budget=5, cache_path=cache_path)
    assert out1["ai_status"] == "failed" and out1["ai_calls"] == 0

    _mock_claude(monkeypatch, 0, _GENUINE)
    out2 = ai_tier.apply(tmp_path, [], budget=5, cache_path=cache_path)
    assert out2["ai_status"] == "ok"
    assert out2["ai_calls"] == 1, "a real call must be made — the refusal must not have been cached as []"
    assert out2["ai_surfaces_added"] == 1


# --- DEFECT 1: nonzero exit without a parseable JSON array -> VISIBLE failed ---------------------------

def test_nonzero_exit_with_nonjson_stdout_fails_loud(monkeypatch, tmp_path):
    (tmp_path / "agent_app.py").write_text(_SRC)
    cache_path = tmp_path / "cache.json"
    _mock_claude(monkeypatch, 1, "diagnostic chatter, no findings array here", "boom")

    out = ai_tier.apply(tmp_path, [], budget=5, cache_path=cache_path)

    assert out["ai_status"] == "failed"
    assert out["ai_surfaces_added"] == 0
    assert "ai_failure" in out
    assert not cache_path.exists()


# --- DEFECT 1: a genuine findings array IS cached (and replays without a new subprocess call) ----------

def test_genuine_result_is_cached_and_replays(monkeypatch, tmp_path):
    (tmp_path / "agent_app.py").write_text(_SRC)
    cache_path = tmp_path / "cache.json"

    _mock_claude(monkeypatch, 0, _GENUINE)
    out1 = ai_tier.apply(tmp_path, [], budget=5, cache_path=cache_path)
    assert out1["ai_status"] == "ok"
    assert out1["ai_calls"] == 1 and out1["ai_surfaces_added"] == 1
    assert cache_path.exists()
    assert len(json.loads(cache_path.read_text())) == 1        # one genuine entry persisted

    # a second run replays from cache — the subprocess must NOT be invoked again
    def _boom(*_a, **_k):
        raise AssertionError("claude must not be called on a cache hit")

    monkeypatch.setattr(ai_assist.subprocess, "run", _boom)
    out2 = ai_tier.apply(tmp_path, [], budget=5, cache_path=cache_path)
    assert out2["ai_status"] == "ok"
    assert out2["ai_calls"] == 0 and out2["ai_surfaces_added"] == 1  # replayed, not re-called


# --- DEFECT 2: first --ai run into a fresh output dir -> no [Errno 2] crash, cache written -------------

def test_first_ai_run_into_fresh_output_dir_writes_cache(monkeypatch, tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "agent_app.py").write_text(_SRC)
    fresh_out = tmp_path / "fresh" / "outputs"                  # does NOT exist yet
    assert not fresh_out.exists()

    _mock_claude(monkeypatch, 0, _GENUINE)
    # cache_dir threads the (not-yet-created) scan output dir; the cache lives under it.
    out = ai_tier.apply(root, [], budget=5, cache_dir=fresh_out)

    assert out["ai_status"] == "ok"                            # no crash discarded the findings
    assert out["ai_surfaces_added"] == 1
    cache_file = fresh_out / ".hermes_shield_ai_cache.json"
    assert cache_file.exists(), "DEFECT 2: the first-run cache write must makedirs(parent) first"
    assert len(json.loads(cache_file.read_text())) == 1


# --- unit-level: the ported guards behave exactly like ai_finder's ------------------------------------

def test_is_refusal_truth_table():
    assert ai_assist._is_refusal("[]") is False               # legitimate empty result
    assert ai_assist._is_refusal(_GENUINE) is False           # real findings array
    assert ai_assist._is_refusal("found nothing") is False    # terse prose, no signature
    assert ai_assist._is_refusal(_REFUSAL) is True            # real AUP refusal
    # a refusal carrying a stray, non-parsing bracket pair is STILL detected
    assert ai_assist._is_refusal(
        "I can't respond to this request [x] — usage policies. "
        "https://www.anthropic.com/legal/aup") is True


def test_toplevel_json_array_rejects_embedded_error_payload():
    overload = '{"type":"error","errors":[],"message":"overloaded_error: server overloaded"}'
    assert ai_assist._is_toplevel_json_array(overload) is None    # object, not a top-level array
    assert ai_assist._json_array(overload) == []                  # the embedded span DID parse (the old hole)
    assert ai_assist._is_toplevel_json_array(_GENUINE) is not None  # a genuine array is trusted
