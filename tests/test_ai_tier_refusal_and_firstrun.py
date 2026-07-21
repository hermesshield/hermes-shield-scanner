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

# The SHIP-BLOCKER shape: an exit-0 refusal phrased ENTIRELY OUTSIDE the historical marker set. Marker-based
# detection parsed this to [] -> "ok/nothing found" and CACHED it, replaying a fake all-clear forever. The
# structural guard (exit 0 + no parseable JSON array = protocol violation) now catches it on STRUCTURE.
_NON_MARKER_REFUSAL = "I'm sorry, but I won't be able to analyse this particular code for you."

# Arbitrary exit-0 prose carrying no JSON array at all (chatter / apology / truncation) — also a violation.
_PROSE_NO_JSON = "Sure — here is a summary of what the file appears to do, but I have no structured output."

_GENUINE = json.dumps([{"line": 3, "call": "subprocess.run(cmd, shell=True)",
                        "capability": "code_exec", "why": "shell exec", "confidence": 0.9}])

# --- THE EXACT EMBEDDED-`[]` SILENT-CLEANS (the live ship-blocker the previous green tests MISSED) --------
# Each is an exit-0 reply that the LENIENT `_json_array` bracketed-span arbiter accepted (it CONTAINS a
# parseable `[]`), so the old exit-0 guard passed it -> _parse_json -> [] -> ai_status="ok" AND it was
# CACHED, replaying a phantom clean forever. The STRICT `_is_toplevel_json_array` gate now fails each loud.
_OVERLOAD_ERR = '{"type":"error","errors":[],"message":"overloaded"}'        # (1) rate-limit/overload OBJECT
_REFUSAL_EMPTY = "I can't help with that. Here is an empty result: []"        # (2) refusal + trailing []
_CHATTY_EMPTY = "Sure, here is my analysis. I found no dangerous surfaces: []"  # (3) chatty prose + trailing []
_NONDICT_LIST = "[1]"                                                          # (4) a non-findings array

# every one of these exit-0 replies MUST become a VISIBLE per-tier FAILED and MUST NOT be cached
_SILENT_CLEANS = [
    pytest.param(_OVERLOAD_ERR, id="overload_error_object"),
    pytest.param(_REFUSAL_EMPTY, id="refusal_with_trailing_empty"),
    pytest.param(_CHATTY_EMPTY, id="chatty_prose_with_trailing_empty"),
    pytest.param(_NONDICT_LIST, id="nondict_list_[1]"),
]


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


# --- SHIP-BLOCKER (structural): exit-0 NON-MARKER refusal -> FAILED, NOT cached, no poisoned replay -----

def test_exit0_non_marker_refusal_fails_loud_and_is_not_cached(monkeypatch, tmp_path):
    """The core SHIP-BLOCKER: an exit-0 refusal phrased OUTSIDE the marker set has no parseable JSON array,
    so the STRUCTURAL guard fails it loud (protocol violation) — it is NOT read as 'ok/nothing found' and
    NOT written to the cache. Marker-based detection alone would have parsed it to [] and cached a phantom
    clean forever."""
    (tmp_path / "agent_app.py").write_text(_SRC)
    cache_path = tmp_path / "cache.json"
    _mock_claude(monkeypatch, 0, _NON_MARKER_REFUSAL)

    out = ai_tier.apply(tmp_path, [], budget=5, cache_path=cache_path)

    assert out["ai_status"] == "failed"
    assert out["ai_surfaces_added"] == 0
    assert "ai_failure" in out and "parseable json array" in out["ai_failure"].lower()
    assert not cache_path.exists()


def test_exit0_non_marker_refusal_not_cached_so_later_healthy_run_makes_a_real_call(monkeypatch, tmp_path):
    """A non-marker exit-0 refusal must NOT poison the cache: a subsequent healthy run under the SAME key
    makes a REAL call and finds the surface — it does NOT replay a cached [] all-clear."""
    (tmp_path / "agent_app.py").write_text(_SRC)
    cache_path = tmp_path / "cache.json"

    _mock_claude(monkeypatch, 0, _NON_MARKER_REFUSAL)
    out1 = ai_tier.apply(tmp_path, [], budget=5, cache_path=cache_path)
    assert out1["ai_status"] == "failed" and out1["ai_calls"] == 0
    assert not cache_path.exists()

    _mock_claude(monkeypatch, 0, _GENUINE)
    out2 = ai_tier.apply(tmp_path, [], budget=5, cache_path=cache_path)
    assert out2["ai_status"] == "ok"
    assert out2["ai_calls"] == 1, "a real call must be made — the refusal must not have been cached as []"
    assert out2["ai_surfaces_added"] == 1


# --- SHIP-BLOCKER (structural): arbitrary exit-0 prose with no JSON array -> FAILED --------------------

def test_exit0_arbitrary_prose_without_json_fails_loud(monkeypatch, tmp_path):
    """PINNED BEHAVIOUR FLIP: exit-0 prose that carries NO parseable JSON array (chatter/apology/truncation)
    was previously read as a clean nothing-found ([]). Under the STRICT-JSON contract it is now a protocol
    violation -> FAILED, and never cached."""
    (tmp_path / "agent_app.py").write_text(_SRC)
    cache_path = tmp_path / "cache.json"
    _mock_claude(monkeypatch, 0, _PROSE_NO_JSON)

    out = ai_tier.apply(tmp_path, [], budget=5, cache_path=cache_path)

    assert out["ai_status"] == "failed"
    assert out["ai_surfaces_added"] == 0
    assert "parseable json array" in out["ai_failure"].lower()
    assert not cache_path.exists()


# --- MUST-NOT-OVER-CORRECT: a genuine `[]` is a real nothing-found (status ok), NOT a failure -----------

def test_exit0_genuine_empty_array_is_nothing_found_not_failed(monkeypatch, tmp_path):
    """A genuinely-empty result — the model emitting a REAL `[]` (valid JSON array) — must STILL read as
    nothing-found (status ok), never over-corrected to failed. This is the honest 'AI ran and found nothing'
    path and it is cached like any parsed result."""
    (tmp_path / "agent_app.py").write_text(_SRC)
    cache_path = tmp_path / "cache.json"
    _mock_claude(monkeypatch, 0, "[]")

    out = ai_tier.apply(tmp_path, [], budget=5, cache_path=cache_path)

    assert out["ai_status"] == "ok"
    assert out["ai_surfaces_added"] == 0
    assert out["ai_calls"] == 1
    assert cache_path.exists()                                # a genuine parsed [] IS cached
    assert json.loads(cache_path.read_text())                # one entry present (the empty finding list)


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
    # NB: _is_refusal is now ENRICHMENT-ONLY — it no longer decides pass/fail. The STRUCTURAL guard (exit 0 +
    # no parseable JSON array) is what fails a reply loud; _is_refusal only picks the friendlier reason text.
    # So "found nothing" stays 'not a refusal' HERE, yet at the tier it FAILS as a protocol violation (see
    # test_exit0_arbitrary_prose_without_json_fails_loud) — the marker-based signal is no longer the gate.
    assert ai_assist._is_refusal("[]") is False               # legitimate empty result
    assert ai_assist._is_refusal(_GENUINE) is False           # real findings array
    assert ai_assist._is_refusal("found nothing") is False    # terse prose, no signature (enrichment miss)
    assert ai_assist._is_refusal(_REFUSAL) is True            # real AUP refusal
    # newly-added markers enrich the reason for the common phrasings
    assert ai_assist._is_refusal("I can't help with this. Acceptable Use Policy.") is True
    # a refusal carrying a stray, non-parsing bracket pair is STILL detected
    assert ai_assist._is_refusal(
        "I can't respond to this request [x] — usage policies. "
        "https://www.anthropic.com/legal/aup") is True


def test_toplevel_json_array_rejects_embedded_error_payload():
    overload = '{"type":"error","errors":[],"message":"overloaded_error: server overloaded"}'
    assert ai_assist._is_toplevel_json_array(overload) is None    # object, not a top-level array
    assert ai_assist._json_array(overload) == []                  # the embedded span DID parse (the old hole)
    assert ai_assist._is_toplevel_json_array(_GENUINE) is not None  # a genuine array is trusted


# === SHIP-BLOCKER END-TO-END: the EXACT embedded-`[]` silent-cleans, driven THROUGH ai_tier.apply =========
# These are the cases the previous green suite MISSED: they carry an embedded `[]` that the lenient
# `_json_array` guard accepted, so a real overload/refusal/chatty reply was read as "ok/nothing found" and
# CACHED. They are wired end-to-end (claude_agent -> analyze_source -> ai_tier.apply), not asserted at the
# unit boundary, precisely because green at the unit boundary hid this live hole.

@pytest.mark.parametrize("reply", _SILENT_CLEANS)
def test_exit0_embedded_empty_silent_clean_fails_loud_and_is_not_cached(reply, monkeypatch, tmp_path):
    (tmp_path / "agent_app.py").write_text(_SRC)
    cache_path = tmp_path / "cache.json"
    _mock_claude(monkeypatch, 0, reply)

    out = ai_tier.apply(tmp_path, [], budget=5, cache_path=cache_path)

    # a VISIBLE per-tier failure — NEVER the silent "(none - AI tier off or nothing found)"
    assert out["ai_status"] == "failed", f"exit-0 silent-clean {reply!r} must FAIL the tier, not read as ok"
    assert out["ai_surfaces_added"] == 0
    assert out["ai_calls"] == 0
    assert "ai_failure" in out
    # the phantom non-result was NOT persisted — nothing to replay
    assert not cache_path.exists(), f"{reply!r} must never be cached (it would replay a phantom clean)"


@pytest.mark.parametrize("reply", _SILENT_CLEANS)
def test_exit0_embedded_empty_not_cached_so_later_healthy_run_makes_a_real_call(reply, monkeypatch, tmp_path):
    """The silent-clean must NOT poison the cache: a subsequent healthy run under the SAME SHA key makes a
    REAL subprocess call and finds the surface — it does NOT replay a cached [] all-clear forever."""
    (tmp_path / "agent_app.py").write_text(_SRC)
    cache_path = tmp_path / "cache.json"

    _mock_claude(monkeypatch, 0, reply)
    out1 = ai_tier.apply(tmp_path, [], budget=5, cache_path=cache_path)
    assert out1["ai_status"] == "failed" and out1["ai_calls"] == 0
    assert not cache_path.exists()

    _mock_claude(monkeypatch, 0, _GENUINE)
    out2 = ai_tier.apply(tmp_path, [], budget=5, cache_path=cache_path)
    assert out2["ai_status"] == "ok"
    assert out2["ai_calls"] == 1, "a real call must be made — the silent-clean must not have been cached"
    assert out2["ai_surfaces_added"] == 1


def test_exit0_fenced_genuine_empty_array_still_reads_as_nothing_found(monkeypatch, tmp_path):
    """MUST-NOT-OVER-CORRECT: a genuine `[]` wrapped in a ```json code fence is STILL a real nothing-found
    (status ok, cached) — the strict arbiter strips the fence before checking, so a well-behaved fenced reply
    is not mis-failed as a protocol violation."""
    (tmp_path / "agent_app.py").write_text(_SRC)
    cache_path = tmp_path / "cache.json"
    _mock_claude(monkeypatch, 0, "```json\n[]\n```")

    out = ai_tier.apply(tmp_path, [], budget=5, cache_path=cache_path)

    assert out["ai_status"] == "ok"
    assert out["ai_surfaces_added"] == 0
    assert out["ai_calls"] == 1
    assert cache_path.exists()


def test_toplevel_json_array_rejects_nondict_and_error_object():
    # the strict arbiter is the single place all three shapes are rejected
    assert ai_assist._is_toplevel_json_array(_OVERLOAD_ERR) is None     # error OBJECT, not a top-level array
    assert ai_assist._is_toplevel_json_array("[1]") is None            # non-findings array
    assert ai_assist._is_toplevel_json_array('["x"]') is None          # non-findings array
    assert ai_assist._is_toplevel_json_array("[]") == []              # genuine empty -> passes
    assert ai_assist._is_toplevel_json_array(_GENUINE) is not None     # genuine findings -> passes
    assert ai_assist._is_toplevel_json_array("```json\n[]\n```") == []  # fenced empty -> passes
    # the OLD lenient arbiter still accepts the embedded span (documents exactly what changed)
    assert ai_assist._json_array(_OVERLOAD_ERR) == []
