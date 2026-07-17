#!/usr/bin/env python3
"""P2.9B — scanner precision + call-graph guard proof. Scans corpus fixtures and asserts the honest
semantics: PROTECTED_FULL_PATH only when a guard is AST-proven before the sink; comments/strings never
count; new sinks detected; read-only not blocked; FP classes downgraded; stable drift identity."""
from __future__ import annotations
import sys
from pathlib import Path


from hermes_shield import repo_scanner, surface_classifier, call_graph, baseline as BL, drift as DR  # noqa: E402

CORPUS = Path(__file__).resolve().parent / "corpus"


def _scan(root):
    scan = repo_scanner.scan_repo(root)
    for s in scan["surfaces"]:
        surface_classifier.classify(s)
    return scan


def _one(name):
    scan = _scan(CORPUS)
    hits = [s for s in scan["surfaces"] if Path(s.file_path).name == name]
    assert hits, f"no surface found in {name}"
    return hits[0]


# ---- call-graph guard proof ----------------------------------------------------------------
def test_01_same_function_guard_is_proven():
    s = _one("f01_same_func_guarded.py")
    assert s.guard_proof["status"] == "proven"
    assert s.guard_proof["proof_type"] == "same_function_before_sink"
    assert s.guard_evidence_level == "proven_before_sink"


def test_02_guard_after_sink_not_protected():
    s = _one("f02_guard_after_sink.py")
    assert s.guard_proof["status"] != "proven"
    assert s.verdict != "PROTECTED_FULL_PATH"


def test_03_guard_in_other_function_not_protected():
    s = _one("f03_guard_other_function.py")
    assert s.verdict != "PROTECTED_FULL_PATH"
    assert s.verdict in ("BLOCK_LIVE_PROMOTION", "NEEDS_CALL_GRAPH", "CALLER_GUARDED_NOT_PROVEN", "STATIC_EVIDENCE_ONLY")


def test_04_wrapper_all_callers_guarded_proven():
    s = _one("f04_wrapper_guarded.py")
    assert s.guard_proof["status"] == "proven"
    assert s.guard_proof["proof_type"] == "private_wrapper_guarded"


def test_05_wrapper_one_unguarded_caller_not_proven():
    s = _one("f05_wrapper_one_unguarded_caller.py")
    assert s.guard_proof["status"] != "proven"
    assert s.verdict != "PROTECTED_FULL_PATH"


def test_06_comment_guard_does_not_count():
    s = _one("f06_comment_guard.py")
    assert s.guard_proof["status"] != "proven"
    assert s.guard_evidence_level != 'proven_before_sink'  # AST proof: comment must not prove a guard
    assert s.verdict == "BLOCK_LIVE_PROMOTION"


def test_07_string_guard_does_not_count():
    s = _one("f07_string_guard.py")
    assert s.guard_proof["status"] != "proven"
    assert s.verdict != "PROTECTED_FULL_PATH"


# ---- false-negative sinks now detected -----------------------------------------------------
def test_08_requests_post_detected_mutating():
    s = _one("f08_requests_post.py")
    assert s.capability == "external_write" and s.mutating == "yes"


def test_09_requests_get_is_read_only():
    s = _one("f09_requests_get_readonly.py")
    assert s.capability == "external_read" and s.mutating == "no"
    assert s.verdict in ("READ_ONLY_SURFACE", "PROTECTED_TEXT_PATH_ONLY")
    assert s.verdict != "BLOCK_LIVE_PROMOTION"


def test_10_httpx_subprocess_ossystem_tweepy_detected():
    assert _one("f10_httpx_post.py").capability == "external_write"
    assert _one("f11_subprocess.py").capability == "subprocess_exec"
    assert _one("f12_os_system.py").capability == "subprocess_exec"
    assert _one("f13_tweepy_post.py").capability == "post"


def test_11_ready_file_write_detected():
    s = _one("f14_ready_file_write.py")
    assert s.capability == "publish_write"


# ---- FP classes downgraded (not silently suppressed) ---------------------------------------
def test_12_generator_no_write_not_blocking():
    scan = _scan(CORPUS)
    gen = [s for s in scan["surfaces"] if Path(s.file_path).name == "f15_generator_no_write.py"]
    # a pure text generator with no outbound sink should produce no BLOCK finding
    assert all(s.verdict != "BLOCK_LIVE_PROMOTION" for s in gen)


def test_13_variable_name_false_positive_not_blocking():
    scan = _scan(CORPUS)
    v = [s for s in scan["surfaces"] if Path(s.file_path).name == "f16_var_name_falsepos.py"]
    assert all(s.verdict != "BLOCK_LIVE_PROMOTION" for s in v)  # variable name, not an action call


# ---- stable drift identity -----------------------------------------------------------------
def test_14_line_shift_is_not_new_surface(tmp_path):
    (tmp_path / "p.py").write_text(
        "from shield_kill_switch import assert_live_action_allowed\n"
        "def publish():\n    assert_live_action_allowed({'s':'x'})\n    client.create_tweet(text='x')\n")
    base = BL.build_baseline(_scan(tmp_path), "h0")
    # add two blank lines at top -> action line shifts, but stable id (file,symbol,cap,sink) is same
    (tmp_path / "p.py").write_text(
        "\n\nfrom shield_kill_switch import assert_live_action_allowed\n"
        "def publish():\n    assert_live_action_allowed({'s':'x'})\n    client.create_tweet(text='x')\n")
    overall, findings = DR.diff(base, _scan(tmp_path))
    assert not any(f.kind == "new_live_action_surface" for f in findings)  # NOT a false new surface


def test_15_guard_removal_after_line_shift_is_protection_change(tmp_path):
    (tmp_path / "p.py").write_text(
        "from shield_kill_switch import assert_live_action_allowed\n"
        "def publish():\n    assert_live_action_allowed({'s':'x'})\n    client.create_tweet(text='x')\n")
    base = BL.build_baseline(_scan(tmp_path), "h0")
    # remove guard AND shift line -> stable id preserved -> protection_changed / guard_removed, not new
    (tmp_path / "p.py").write_text(
        "\ndef publish():\n    client.create_tweet(text='x')\n")
    overall, findings = DR.diff(base, _scan(tmp_path))
    kinds = {f.kind for f in findings}
    assert overall == "DRIFT_DETECTED"
    assert ("protection_changed" in kinds or "guard_removed" in kinds)
    assert "new_live_action_surface" not in kinds


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
