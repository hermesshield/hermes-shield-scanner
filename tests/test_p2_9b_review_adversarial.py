#!/usr/bin/env python3
"""P2.9B-REVIEW — independent adversarial audit of the guard-proof model. Uses fresh inline fixtures
(NOT the builder's corpus) to probe whether PROTECTED_FULL_PATH is genuinely proof-gated or still
over-credited. Read-only; no live actions."""
from __future__ import annotations
import sys
from pathlib import Path


from hermes_shield import repo_scanner, surface_classifier  # noqa: E402


def _scan_text(tmp: Path, name: str, code: str):
    (tmp / name).write_text(code)
    scan = repo_scanner.scan_repo(tmp)
    for s in scan["surfaces"]:
        surface_classifier.classify(s)
    return [s for s in scan["surfaces"] if s.file_path.endswith(name)]


# ---- the 12 minimum cases (independent fixtures) -------------------------------------------
def test_min01_comment_guard_not_protected(tmp_path):
    s = _scan_text(tmp_path, "a.py", "def p():\n    # assert_live_action_allowed here\n    client.create_tweet(text='x')\n")[0]
    assert s.verdict != "PROTECTED_FULL_PATH" and s.guard_proof["status"] != "proven"


def test_min02_string_guard_not_protected(tmp_path):
    s = _scan_text(tmp_path, "a.py", "def p():\n    x='assert_live_action_allowed'\n    client.create_tweet(text=x)\n")[0]
    assert s.verdict != "PROTECTED_FULL_PATH"


def test_min03_guard_defined_never_called_not_protected(tmp_path):
    code = ("def guard():\n    assert_live_action_allowed({})\n"
            "def p():\n    client.create_tweet(text='x')\n")
    s = _scan_text(tmp_path, "a.py", code)[0]
    assert s.verdict != "PROTECTED_FULL_PATH"


def test_min04_guard_after_sink_not_protected(tmp_path):
    s = _scan_text(tmp_path, "a.py", "def p():\n    client.create_tweet(text='x')\n    assert_live_action_allowed({})\n")[0]
    assert s.verdict != "PROTECTED_FULL_PATH" and s.guard_proof["status"] != "proven"


def test_min05_wrapper_unguarded_alt_caller_not_protected(tmp_path):
    code = ("def _do():\n    client.create_tweet(text='x')\n"
            "def p():\n    assert_live_action_allowed({})\n    _do()\n"
            "def sneak():\n    _do()\n")
    hits = _scan_text(tmp_path, "a.py", code)
    do = [s for s in hits if s.symbol == "_do"][0]
    assert do.verdict != "PROTECTED_FULL_PATH"


def test_min06_same_function_guard_before_sink_protected(tmp_path):
    s = _scan_text(tmp_path, "a.py", "from shield_kill_switch import assert_live_action_allowed\ndef p():\n    assert_live_action_allowed({})\n    client.create_tweet(text='x')\n")[0]
    assert s.guard_proof["status"] == "proven" and s.guard_proof["proof_type"] == "same_function_before_sink"


def test_min07_requests_post_mutating(tmp_path):
    s = _scan_text(tmp_path, "a.py", "import requests\ndef p(u,d):\n    requests.post(u, json=d)\n")[0]
    assert s.capability == "external_write" and s.mutating == "yes"


def test_min08_requests_get_read_only(tmp_path):
    s = _scan_text(tmp_path, "a.py", "import requests\ndef p(u):\n    return requests.get(u).json()\n")[0]
    assert s.mutating == "no" and s.verdict != "BLOCK_LIVE_PROMOTION"


def test_min09_subprocess_detected(tmp_path):
    s = _scan_text(tmp_path, "a.py", "import subprocess\ndef p():\n    subprocess.run(['ls'])\n")[0]
    assert s.capability == "subprocess_exec"


def test_min10_publish_dir_write_detected(tmp_path):
    s = _scan_text(tmp_path, "a.py", "def p(t):\n    open('x/ready/y.md','w').write(t)\n")[0]
    assert s.capability == "publish_write"


# ---- ADVERSARIAL: does the proof over-credit? ----------------------------------------------
def test_adv01_guard_in_conditional_branch_NOT_proven(tmp_path):
    """PATCHED: a guard inside an if-branch does NOT dominate the sink -> must NOT be proven."""
    code = ("def p(debug):\n"
            "    if debug:\n"
            "        assert_live_action_allowed({})\n"
            "    client.create_tweet(text='x')\n")
    s = _scan_text(tmp_path, "a.py", code)[0]
    assert s.guard_proof["status"] != "proven"
    assert s.verdict != "PROTECTED_FULL_PATH"


def test_adv02_exposed_public_wrapper_NOT_protected(tmp_path):
    """PATCHED: a PUBLIC helper (no underscore) may have external callers -> must NOT be full-path."""
    code = ("def do_post():\n    client.create_tweet(text='x')\n"
            "def p():\n    assert_live_action_allowed({})\n    do_post()\n")
    hits = _scan_text(tmp_path, "a.py", code)
    do = [s for s in hits if s.symbol == "do_post"][0]
    assert do.guard_proof["status"] != "proven"
    assert do.verdict != "PROTECTED_FULL_PATH"


def test_adv02b_private_wrapper_still_proven(tmp_path):
    """Regression: a PRIVATE helper with a guarded caller is still legitimately proven."""
    code = ("from shield_kill_switch import assert_live_action_allowed\n"
            "def _do_post():\n    client.create_tweet(text='x')\n"
            "def p():\n    assert_live_action_allowed({})\n    _do_post()\n")
    hits = _scan_text(tmp_path, "a.py", code)
    do = [s for s in hits if s.symbol == "_do_post"][0]
    assert do.guard_proof["status"] == "proven"


def test_adv03_dynamic_dispatch_not_protected(tmp_path):
    code = ("def p(name):\n    fn = getattr(client, name)\n    fn(text='x')\n    assert_live_action_allowed({})\n")
    hits = _scan_text(tmp_path, "a.py", code)
    # getattr dispatch: no static sink match likely -> may be no surface; if surface exists, not proven
    assert all(s.verdict != "PROTECTED_FULL_PATH" for s in hits)


def test_adv04_unrelated_method_named_like_guard(tmp_path):
    """An unrelated method named allow_action() should ideally not count as the final-action gate."""
    code = ("def p(self):\n    self.allow_action()\n    client.create_tweet(text='x')\n")
    s = _scan_text(tmp_path, "a.py", code)[0]
    globals()["_ADV04"] = {"proven": s.guard_proof["status"] == "proven", "verdict": s.verdict}


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q", "-s"]))
