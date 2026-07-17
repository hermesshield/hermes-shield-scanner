#!/usr/bin/env python3
"""P2.9D-REVIEW — independent audit of try-dominance soundness + configured identity + the first real
proofs. Fresh inline fixtures. Read-only; no live actions."""
from __future__ import annotations
import ast
import sys
from pathlib import Path


from hermes_shield import repo_scanner, surface_classifier, module_index as MI  # noqa: E402

_KS = "from hermes_global_kill_switch import assert_live_action_allowed as _ks\n"


def _p(tmp, code):
    (tmp / "a.py").write_text(code)
    scan = repo_scanner.scan_repo(tmp)
    for s in scan["surfaces"]:
        surface_classifier.classify(s)
    return scan["surfaces"][0]


# ---- try-dominance soundness ---------------------------------------------------------------
def test_01_try_guard_reraise_proves(tmp_path):
    s = _p(tmp_path, _KS + "def s():\n    try:\n        _ks({})\n    except Exception:\n        raise\n    client.create_tweet(text='x')\n")
    assert s.guard_proof["status"] == "proven"


def test_02_try_guard_return_exits_proves(tmp_path):
    # the real Gmail/LinkedIn-DM shape: except returns (exits) -> sound
    s = _p(tmp_path, _KS + "def s():\n    try:\n        _ks({})\n    except Exception:\n        return None\n    client.create_tweet(text='x')\n")
    assert s.guard_proof["status"] == "proven"


def test_03_try_swallow_pass_not_proven(tmp_path):
    s = _p(tmp_path, _KS + "def s():\n    try:\n        _ks({})\n    except Exception:\n        pass\n    client.create_tweet(text='x')\n")
    assert s.guard_proof["status"] != "proven"


def test_04_conditional_raise_fallthrough_not_proven(tmp_path):
    s = _p(tmp_path, _KS + "def s(bad):\n    try:\n        _ks({})\n    except Exception:\n        if bad:\n            raise\n        log('x')\n    client.create_tweet(text='x')\n")
    assert s.guard_proof["status"] != "proven"  # else path reaches sink unguarded


def test_05_log_only_handler_not_proven(tmp_path):
    s = _p(tmp_path, _KS + "def s():\n    try:\n        _ks({})\n    except Exception:\n        log('err')\n    client.create_tweet(text='x')\n")
    assert s.guard_proof["status"] != "proven"


def test_06_guard_after_sink_in_try_not_proven(tmp_path):
    s = _p(tmp_path, _KS + "def s():\n    try:\n        client.create_tweet(text='x')\n        _ks({})\n    except Exception:\n        raise\n")
    assert s.guard_proof["status"] != "proven"


def test_07_guard_in_except_not_proven(tmp_path):
    s = _p(tmp_path, _KS + "def s():\n    try:\n        pass\n    except Exception:\n        _ks({})\n    client.create_tweet(text='x')\n")
    assert s.guard_proof["status"] != "proven"


def test_08_two_handlers_one_swallows_not_proven(tmp_path):
    s = _p(tmp_path, _KS + "def s():\n    try:\n        _ks({})\n    except ValueError:\n        raise\n    except Exception:\n        pass\n    client.create_tweet(text='x')\n")
    assert s.guard_proof["status"] != "proven"  # the second handler swallows


def test_09_cleanup_then_raise_proves(tmp_path):
    s = _p(tmp_path, _KS + "def s():\n    try:\n        _ks({})\n    except Exception:\n        cleanup()\n        raise\n    client.create_tweet(text='x')\n")
    assert s.guard_proof["status"] == "proven"


def test_10_sink_in_finally_not_over_credited(tmp_path):
    # a sink inside finally runs even when the guard raised -> must NOT be proven by the try guard
    s = _p(tmp_path, _KS + "def s():\n    try:\n        _ks({})\n    except Exception:\n        raise\n    finally:\n        client.create_tweet(text='x')\n")
    assert s.guard_proof["status"] != "proven"  # PATCHED: finally-sink not dominated by the guard


# ---- configured identity + regression ------------------------------------------------------
def test_11_alias_configured_guard_strong():
    r = MI.resolve_guard_identity("_ks", False, MI.parse_imports(ast.parse(_KS)), set())
    assert r["strong"] and r["identity"] == MI.RESOLVED_IMPORT


def test_12_wrong_module_same_name_weak():
    r = MI.resolve_guard_identity("allow_action", False,
                                  MI.parse_imports(ast.parse("from myapp.helpers import allow_action\n")), set())
    assert not r["strong"]


def test_13_self_method_collision_rejected():
    r = MI.resolve_guard_identity("allow_action", True, {}, set())
    assert not r["strong"] and r["identity"] == MI.REJECTED_COLLISION


def test_14_comment_and_string_guard_not_proven(tmp_path):
    s = _p(tmp_path, "def s():\n    # assert_live_action_allowed\n    x='assert_live_action_allowed'\n    client.create_tweet(text=x)\n")
    assert s.guard_proof["status"] != "proven"


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
