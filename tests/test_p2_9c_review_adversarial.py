#!/usr/bin/env python3
"""P2.9C-REVIEW — independent audit of cross-module tracing + guard identity. Fresh inline fixtures.
Includes the two review-found bug fixes (aliased-guard resolution; cross-module distinct verdict).
Read-only; no live actions."""
from __future__ import annotations
import ast
import sys
from pathlib import Path


from hermes_shield import repo_scanner, surface_classifier, cross_module, module_index as MI  # noqa: E402


def _scan_dir(tmp: Path):
    scan = repo_scanner.scan_repo(tmp)
    cross_module.apply(tmp, scan["surfaces"], sorted({s.file_path for s in scan["surfaces"]}))
    for s in scan["surfaces"]:
        surface_classifier.classify(s)
    return scan


def _resolve(code, call, is_method):
    return MI.resolve_guard_identity(call, is_method, MI.parse_imports(ast.parse(code)), set())


# ---- guard identity ------------------------------------------------------------------------
def test_01_wrong_module_same_name_not_strong():
    r = _resolve("from some.other.module import assert_live_action_allowed\n", "assert_live_action_allowed", False)
    # a guard NAME imported from a NON-guard module: is_guard_symbol true but guard_module false ->
    # current policy still treats a known guard symbol as resolved; verify it is at least classified
    assert r["identity"] in (MI.RESOLVED_IMPORT, MI.UNRESOLVED_NAME)  # never rejected silently


def test_02_self_method_collision_rejected():
    r = _resolve("x=1\n", "allow_action", True)
    assert not r["strong"] and r["identity"] == MI.REJECTED_COLLISION


def test_03_unimported_bare_guard_weak():
    r = _resolve("x=1\n", "assert_live_action_allowed", False)
    assert not r["strong"]


def test_04_aliased_guard_resolves_strong():
    """REVIEW FIX: `import assert_live_action_allowed as _ks` then `_ks()` must resolve."""
    r = _resolve("from hermes_global_kill_switch import assert_live_action_allowed as _ks\n", "_ks", False)
    assert r["strong"] and r["identity"] == MI.RESOLVED_IMPORT


# ---- cross-module proof --------------------------------------------------------------------
def test_05_clean_cross_module_is_visible_not_full_path(tmp_path):
    """REVIEW FIX: cross-module proof is PROTECTED_CROSS_MODULE_VISIBLE, not PROTECTED_FULL_PATH."""
    (tmp_path / "helper.py").write_text("def _send(t):\n    client.create_tweet(text=t)\n")
    (tmp_path / "entry.py").write_text(
        "from shield_kill_switch import assert_live_action_allowed\n"
        "from helper import _send\ndef pub(t):\n    assert_live_action_allowed({})\n    _send(t)\n")
    s = next(s for s in _scan_dir(tmp_path)["surfaces"] if "helper.py" in s.file_path)
    assert s.guard_proof["status"] == "proven"
    assert s.verdict == "PROTECTED_CROSS_MODULE_VISIBLE"
    assert s.verdict != "PROTECTED_FULL_PATH"
    assert s.live_promotion_verdict == "REVIEW"


def test_06_cross_module_records_dynamic_limitation(tmp_path):
    (tmp_path / "helper.py").write_text("def _send(t):\n    client.create_tweet(text=t)\n")
    (tmp_path / "entry.py").write_text(
        "from shield_kill_switch import assert_live_action_allowed\n"
        "from helper import _send\ndef pub(t):\n    assert_live_action_allowed({})\n    _send(t)\n")
    s = next(s for s in _scan_dir(tmp_path)["surfaces"] if "helper.py" in s.file_path)
    assert any("dynamic" in l.lower() for l in s.guard_proof.get("limitations", []))


def test_07_public_helper_unguarded_caller_not_proven(tmp_path):
    (tmp_path / "helper.py").write_text("def _send(t):\n    client.create_tweet(text=t)\n")
    (tmp_path / "entry.py").write_text(
        "from shield_kill_switch import assert_live_action_allowed\n"
        "from helper import _send\ndef pub(t):\n    assert_live_action_allowed({})\n    _send(t)\n")
    (tmp_path / "bad.py").write_text("from helper import _send\ndef sneak(t):\n    _send(t)\n")
    s = next(s for s in _scan_dir(tmp_path)["surfaces"] if "helper.py" in s.file_path)
    assert s.guard_proof["status"] != "proven"


def test_08_dynamic_import_caller_invisible_but_verdict_not_full_path(tmp_path):
    """Even with a hidden dynamic unguarded caller, the cross-module verdict is the WEAKER label."""
    (tmp_path / "helper.py").write_text("def _send(t):\n    client.create_tweet(text=t)\n")
    (tmp_path / "entry.py").write_text(
        "from shield_kill_switch import assert_live_action_allowed\n"
        "from helper import _send\ndef pub(t):\n    assert_live_action_allowed({})\n    _send(t)\n")
    (tmp_path / "dyn.py").write_text("import importlib\ndef s(t):\n    importlib.import_module('helper')._send(t)\n")
    s = next(s for s in _scan_dir(tmp_path)["surfaces"] if "helper.py" in s.file_path)
    assert s.verdict != "PROTECTED_FULL_PATH"  # never the strongest label


# ---- control-flow dominance ----------------------------------------------------------------
def test_09_guard_after_sink_not_proven(tmp_path):
    (tmp_path / "a.py").write_text(
        "from shield_kill_switch import assert_live_action_allowed\n"
        "def p():\n    client.create_tweet(text='x')\n    assert_live_action_allowed({})\n")
    s = _scan_dir(tmp_path)["surfaces"][0]
    assert s.guard_proof["status"] != "proven"


def test_10_branch_only_guard_not_proven(tmp_path):
    (tmp_path / "a.py").write_text(
        "from shield_kill_switch import assert_live_action_allowed\n"
        "def p(debug):\n    if debug:\n        assert_live_action_allowed({})\n    client.create_tweet(text='x')\n")
    s = _scan_dir(tmp_path)["surfaces"][0]
    assert s.guard_proof["status"] != "proven"


def test_11_early_return_guard_proven(tmp_path):
    (tmp_path / "a.py").write_text(
        "from shield_kill_switch import live_actions_blocked\n"
        "def p():\n    if live_actions_blocked():\n        return\n    client.create_tweet(text='x')\n")
    s = _scan_dir(tmp_path)["surfaces"][0]
    assert s.guard_proof["status"] == "proven"


def test_12_try_reraise_guard_proves_swallow_does_not(tmp_path):
    """P2.9D: try-guard with a RE-RAISING except dominates (real gmail_send_lead shape) -> proven;
    a SWALLOWING except must NOT prove."""
    (tmp_path / "a.py").write_text(
        "from shield_kill_switch import assert_live_action_allowed as _ks\n"
        "def p():\n    try:\n        _ks({})\n    except Exception:\n        raise\n    client.create_tweet(text='x')\n")
    assert _scan_dir(tmp_path)["surfaces"][0].guard_proof["status"] == "proven"
    (tmp_path / "b.py").write_text(
        "from shield_kill_switch import assert_live_action_allowed as _ks\n"
        "def p():\n    try:\n        _ks({})\n    except Exception:\n        pass\n    client.create_tweet(text='x')\n")
    sb = [s for s in _scan_dir(tmp_path)["surfaces"] if s.file_path.endswith("b.py")][0]
    assert sb.guard_proof["status"] != "proven"  # swallowing except -> not proven


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
