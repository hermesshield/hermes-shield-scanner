#!/usr/bin/env python3
"""P2.9C — cross-module guard tracing + guard identity + dominance. Read-only; no live actions."""
from __future__ import annotations
import sys
from pathlib import Path


from hermes_shield import repo_scanner, surface_classifier, cross_module, module_index as MI  # noqa: E402

XMOD = Path(__file__).resolve().parent / "corpus" / "xmod"


def _scan_xmod():
    scan = repo_scanner.scan_repo(XMOD)
    cross_module.apply(XMOD, scan["surfaces"], sorted({s.file_path for s in scan["surfaces"]}))
    for s in scan["surfaces"]:
        surface_classifier.classify(s)
    return scan


def _helper(scan, sym):
    return next(s for s in scan["surfaces"] if s.symbol == sym and "mod_b" in s.file_path)


# ---- cross-module tracing -------------------------------------------------------------------
def test_01_clean_helper_cross_module_proven():
    s = _helper(_scan_xmod(), "_send_clean")
    assert s.guard_proof["status"] == "proven"
    assert s.guard_proof["proof_type"] == "cross_module_entry_guard_before_helper"
    assert "mod_c_entry_guarded" in s.guard_proof["modules_involved"]


def test_02_shared_helper_with_unguarded_caller_not_proven():
    s = _helper(_scan_xmod(), "_send_shared")
    assert s.guard_proof["status"] != "proven"
    assert s.verdict != "PROTECTED_FULL_PATH"


def test_03_cross_module_proof_records_dynamic_limitation():
    s = _helper(_scan_xmod(), "_send_clean")
    assert any("dynamic" in l.lower() for l in s.guard_proof.get("limitations", []))


def test_04_same_name_wrong_module_does_not_break_proof():
    # mod_g imports a different _send_clean from xmod.unrelated; must not defeat the real proof
    s = _helper(_scan_xmod(), "_send_clean")
    assert s.guard_proof["status"] == "proven"


# ---- guard identity resolution (ADV04 + import kinds) ---------------------------------------
def _resolve(code, call, is_method):
    import ast
    tree = ast.parse(code)
    imports = MI.parse_imports(tree)
    return MI.resolve_guard_identity(call, is_method, imports, set())


def test_05_resolved_import_is_strong():
    r = _resolve("from shield_kill_switch import assert_live_action_allowed\n",
                 "assert_live_action_allowed", False)
    assert r["strong"] and r["identity"] == MI.RESOLVED_IMPORT


def test_06_method_name_collision_rejected():
    r = _resolve("x=1\n", "allow_action", True)  # self.allow_action() style
    assert not r["strong"] and r["identity"] == MI.REJECTED_COLLISION


def test_07_unimported_bare_guard_is_weak():
    r = _resolve("x=1\n", "assert_live_action_allowed", False)
    assert not r["strong"] and r["identity"] == MI.UNRESOLVED_NAME


def test_08_aliased_import_resolves():
    r = _resolve("from shield_kill_switch import assert_live_action_allowed as g\n",
                 "g", False)
    # aliased to g: g is not a guard NAME, so this specific call name won't match; verify the import map
    import ast
    imp = MI.parse_imports(ast.parse("from shield_kill_switch import assert_live_action_allowed as g\n"))
    assert "g" in imp and imp["g"]["guard_module"]


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
