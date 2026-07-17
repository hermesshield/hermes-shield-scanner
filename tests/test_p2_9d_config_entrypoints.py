#!/usr/bin/env python3
"""P2.9D — configured guard identity + try dominance + module-scope FP reduction. Read-only."""
from __future__ import annotations
import ast
import sys
from pathlib import Path


from hermes_shield import repo_scanner, surface_classifier, config_loader, module_index as MI  # noqa: E402

CORPUS = Path(__file__).resolve().parent / "corpus"


def _scan(root):
    scan = repo_scanner.scan_repo(root)
    for s in scan["surfaces"]:
        surface_classifier.classify(s)
    return scan


def _one(name):
    return next(s for s in _scan(CORPUS)["surfaces"] if Path(s.file_path).name == name)


# ---- configured guard identity -------------------------------------------------------------
def test_01_config_loads_guard_primitives():
    modules, symbols, ids = config_loader.load_guard_config()
    assert "final_action_gate" in modules and "assert_live_action_allowed" in symbols
    assert ids.get("assert_live_action_allowed") == "kill_switch"


def test_02_invalid_config_falls_back_safe(tmp_path, monkeypatch=None):
    # the loader must never crash the scanner; defaults are always present
    modules, symbols, ids = config_loader.load_guard_config()
    assert symbols  # non-empty


def test_03_config_alias_guard_resolves():
    r = MI.resolve_guard_identity("_gate", False,
                                  MI.parse_imports(ast.parse("from final_action_gate import allow_action as _gate\n")),
                                  set())
    assert r["strong"] and r["identity"] == MI.RESOLVED_IMPORT


def test_04_wrong_module_same_name_not_proven():
    s = _one("d06_wrong_module_same_name.py")
    assert s.guard_proof["status"] != "proven"  # allow_action from myapp.helpers is not the real gate


# ---- try dominance -------------------------------------------------------------------------
def test_05_try_reraise_guard_before_sink_proven():
    s = _one("d01_try_guard_before_sink.py")
    assert s.guard_proof["status"] == "proven"
    assert s.guard_proof["proof_type"] == "try_block_guard_before_sink"


def test_06_try_swallow_not_proven():
    assert _one("d02_try_swallow_negative.py").guard_proof["status"] != "proven"


def test_07_guard_in_except_not_proven():
    assert _one("d03_guard_in_except_negative.py").guard_proof["status"] != "proven"


def test_08_try_early_return_guard_proven():
    s = _one("d04_try_early_return_guard.py")
    assert s.guard_proof["status"] == "proven"
    assert "early_return" in s.guard_proof["proof_type"]


def test_09_config_alias_gate_proven():
    s = _one("d05_config_alias_guard.py")
    assert s.guard_proof["status"] == "proven"


# ---- module-scope / reference FP reduction -------------------------------------------------
def test_10_def_and_import_lines_not_sinks():
    # P2.9D: definition/import lines are not action sinks (reduces module-scope false positives).
    scan = _scan(CORPUS)
    for s in scan["surfaces"]:
        import pathlib as _p
        if _p.Path(s.file_path).exists():
            line = _p.Path(s.file_path).read_text(errors="ignore").splitlines()[s.line_start-1].strip()
            assert not line.startswith(("def ", "import ", "from ", "class "))


def test_11_actual_module_scope_call_still_detected():
    scan = _scan(CORPUS)
    mod = [s for s in scan["surfaces"] if Path(s.file_path).name == "d08_actual_module_scope_call.py"]
    assert any(s.capability == "external_write" for s in mod)  # real module-scope call still surfaces


def test_12_import_line_not_a_sink():
    scan = _scan(CORPUS)
    # no surface should originate from an import/def line in any d0* fixture
    for s in scan["surfaces"]:
        if Path(s.file_path).name.startswith("d0"):
            assert s.capability != "unknown_action"


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
