#!/usr/bin/env python3
"""P2.9E — AST-backed sink detection. Import/def/reference/string lines are not live sinks; actual
call/write nodes are. Read-only."""
from __future__ import annotations
import sys
from pathlib import Path


from hermes_shield import repo_scanner, surface_classifier, ast_sinks  # noqa: E402

CORPUS = Path(__file__).resolve().parent / "corpus"


def _scan():
    scan = repo_scanner.scan_repo(CORPUS)
    for s in scan["surfaces"]:
        surface_classifier.classify(s)
    return scan


def _caps(name):
    return {s.capability for s in _scan()["surfaces"] if Path(s.file_path).name == name}


# ---- what must NOT be a live sink ----------------------------------------------------------
def test_01_import_line_not_sink():
    assert "email_send" not in _caps("e01_import_not_sink.py")


def test_02_def_line_not_sink():
    assert "post" not in _caps("e02_def_not_sink.py")


def test_03_string_only_not_live_sink():
    assert "queue_mutation" not in _caps("e03_string_not_live_sink.py")
    assert "db_mutation" not in _caps("e03_string_not_live_sink.py")


def test_04_reference_not_sink():
    assert "external_write" not in _caps("e12_reference_not_sink.py")


# ---- what MUST be a sink --------------------------------------------------------------------
def test_05_module_scope_call_detected():
    assert "external_write" in _caps("e04_actual_module_scope_call.py")


def test_06_open_write_publish_detected():
    assert "publish_write" in _caps("e05_open_write_publish.py")


def test_07_path_write_text_detected():
    assert _caps("e06_path_write_text.py") & {"publish_write", "file_write"}


def test_08_shutil_copy_publish_detected():
    assert "publish_write" in _caps("e07_shutil_copy_publish.py")


def test_09_sql_execute_call_detected():
    assert "queue_mutation" in _caps("e08_sql_execute_call.py")


def test_10_subprocess_run_detected():
    assert "subprocess_exec" in _caps("e09_subprocess_run.py")


def test_11_requests_get_read_only():
    caps = _caps("e10_requests_get_readonly.py")
    assert "external_read" in caps and "external_write" not in caps


def test_12_gmail_send_chain_detected():
    assert "email_send" in _caps("e11_gmail_send_chain.py")


# ---- detector unit + module-scope + regression ---------------------------------------------
def test_13_detector_ok_and_module_scope_flag():
    ok, sinks = ast_sinks.detect("import requests\nrequests.post('u', json={})\n")
    assert ok
    ms = [s for s in sinks if s["capability"] == "external_write"]
    assert ms and ms[0]["module_scope"] is True


def test_14_parse_failure_returns_false():
    ok, sinks = ast_sinks.detect("def broken(:\n")
    assert ok is False and sinks == []


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
