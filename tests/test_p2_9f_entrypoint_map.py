#!/usr/bin/env python3
"""P2.9F — reviewed real-entrypoint map for public helpers. A public helper is protected only when
explicitly modelled AND its allowed callers run the expected guard BEFORE the call — and then only
with the WEAKER PROTECTED_BY_REVIEWED_ENTRYPOINT verdict. Read-only; no live actions."""
from __future__ import annotations
import sys
from pathlib import Path


from hermes_shield import repo_scanner, surface_classifier, entrypoint_proof  # noqa: E402

CORPUS = Path(__file__).resolve().parent / "corpus"


def _apply(helpers):
    scan = repo_scanner.scan_repo(CORPUS)
    for s in scan["surfaces"]:
        surface_classifier.classify(s)
    patch = []
    entrypoint_proof.apply(CORPUS, scan["surfaces"], patch, config=([], helpers))
    return scan["surfaces"], patch


def _surf(surfaces, stem, symbol):
    return next((s for s in surfaces if Path(s.file_path).stem == stem and s.symbol == symbol), None)


def test_01_reviewed_entrypoint_protects_public_helper():
    helpers = {("g01_helper_reviewed_entrypoint", "upload"):
               {"allowed_callers": ["entry"], "expected_guards": ["kill_switch"]}}
    surfaces, _ = _apply(helpers)
    s = _surf(surfaces, "g01_helper_reviewed_entrypoint", "upload")
    assert s and s.verdict == "PROTECTED_BY_REVIEWED_ENTRYPOINT"
    assert s.guard_proof["helper_visibility"] == "public_helper"
    # weaker than full-path — must NOT be PROTECTED_FULL_PATH
    assert s.verdict != "PROTECTED_FULL_PATH"


def test_02_disallowed_caller_needs_config():
    helpers = {("g02_helper_disallowed_caller", "upload"):
               {"allowed_callers": ["entry"], "expected_guards": ["kill_switch"]}}
    surfaces, _ = _apply(helpers)
    s = _surf(surfaces, "g02_helper_disallowed_caller", "upload")
    assert s and s.verdict == "NEEDS_ENTRYPOINT_CONFIG"


def test_03_guard_after_sink_blocks():
    helpers = {("g03_helper_guard_after_sink", "upload"):
               {"allowed_callers": ["entry"], "expected_guards": ["kill_switch"]}}
    surfaces, patch = _apply(helpers)
    s = _surf(surfaces, "g03_helper_guard_after_sink", "upload")
    assert s and s.verdict == "EXPECTED_GUARD_UNPROVEN"
    assert s.live_promotion_verdict == "BLOCK"
    assert any("without the expected guard" in p["finding"] for p in patch)  # patch-plan diagnostic


def test_04_no_config_stays_unproven():
    surfaces, _ = _apply({})  # empty map -> nothing upgraded
    s = _surf(surfaces, "g04_helper_no_config", "upload")
    assert s and s.verdict != "PROTECTED_BY_REVIEWED_ENTRYPOINT"
    assert s.guard_proof.get("status") != "proven"


def test_05_scheduler_to_helper_reviewed():
    helpers = {("g05_scheduler_to_helper", "send_dm"):
               {"allowed_callers": ["scheduler_entry"], "expected_guards": ["kill_switch"]}}
    surfaces, _ = _apply(helpers)
    s = _surf(surfaces, "g05_scheduler_to_helper", "send_dm")
    assert s and s.verdict == "PROTECTED_BY_REVIEWED_ENTRYPOINT"


def test_06_private_helper_fullpath_not_downgraded():
    # a PRIVATE helper already proven via cross-module full-path must NOT be touched by entrypoint pass
    helpers = {("g06_private_helper_fullpath", "_upload"):
               {"allowed_callers": ["entry"], "expected_guards": ["kill_switch"]}}
    surfaces, _ = _apply(helpers)
    s = _surf(surfaces, "g06_private_helper_fullpath", "_upload")
    if s and s.guard_proof.get("status") == "proven":
        assert s.verdict != "PROTECTED_BY_REVIEWED_ENTRYPOINT"  # keeps its stronger proof


def test_07_missing_guard_never_credits():
    # expected guard the caller does not have at all -> not protected
    helpers = {("g04_helper_no_config", "upload"):
               {"allowed_callers": ["entry"], "expected_guards": ["kill_switch"]}}
    surfaces, _ = _apply(helpers)
    s = _surf(surfaces, "g04_helper_no_config", "upload")
    assert s and s.verdict == "EXPECTED_GUARD_UNPROVEN"  # entry has no guard


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
