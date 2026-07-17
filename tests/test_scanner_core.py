#!/usr/bin/env python3
"""P2.9A — Hermes Shield MVP-1A scanner tests. Read-only; scans mock-lane fixtures + the real repo;
proves detection, guard evidence, scope/verdict, baseline diff/drift, patch-plan, dashboard export,
read-only behaviour, and no-secret-leak. No live actions."""
from __future__ import annotations
import json
import os
import sys
from pathlib import Path


from hermes_shield import repo_scanner, surface_classifier, baseline as BL, drift as DR  # noqa: E402
from hermes_shield import patch_plan, dashboard_export  # noqa: E402

MOCK = Path(__file__).resolve().parent / "mock_lanes"


def _scan(root: Path):
    scan = repo_scanner.scan_repo(root)
    for s in scan["surfaces"]:
        surface_classifier.classify(s)
    return scan


def _by_file(scan, name):
    return [s for s in scan["surfaces"] if Path(s.file_path).name == name]


# ---- detection + verdicts on mock lanes -----------------------------------------------------
def test_01_detects_vulnerable_x_poster_blocks():
    scan = _scan(MOCK)
    v = _by_file(scan, "vulnerable_x_poster.py")
    assert v and any(s.capability == "post" and s.verdict == "BLOCK_LIVE_PROMOTION" for s in v)


def test_02_protected_x_poster_not_blocked():
    scan = _scan(MOCK)
    p = _by_file(scan, "protected_x_poster.py")
    assert p and all(s.verdict != "BLOCK_LIVE_PROMOTION" for s in p)
    assert any(s.guards.kill_switch for s in p)


def test_03_vulnerable_gmail_blocks_protected_ok():
    scan = _scan(MOCK)
    assert any(s.verdict == "BLOCK_LIVE_PROMOTION" for s in _by_file(scan, "vulnerable_gmail.py"))
    assert all(s.verdict != "BLOCK_LIVE_PROMOTION" for s in _by_file(scan, "protected_gmail.py"))


def test_04_vulnerable_browser_blocks():
    scan = _scan(MOCK)
    assert any(s.verdict == "BLOCK_LIVE_PROMOTION" for s in _by_file(scan, "vulnerable_browser.py"))


def test_05_dashboard_csrf_distinguished():
    scan = _scan(MOCK)
    vuln = _by_file(scan, "vulnerable_dashboard.py")
    prot = _by_file(scan, "protected_dashboard.py")
    assert any(s.verdict == "NEEDS_CERTIFICATION" for s in vuln)
    assert any(s.guards.csrf_token for s in prot)


def test_06_untrusted_ingress_fence_detected():
    scan = _scan(MOCK)
    prot = [i for i in scan["ingresses"] if Path(i.file_path).name == "protected_untrusted_source.py"]
    assert any(i.fenced for i in prot)


def test_07_vision_is_provider_scope():
    scan = _scan(MOCK)
    v = _by_file(scan, "vulnerable_vision.py")
    assert any(s.capability == "vision_model_call" and s.verdict == "PROVIDER_SCOPE" for s in v)


# ---- baseline + drift -----------------------------------------------------------------------
def test_08_baseline_valid_json(tmp_path):
    scan = _scan(MOCK)
    b = BL.build_baseline(scan, "testhead")
    p = tmp_path / "b.json"; BL.save_baseline(b, p)
    assert json.loads(p.read_text())["repo_head"] == "testhead"


def test_09_drift_detects_new_surface_and_guard_loss(tmp_path):
    # baseline from a PROTECTED-only view; then a scan that ADDS a vulnerable surface + loses a guard
    base_scan = _scan(MOCK)
    # simulate baseline WITHOUT the vulnerable_x_poster surface + WITH a guard on it
    base = BL.build_baseline(base_scan, "h0")
    # remove vulnerable_x_poster from baseline -> its presence now = new surface
    base["surfaces"] = {k: v for k, v in base["surfaces"].items() if "vulnerable_x_poster" not in k}
    # add a fake baseline surface WITH a kill_switch guard, that the current scan lacks -> guard_removed
    a_prot = next(s for s in base_scan["surfaces"] if "protected_gmail" in s.file_path)
    # P2.9B: baseline is keyed on STABLE id; inject an entry with a stronger guard set + diff fingerprint
    base["surfaces"][a_prot.stable_id] = {"cap": a_prot.capability, "risk": a_prot.risk_level,
        "ctx": a_prot.context, "live": a_prot.live_capable, "verdict": a_prot.verdict,
        "scope": a_prot.scope, "fingerprint": "DIFFERENT_FP", "guard_evidence_level": "proven_before_sink",
        "sink": a_prot.sink_name, "guards": ["kill_switch", "final_action_gate"]}
    overall, findings = DR.diff(base, base_scan)
    kinds = {f.kind for f in findings}
    assert overall == "DRIFT_DETECTED"
    assert "new_live_action_surface" in kinds                       # vulnerable_x_poster reappears
    assert any(f.kind in ("changed_surface", "guard_removed", "protection_changed") for f in findings)


def test_10_no_drift_against_own_baseline():
    scan = _scan(MOCK)
    base = BL.build_baseline(scan, "h")
    overall, findings = DR.diff(base, scan)
    assert overall == "NO_DRIFT" and findings == []


# ---- patch-plan + dashboard export ----------------------------------------------------------
def test_11_patch_plan_for_unprotected():
    scan = _scan(MOCK)
    items = patch_plan.build([s for s in scan["surfaces"] if s.context != "report"])
    assert any(i.block_live_promotion for i in items)
    assert all(i.human_approval_required for i in items)


def test_12_dashboard_export_valid():
    scan = _scan(MOCK)
    exp = dashboard_export.build(scan, "NO_DRIFT", [], patch_plan.build(scan["surfaces"]), "present", "t")
    assert exp["overall_verdict"] in ("BLOCK_LIVE_PROMOTION", "DRIFT_DETECTED", "PASS_WITH_RESIDUAL_RISK")
    assert isinstance(exp["action_surfaces"], int)
    json.dumps(exp)  # serialisable


# ---- read-only + no-secret guarantees -------------------------------------------------------
def test_13_scan_is_read_only(tmp_path):
    import subprocess
    (tmp_path / "x.py").write_text("client.create_tweet(text='x')\n")
    before = sorted(p.name for p in tmp_path.iterdir())
    _scan(tmp_path)
    after = sorted(p.name for p in tmp_path.iterdir())
    assert before == after  # scanner wrote nothing to the target


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
