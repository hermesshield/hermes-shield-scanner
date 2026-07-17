"""Dashboard export JSON (read-only; future /shield can ingest)."""
from __future__ import annotations
from collections import Counter


def build(scan: dict, drift_overall: str, drift_findings, patch_items, baseline_status: str, scan_time: str):
    surfaces = scan["surfaces"]
    # DETERMINISTIC HEADLINE = STATIC ONLY. The overall_verdict, block_live_promotion count and top_risks
    # are deterministic — a model GUESS (detection_source != "static") must never drive them. Verdict/scope
    # tallies and the block set are built from static surfaces alone; action_surfaces stays a full map count.
    static = [s for s in surfaces if getattr(s, "detection_source", "static") == "static"]
    verdicts = Counter(s.verdict for s in static)
    scopes = Counter(s.scope for s in static)
    block = [s for s in static if s.verdict in ("BLOCK_LIVE_PROMOTION", "GUARD_LOST", "UNGUARDED_CRITICAL_LIVE_SINK")]
    overall = "BLOCK_LIVE_PROMOTION" if block else ("DRIFT_DETECTED" if drift_overall == "DRIFT_DETECTED" else "PASS_WITH_RESIDUAL_RISK")
    return {
        "overall_verdict": overall,
        "scan_time": scan_time,
        "scanner_version": scan["scanner_version"],
        "action_surfaces": len(surfaces),
        "untrusted_ingresses": len(scan["ingresses"]),
        "protected_full_path": verdicts.get("PROTECTED_FULL_PATH", 0),
        "text_path_only": verdicts.get("PROTECTED_TEXT_PATH_ONLY", 0),
        "provider_scope": verdicts.get("PROVIDER_SCOPE", 0),
        "residual": scopes.get("residual", 0),
        "needs_certification": verdicts.get("NEEDS_CERTIFICATION", 0),
        "needs_retest": verdicts.get("NEEDS_RETEST", 0),
        "drift_detected": len(drift_findings),
        "block_live_promotion": len(block),
        "top_risks": [f"{s.capability} @ {s.file_path}:{s.line_start}" for s in
                      sorted(block, key=lambda x: x.risk_level)[:10]],
        "patch_plan_summary": {"items": len(patch_items),
                               "blocking": sum(1 for p in patch_items if p.block_live_promotion)},
        "baseline_status": baseline_status,
    }
