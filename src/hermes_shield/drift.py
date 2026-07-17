"""Baseline diff / drift detector. Compares a fresh scan against a saved baseline. Read-only."""
from __future__ import annotations
from .models import DriftFinding


def diff(baseline: dict, scan: dict):
    findings = []
    base_s = baseline.get("surfaces", {})
    # P2.9B: STABLE identity so a line shift is not a new surface
    cur_s = {(s.stable_id or s.id): s for s in scan["surfaces"]}
    base_i = baseline.get("ingresses", {})
    cur_i = {i.id: i for i in scan["ingresses"]}

    for sid, s in cur_s.items():
        if sid not in base_s:
            if s.live_capable == "yes":
                findings.append(DriftFinding("new_live_action_surface", sid,
                    f"new {s.capability} in {s.file_path}", "high", "BLOCK_LIVE_PROMOTION"))
            else:
                findings.append(DriftFinding("new_surface", sid,
                    f"new {s.capability} in {s.file_path}", "medium", "REVIEW_REQUIRED"))
            continue
        b = base_s[sid]
        # capability change on the same (file,symbol,sink) identity
        if b.get("cap") and b["cap"] != s.capability:
            findings.append(DriftFinding("capability_changed", sid,
                f"{s.file_path} {b['cap']} -> {s.capability}", "high", "NEEDS_RETEST"))
        if b["fingerprint"] != s.fingerprint:
            findings.append(DriftFinding("changed_surface", sid,
                f"{s.capability} in {s.file_path} changed since baseline", "high", "NEEDS_RETEST"))
        # guard-evidence downgrade (protection weakened) — even across a line shift
        base_lvl = b.get("guard_evidence_level", "none")
        _rank = {"proven_before_sink": 3, "wrapper_proven": 2, "static_only": 1, "none": 0}
        if _rank.get(s.guard_evidence_level, 0) < _rank.get(base_lvl, 0):
            findings.append(DriftFinding("protection_changed", sid,
                f"guard evidence weakened: {base_lvl} -> {s.guard_evidence_level}", "high", "NEEDS_RETEST"))
        base_guards = set(b.get("guards", []))
        cur_guards = {k for k, v in s.guards.__dict__.items() if v is True}
        lost = base_guards - cur_guards
        if lost:
            sev = "critical" if "kill_switch" in lost or "final_action_gate" in lost else "high"
            findings.append(DriftFinding("guard_removed", sid,
                f"guard(s) lost: {sorted(lost)}", sev,
                "GUARD_LOST" if sev == "critical" else "NEEDS_RETEST"))

    for sid in base_s:
        if sid not in cur_s:
            findings.append(DriftFinding("removed_surface", sid, "surface no longer present",
                "low", "REVIEW_REQUIRED"))

    for iid, i in cur_i.items():
        if iid not in base_i:
            findings.append(DriftFinding("untrusted_ingress_added", iid,
                f"new {i.source_type} ingress in {i.file_path}",
                "medium", "REVIEW_REQUIRED"))
        elif not i.fenced and base_i[iid].get("fenced"):
            findings.append(DriftFinding("untrusted_fence_removed", iid,
                f"fence removed on {i.source_type} in {i.file_path}", "high", "BLOCK_LIVE_PROMOTION"))

    overall = "NO_DRIFT"
    if findings:
        sevs = {f.verdict for f in findings}
        for v in ("BLOCK_LIVE_PROMOTION", "GUARD_LOST", "NEEDS_RETEST", "NEEDS_CERTIFICATION", "REVIEW_REQUIRED"):
            if v in sevs:
                overall = "DRIFT_DETECTED"
                break
    return overall, findings
