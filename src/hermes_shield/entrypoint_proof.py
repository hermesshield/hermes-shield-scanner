"""
Hermes Shield MVP — reviewed real-entrypoint proof (P2.9F).

A PUBLIC helper (externally callable) is never PROTECTED_FULL_PATH just because one caller guards. If
it is EXPLICITLY modelled in config/entrypoints.json with allowed_callers + expected guards, and EVERY
in-file caller (a) is an allowed caller AND (b) runs an EXPECTED guard BEFORE calling the helper, we
emit the WEAKER, honest verdict PROTECTED_BY_REVIEWED_ENTRYPOINT (records the public-helper residual).
If a caller is not allowed -> NEEDS_ENTRYPOINT_CONFIG. If the expected guard is missing / after the
call -> EXPECTED_GUARD_UNPROVEN (+ patch-plan diagnostic). Static only; never over-credits.
"""
from __future__ import annotations
from pathlib import Path
from typing import List

from . import patterns as PAT
from .call_graph import FileGraph
from .config_loader import load_entrypoints
from .cross_module import _all_py_rel, build_graphs, _dotted


def _guard_kinds_before(fg: FileGraph, caller: str, call_line: int) -> set:
    f = fg.funcs.get(caller)
    if not f:
        return set()
    return {g[1] for g in f["top_guards"] if g[0] < call_line}


def apply(root: Path, surfaces, patch_items, config=None, graphs=None) -> dict:
    """Post-pass over unproven critical PUBLIC-helper surfaces. Upgrades to reviewed-entrypoint verdict
    only where the config supports it AND expected guards are proven before the call. Returns counts.
    S8 speed: accepts a shared graph build."""
    _entrypoints, helpers = config if config is not None else load_entrypoints()
    if not helpers:
        return {"reviewed_entrypoint_proven": 0, "expected_guard_unproven": 0, "needs_entrypoint_config": 0}
    if graphs is None:
        graphs = build_graphs(root, _all_py_rel(root))
    counts = {"reviewed_entrypoint_proven": 0, "expected_guard_unproven": 0, "needs_entrypoint_config": 0}
    # S8.82 (CTO review #5): idempotent patch-plan — never re-append a diagnostic for a surface already
    # present. The S8.81 AI re-run calls apply() a SECOND time with the SAME patch_items list; without this
    # guard the EXPECTED_GUARD_UNPROVEN item would be duplicated on the re-run.
    _existing_patch_ids = {p.get("surface_id") for p in patch_items}

    for s in surfaces:
        if s.context != "prod" or s.capability not in PAT.CRITICAL_CAPS:
            continue
        # AI-suspected surfaces are advisory only: never stamp a deterministic entrypoint verdict on a model
        # GUESS. Leave .verdict == "AI_SUSPECTED_REVIEW" so it cannot enter the deterministic headline.
        if getattr(s, "detection_source", "static") != "static":
            continue
        if s.guard_proof.get("status") == "proven":
            continue
        mod_tail = _dotted(s.file_path).split(".")[-1]
        policy = helpers.get((mod_tail, s.symbol))
        if not policy:
            continue  # not a modelled helper
        allowed = set(policy.get("allowed_callers", []))
        expected = set(policy.get("expected_guards", policy.get("expected_guard", []) or []))
        # find all in-file callers of this helper symbol
        hg = graphs.get(s.file_path)
        callers: List[tuple] = []
        if hg:
            for cname, f in hg.funcs.items():
                for (line, callee) in f["local_calls"]:
                    if callee == s.symbol:
                        callers.append((cname, line))
        if not callers:
            s.verdict = "NEEDS_ENTRYPOINT_CONFIG"
            s.guard_proof = {"status": "needs_entrypoint_config", "proof_type": "no_in_file_caller",
                             "helper_visibility": "public_helper", "limitations": ["no resolvable in-file caller"]}
            counts["needs_entrypoint_config"] += 1
            continue

        disallowed = [c for c, _ in callers if allowed and c not in allowed]
        # expected-guard check: every caller must run an expected guard BEFORE the call
        guard_gap = []
        for cname, line in callers:
            kinds = _guard_kinds_before(hg, cname, line)
            if expected and not (kinds & expected):
                guard_gap.append((cname, line))

        if disallowed:
            s.verdict = "NEEDS_ENTRYPOINT_CONFIG"
            s.guard_proof = {"status": "needs_entrypoint_config", "proof_type": "caller_not_allowed",
                             "entrypoint_status": "caller_not_in_allowed_callers",
                             "helper_visibility": "public_helper", "disallowed_callers": disallowed,
                             "limitations": ["caller not in allowed_callers"]}
            counts["needs_entrypoint_config"] += 1
        elif guard_gap:
            s.verdict = "EXPECTED_GUARD_UNPROVEN"
            s.live_promotion_verdict = "BLOCK"
            s.guard_proof = {"status": "expected_guard_unproven", "proof_type": "expected_guard_not_before_sink",
                             "helper_visibility": "public_helper", "expected_guards": sorted(expected),
                             "unguarded_callers": guard_gap,
                             "limitations": ["an allowed caller does not run the expected guard before the call"]}
            if s.id not in _existing_patch_ids:
                patch_items.append({
                    "surface_id": s.id, "severity": "high",
                    "finding": f"{s.symbol} ({s.capability}) reached via {guard_gap} without the expected guard {sorted(expected)} before the call",
                    "required_control": f"run {sorted(expected)} BEFORE calling {s.symbol}",
                    "suggested_file": s.file_path, "scanner_or_production": "PRODUCTION_CODE_CHANGE",
                    "human_approval_required": True, "block_live_promotion": True})
                _existing_patch_ids.add(s.id)
            counts["expected_guard_unproven"] += 1
        else:
            s.verdict = "PROTECTED_BY_REVIEWED_ENTRYPOINT"
            s.live_promotion_verdict = "REVIEW"
            s.guard_proof = {"status": "proven_by_reviewed_entrypoint",
                             "proof_type": "reviewed_entrypoint_guard_before_helper",
                             "entrypoint_status": "modelled", "helper_visibility": "public_helper",
                             "allowed_callers": sorted(allowed), "expected_guards": sorted(expected),
                             "modelled_call_path": [f"{c}->{s.symbol}" for c, _ in callers],
                             "reviewed_entrypoint_limitations": ["helper remains technically public / externally callable"],
                             "proof_policy": policy.get("proof_policy", "allowed_entrypoint_required")}
            counts["reviewed_entrypoint_proven"] += 1
    return counts
