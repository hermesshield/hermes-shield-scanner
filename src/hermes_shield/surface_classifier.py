"""Assign scope + verdict to each ActionSurface from AST-proven guard evidence (P2.9B).

Core rule: PROTECTED_FULL_PATH is emitted ONLY when the call-graph proves a guard runs before the
action sink. A guard marker that merely exists in the file downgrades to STATIC_EVIDENCE_ONLY /
CALLER_GUARDED_NOT_PROVEN / NEEDS_CALL_GRAPH — never a full-path protection claim. Read-only, debug,
test, and generator surfaces are classified honestly, not silently suppressed. No secrets."""
from __future__ import annotations
from .models import ActionSurface
from . import patterns as PAT


def _promotion(verdict: str) -> str:
    if verdict in ("PROTECTED_FULL_PATH",):
        return "ALLOW"
    if verdict in ("BLOCK_LIVE_PROMOTION", "GUARD_LOST", "NEEDS_CERTIFICATION", "UNGUARDED_CRITICAL_LIVE_SINK"):
        return "BLOCK"
    return "REVIEW"


def classify(s: ActionSurface, certified_lanes=None) -> ActionSurface:
    g = s.guards
    proof = s.guard_proof or {}
    proven = proof.get("status") == "proven"

    # 1) non-live contexts: honest low-risk labels, not protection claims
    if s.context in ("test",):
        s.scope = "static_proof_only"; s.verdict = "DEBUG_OR_TEST_ONLY"
        s.live_promotion_verdict = "REVIEW"; return s
    if s.context in ("report",):
        s.scope = "static_proof_only"; s.verdict = "STATIC_EVIDENCE_ONLY"
        s.live_promotion_verdict = "REVIEW"; return s
    if s.context in ("dev",):
        s.scope = "static_proof_only"; s.verdict = "DEBUG_OR_TEST_ONLY"
        s.live_promotion_verdict = "REVIEW"; return s

    # 2) read-only surfaces (requests.get, model/ocr read) are not live-action blockers
    if s.mutating == "no":
        if s.capability == "vision_model_call":
            s.scope = "provider_scope"; s.verdict = "PROVIDER_SCOPE"
        elif s.capability in ("model_call", "pdf_ocr_ingest", "external_read"):
            s.scope = "text_path_only" if g.untrusted_fence else "residual"
            s.verdict = "PROTECTED_TEXT_PATH_ONLY" if g.untrusted_fence else "READ_ONLY_SURFACE"
        else:
            s.verdict = "READ_ONLY_SURFACE"; s.scope = "static_proof_only"
        s.live_promotion_verdict = _promotion(s.verdict); return s

    critical = s.capability in PAT.CRITICAL_CAPS
    fenced = g.untrusted_fence

    # 3) dashboard mutation: CSRF guard, proven via AST if possible
    if s.capability == "dashboard_mutation":
        if proven and proof.get("guard_kind") in ("csrf_token", "caller"):
            s.scope = "full_path_tested"; s.verdict = "PROTECTED_FULL_PATH"
        elif g.csrf_token:
            s.scope = "static_proof_only"; s.verdict = "STATIC_EVIDENCE_ONLY"
        else:
            s.scope = "untested_gap"; s.verdict = "NEEDS_CERTIFICATION"
            s.patch_recommendations.append("Add dashboard_auth CSRF/token check before this POST route mutates state")
        s.live_promotion_verdict = _promotion(s.verdict); return s

    # 4) critical outbound/mutating sinks — the honest core
    if critical:
        if proven and proof.get("scope") == "interprocedural":
            # P2.9C-REVIEW: cross-module proof only checks STATICALLY-VISIBLE callers; an invisible
            # dynamic/reflective caller could reach the sink unguarded. So it is NOT full-path — it is
            # a distinct, weaker verdict that carries that residual (never live-promotion ALLOW).
            s.scope = "static_proof_only"
            s.verdict = "PROTECTED_CROSS_MODULE_VISIBLE"
            s.live_promotion_verdict = "REVIEW"
            s.patch_recommendations.append("Cross-module proof covers visible callers only; dynamic/reflective callers unverified")
            return s
        if proven:
            # intraprocedural (same-function / private-wrapper) proof is sound
            s.scope = "full_path_tested" if s.tests.test_files else "static_proof_only"
            s.verdict = "PROTECTED_FULL_PATH" if s.tests.test_files else "NEEDS_RETEST"
        elif proof.get("status") == "caller_guarded_not_proven":
            s.scope = "untested_gap"; s.verdict = "CALLER_GUARDED_NOT_PROVEN"
            s.patch_recommendations.append("At least one in-file caller reaches this sink without a guard; prove or add guard-before-call")
        elif proof.get("status") == "cross_module_guarded_not_proven":
            s.scope = "untested_gap"; s.verdict = "CALLER_GUARDED_NOT_PROVEN"
            s.patch_recommendations.append("Cross-module: some call sites guarded, but unguarded/ambiguous sites remain; prove all entry paths")
        elif proof.get("proof_type") == "guard_elsewhere_in_file":
            # a REAL guard call exists in the file (AST) but not proven before this sink -> honest downgrade
            s.scope = "static_proof_only"; s.verdict = "STATIC_EVIDENCE_ONLY"
            s.patch_recommendations.append("Guard call present but not proven before the sink; add same-function guard or prove wrapper")
        elif proof.get("proof_type") in ("no_enclosing_function", "parse_failed"):
            s.scope = "untested_gap"; s.verdict = "NEEDS_CALL_GRAPH"
        else:
            # no real guard call reaches this sink -> conservative block
            s.scope = "untested_gap"; s.verdict = "BLOCK_LIVE_PROMOTION"
            s.patch_recommendations.append("Add global kill-switch guard (assert_live_action_allowed) before this outbound action")
        # apply fenced nuance for proven-but-untested criticals
        if s.verdict == "NEEDS_RETEST" and fenced:
            s.verdict = "PROTECTED_TEXT_PATH_ONLY"
        s.live_promotion_verdict = _promotion(s.verdict); return s

    # 5) medium/low mutating: residual with honest confidence
    if proven:
        s.scope = "static_proof_only"; s.verdict = "PROTECTED_TEXT_PATH_ONLY"
    else:
        s.scope = "residual"; s.verdict = "PASS_WITH_RESIDUAL_RISK"
    s.live_promotion_verdict = _promotion(s.verdict)
    return s
