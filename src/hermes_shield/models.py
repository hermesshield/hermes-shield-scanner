"""Hermes Shield MVP-1A — scan data model (product-shape). stdlib-only, no secrets."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict

SCANNER_VERSION = "0.7.1"

# capability taxonomy
CAPABILITIES = [
    "post", "reply", "comment", "like", "dm", "email_send", "telegram_send",
    "browser_click", "browser_type", "browser_submit", "computer_use",
    "queue_mutation", "db_mutation", "cron_mutation", "env_mutation",
    "external_api_call", "model_call", "vision_model_call", "pdf_ocr_ingest",
    "dashboard_mutation", "approval_mutation", "unknown_action",
    "deserialize", "code_exec", "cloud_write", "blockchain_tx", "payment", "file_perms", "tool_invoke", "dynamic_sql_review", "external_read", "dynamic_dispatch",
    # S3.1 chain-add review flags: SSRF (non-constant fetch URL) + RAG retrieval read-back source
    "ssrf_fetch", "knowledge_retrieval",
    "ssti",   # S8.63 server-side template injection (render_template_string / jinja from_string on untrusted) -> RCE
    "secret_exfil",   # S8.72 secret serialised->egress / secret->LLM prompt (LangGrinch CVE-2025-68664 shape)
]
RISK = ["critical", "high", "medium", "low"]
SURFACE_VERDICTS = [
    "PROTECTED_FULL_PATH", "PROTECTED_TEXT_PATH_ONLY", "STATIC_PROOF_ONLY",
    "PROVIDER_SCOPE", "HUMAN_REVIEW_ONLY", "PASS_WITH_RESIDUAL_RISK",
    "NEEDS_CERTIFICATION", "NEEDS_RETEST", "DRIFT_DETECTED", "GUARD_LOST",
    "BLOCK_LIVE_PROMOTION", "UNKNOWN_REVIEW_REQUIRED",
    # P2.9B honest-evidence labels
    "STATIC_EVIDENCE_ONLY", "CALLER_GUARDED_NOT_PROVEN", "NEEDS_CALL_GRAPH",
    "READ_ONLY_SURFACE", "DEBUG_OR_TEST_ONLY", "GENERATED_ARTIFACT_ONLY", "UNKNOWN_CAPABILITY",
    # P2.9C-REVIEW: cross-module proof is weaker than same-function (invisible dynamic callers)
    "PROTECTED_CROSS_MODULE_VISIBLE",
    # P2.9F: reviewed entrypoint map for public helpers
    "PROTECTED_BY_REVIEWED_ENTRYPOINT", "NEEDS_ENTRYPOINT_CONFIG", "NEEDS_ENTRYPOINT_REVIEW",
    # S8.19 FP demotions (real sink, but not a critical-unguarded headline)
    "AUTH_GATED_REVIEW", "CONFIG_DESTINATION_WRITE_REVIEW", "SUBPROCESS_NON_SHELL_REVIEW",
    "EXPECTED_GUARD_MISSING", "EXPECTED_GUARD_UNPROVEN",
    # P2.9G / Stage 1.5: guard-integrity — a control is present but looks like a no-op / fail-open stub
    "GUARD_INTEGRITY_SUSPECT",
    # S2.4 AI-assist tier: model-proposed, AST-line-verified, needs human review (never a static headline)
    "AI_SUSPECTED_REVIEW",
    # S6.1 guard-attribution: an untrusted-reachable live-action sink with NO critical guard on any path
    "UNGUARDED_CRITICAL_LIVE_SINK",
]
# guard_evidence_level: proven_before_sink | wrapper_proven | static_only | none
# protection_confidence: high | medium | low | none
SCOPES = ["full_path_tested", "text_path_only", "static_proof_only",
          "provider_scope", "residual", "untested_gap"]
DRIFT_VERDICTS = ["NO_DRIFT", "DRIFT_DETECTED", "NEEDS_RETEST", "NEEDS_CERTIFICATION",
                  "GUARD_LOST", "BLOCK_LIVE_PROMOTION", "REVIEW_REQUIRED"]


@dataclass
class GuardEvidence:
    kill_switch: bool = False
    final_action_gate: bool = False
    strict_hash: bool = False
    dry_run: bool = False
    human_approval: bool = False
    csrf_token: bool = False
    untrusted_fence: bool = False
    certified: bool = False
    markers: List[str] = field(default_factory=list)


@dataclass
class TestEvidence:
    test_files: List[str] = field(default_factory=list)
    adversarial: bool = False
    mutation: bool = False


@dataclass
class ActionSurface:
    id: str
    file_path: str
    line_start: int = 0
    line_end: int = 0
    symbol: str = ""
    capability: str = "unknown_action"
    risk_level: str = "medium"
    live_capable: str = "unknown"          # yes/no/unknown
    dry_run_supported: str = "unknown"
    context: str = "prod"                  # prod / test / report / dev
    likely_lane: str = ""
    certified: str = "unknown"
    guards: GuardEvidence = field(default_factory=GuardEvidence)
    ingress_links: List[str] = field(default_factory=list)
    tests: TestEvidence = field(default_factory=TestEvidence)
    scope: str = "untested_gap"
    verdict: str = "UNKNOWN_REVIEW_REQUIRED"
    fingerprint: str = ""
    patch_recommendations: List[str] = field(default_factory=list)
    # P2.9B honest-evidence additions
    sink_name: str = ""
    mutating: str = "unknown"                 # yes/no/unknown (read-only network vs mutating)
    guard_proof: dict = field(default_factory=lambda: {"status": "unproven", "proof_type": "not_run", "limitations": []})
    guard_evidence_level: str = "none"        # proven_before_sink|wrapper_proven|static_only|none
    protection_confidence: str = "none"       # high|medium|low|none
    live_promotion_verdict: str = "REVIEW"    # ALLOW|BLOCK|REVIEW
    stable_id: str = ""                       # (file, symbol, capability, sink) identity for drift
    # P2.9E AST sink detection
    sink_detection_mode: str = "ast_call"     # ast_call|ast_write|ast_chained_call|static_artifact|regex_fallback
    module_scope: bool = False
    static_artifact_type: str = ""            # STATIC_ARTEFACT_EVIDENCE subtype, if any
    # S1.6 taint: is this sink reachable from an untrusted input (intra-function, best-effort)?
    tainted_reachable: bool = False
    taint_source: str = ""
    # S8 inter-procedural taint: the exact sink CALL line (line_start is the enclosing def) so cross-function
    # taint joins on the right line — a function with one tainted + one clean sink must not over-mark.
    sink_line: int = 0
    # S8.19 FP demotion evidence: destination provenance for external_write (constant/config/untrusted/
    # unknown) and whether the enclosing route is authenticated (FastAPI Depends(current_org/user)).
    dest_provenance: str = "unknown"
    auth_gated: bool = False
    shell_form: bool = True            # S8.46: subprocess is shell-interpreted (shell=True/os.system) -> a tainted arg is injectable
    language: str = "python"          # S8.24 multi-language: python | typescript | ...
    # S2.4 AI-assist tier: static | ai_suspected (model-asserted, AST-line-verified) | ai_corroborated
    detection_source: str = "static"
    ai_confidence: float = 0.0
    # ADVISORY-ONLY reachability for AI-suspected surfaces. "AI suggests, engine checks reachability" is a
    # useful signal, but a model GUESS must NEVER land a deterministic verdict in the shared .verdict field
    # (that leaks into the customer-facing RED/AMBER headline). guard_attribution records the engine's
    # reachability check HERE instead, leaving .verdict == "AI_SUSPECTED_REVIEW". Empty for static surfaces.
    ai_reachability: dict = field(default_factory=dict)
    # S6.1 guard-attribution: is a CRITICAL guard proven on EVERY path to this sink? (downgrade-only;
    # unknown = unproven = no. severity_rank is the deterministic ordering key, 0 = most severe.)
    guard_attribution: dict = field(default_factory=lambda: {
        "critical_guard_on_path": "unknown", "guards_found": [], "unguarded_paths": [],
        "resolution_limits": [], "path_scope": "intraprocedural"})
    severity_rank: int = 99

    def to_dict(self):
        d = asdict(self)
        # ADVISORY-ONLY: ai_reachability is populated by guard_attribution for AI-suspected
        # surfaces only. Static (AI-off) surfaces leave it empty; omit the key entirely then so
        # the deterministic machine artifacts (hermes_action_surface_scan.json, findings.json)
        # stay byte-for-byte identical to a pre-fix AI-off scan. It only appears once real
        # advisory reachability exists, i.e. exactly on the AI path.
        if not d.get("ai_reachability"):
            d.pop("ai_reachability", None)
        return d


@dataclass
class UntrustedIngress:
    id: str
    file_path: str
    source_type: str                       # x_post / linkedin / email / web / github / pdf / ocr / telegram / dashboard / api
    line: int = 0
    fenced: bool = False
    fence_markers: List[str] = field(default_factory=list)
    classification: str = "unknown_review_required"  # fenced_full_path/fenced_text_path_only/static_instruction_only/unfenced
    context: str = "prod"

    def to_dict(self):
        return asdict(self)


@dataclass
class PatchPlanItem:
    surface_id: str
    finding: str
    severity: str
    why: str
    required_control: str
    suggested_file: str
    suggested_test: str
    human_approval_required: bool
    block_live_promotion: bool

    def to_dict(self):
        return asdict(self)


@dataclass
class DriftFinding:
    kind: str
    surface_id: str
    detail: str
    severity: str
    verdict: str

    def to_dict(self):
        return asdict(self)
