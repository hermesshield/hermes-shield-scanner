"""Patch-plan generator + remediation dictionary. Read-only: this module PLANS a fix — it never writes
one. It maps a dangerous action-surface to a fix-at-source control, keyed on the REAL capability
vocabulary (code_exec, subprocess_exec, deserialize, ssti, secret_exfil, tool_invoke, external_write,
file_delete, and the mutation caps) — NOT on any product-internal lane names.

The scanner suggests; a human (or the paid repairer, under a human gate) applies. Nothing here is
"auto-fix", and install-liability surfaces get wiring-time guidance, never "fix this vulnerability".
"""
from __future__ import annotations
from .models import PatchPlanItem
from . import install_report as _IR

# Fix-at-source remediation, keyed on the real dangerous-capability vocabulary. Customer-facing prose:
# concrete, actionable, no product-internal jargon.
_REMEDIATION = {
    "code_exec": "Replace eval/exec with ast.literal_eval (Python eval sandboxes are trivially escaped, so "
                 "never rely on one); if dynamic code is genuinely required, allowlist the inputs and "
                 "human-gate the call.",
    "subprocess_exec": "Run with shell=False and an argument allowlist; never interpolate model or user "
                       "output into the command string.",
    "deserialize": "Use yaml.safe_load / JSON instead of pickle; never unpickle untrusted bytes.",
    "ssti": "Enable autoescape and use a sandboxed template environment; never render model output as a "
            "template.",
    "secret_exfil": "Put an egress allowlist in front of outbound calls and scope secrets to the env that "
                    "needs them; block outbound traffic to non-allowlisted hosts.",
    "tool_invoke": "Put a final-action gate plus human approval on the tool dispatcher before any tool "
                   "call fires.",
    "xml_parse": "Parse XML with a hardened parser that disables external entities and DTDs (e.g. "
                 "defusedxml, or lxml with resolve_entities=False / no_network); never parse untrusted "
                 "XML with entity resolution enabled (XXE -> file read / SSRF).",
    "external_write": "Gate outbound writes behind a destination allowlist plus human approval; never send "
                      "to a host derived from untrusted input.",
    "file_write": "Confine writes to an allowlisted directory, canonicalise the path and reject traversal; "
                  "never write to a path built from untrusted input.",
    "file_delete": "Confine deletes to an allowlisted directory, canonicalise the path and require an "
                   "explicit confirmation; never delete a path built from untrusted input.",
    "publish_write": "Put a human-approval gate before any publish/post action and log the payload for "
                     "review.",
    "queue_mutation": "Require claim-before-write and an approval-hash gate before mutating the queue.",
    # ACTIONS-FIREWALL — reachable + unguarded agent-action sinks now counted by install_report. RED band
    # (high-impact) first, then the AMBER (reversible/social) band. Concrete fix-at-source controls so the
    # Repairer feed never falls through to the generic fallback for a live action sink.
    "payment": "Put a spend allowlist plus mandatory human approval in front of any payment/transfer call; "
               "cap the amount and never let untrusted input choose the payee or amount.",
    "blockchain_tx": "Require human approval and a signed, allowlisted destination for every on-chain "
                     "transaction; never build a transaction from untrusted input.",
    "cloud_write": "Scope cloud credentials least-privilege and gate writes behind an allowlisted "
                   "bucket/path plus human approval; never target a resource named by untrusted input.",
    "file_perms": "Never change file permissions/ownership from untrusted input; allowlist the paths and "
                  "human-gate any chmod/chown.",
    "email_send": "Put a recipient allowlist plus human approval before any email send; never let untrusted "
                  "input set the recipient, and log the payload for review.",
    "dm": "Put a recipient allowlist plus human approval before any direct-message send; never let untrusted "
          "input choose the recipient.",
    "telegram_send": "Put an allowlisted chat_id plus human approval in front of any Telegram send; never "
                     "let untrusted input choose the chat or message.",
    "post": "Put a human-approval gate before any public post/publish action and log the payload for review; "
            "never publish text derived directly from untrusted input.",
    "reply": "Put a human-approval gate before any public reply and log the payload for review; never reply "
             "with text derived directly from untrusted input.",
    "comment": "Put a human-approval gate before any public comment and log the payload for review.",
    "like": "Gate automated likes/favourites behind a rate limit and a human-approval switch; never drive "
            "them straight from untrusted input.",
    "db_mutation": "Parameterise every query and gate writes behind an authorisation check; never build "
                   "SQL from untrusted input.",
    "cron_mutation": "Gate schedule changes behind human approval; never let untrusted input add or edit a "
                     "scheduled job.",
    "env_mutation": "Treat environment/config writes as privileged: allowlist the keys and human-gate the "
                    "change.",
    "dashboard_mutation": "Require a CSRF token plus an Origin allowlist on the dashboard mutation "
                          "endpoint.",
    "approval_mutation": "Never let the acting agent write its own approvals; separate the approver from "
                         "the actor and gate the write.",
    "browser_submit": "Put a kill-switch plus human approval on the browser/computer-use bridge before any "
                      "form submit or click fires.",
    "browser_click": "Put a kill-switch plus human approval on the browser/computer-use bridge before any "
                     "form submit or click fires.",
    "computer_use": "Put a kill-switch plus human approval on the computer-use bridge before any real "
                    "action fires.",
}

# Generic fallback — still specific enough to act on (not jargon, not a shrug).
_FALLBACK = ("Put a control in front of this action — a kill-switch plus a human-approval gate — and "
             "ensure untrusted input can never reach it unchecked.")

# DE-NOISE / FIX-GROUPING — the one real CONTROL POINT each capability is fixed at. The scanner emits ONE
# patch-plan row per dangerous CALL SITE (correct — the Repairer feed must be complete), but many call sites
# of the same capability close under ONE fix: a single tool-dispatcher gate covers every tool_invoke site, a
# single CSRF/Origin middleware covers every dashboard_mutation endpoint, a single egress allowlist covers
# every outbound write. `control_point` maps a capability to that single fix — its stable slug (fix_group_id)
# and a human label — so the machine feed keeps EVERY row (nothing dropped) while the human report can render
# ONE fix-card per control point ("this one gate covers 388 call sites") instead of 388 identical rows.
# Keyed 1:1 on capability so grouping is GROUPING ONLY — two distinct capabilities are never merged, and no
# genuine distinct fix is ever lost.
_CONTROL_POINT = {
    "code_exec": ("no-dynamic-exec", "the dynamic-exec call site (replace eval/exec with a safe parse)"),
    "subprocess_exec": ("subprocess-allowlist", "the subprocess launcher (shell=False + arg allowlist)"),
    "deserialize": ("safe-deserialize", "the deserialization call (safe_load / no untrusted pickle)"),
    "ssti": ("template-sandbox", "the template render path (autoescape + sandboxed environment)"),
    "xml_parse": ("hardened-xml-parser", "the XML parser (disable external entities / DTDs)"),
    "secret_exfil": ("egress-allowlist", "the outbound-egress boundary (allowlist + secret scoping)"),
    "external_write": ("outbound-write-allowlist", "the outbound-write boundary (destination allowlist)"),
    "file_write": ("write-path-confine", "the file-write path (confine + canonicalise + reject traversal)"),
    "file_delete": ("delete-path-confine", "the file-delete path (confine + explicit confirmation)"),
    "file_perms": ("perms-allowlist", "the chmod/chown path (allowlist + human gate)"),
    "tool_invoke": ("tool-dispatcher-gate", "the tool dispatcher (final-action gate + human approval)"),
    "publish_write": ("publish-approval-gate", "the publish/post path (human-approval gate + payload log)"),
    "post": ("publish-approval-gate", "the public-post path (human-approval gate + payload log)"),
    "reply": ("publish-approval-gate", "the public-reply path (human-approval gate + payload log)"),
    "comment": ("publish-approval-gate", "the public-comment path (human-approval gate + payload log)"),
    "like": ("like-rate-gate", "the automated-like path (rate limit + human-approval switch)"),
    "email_send": ("recipient-allowlist", "the email-send path (recipient allowlist + human approval)"),
    "dm": ("recipient-allowlist", "the direct-message path (recipient allowlist + human approval)"),
    "telegram_send": ("recipient-allowlist", "the Telegram-send path (chat_id allowlist + human approval)"),
    "payment": ("spend-approval-gate", "the payment/transfer path (spend allowlist + human approval)"),
    "blockchain_tx": ("onchain-approval-gate", "the on-chain-tx path (signed allowlisted dest + approval)"),
    "cloud_write": ("cloud-write-allowlist", "the cloud-write path (least-priv creds + bucket allowlist)"),
    "db_mutation": ("db-parameterise-authz", "the DB-write path (parameterise + authorisation check)"),
    "queue_mutation": ("queue-claim-gate", "the queue-write path (claim-before-write + approval-hash)"),
    "cron_mutation": ("schedule-approval-gate", "the schedule-change path (human approval)"),
    "env_mutation": ("env-key-allowlist", "the env/config-write path (key allowlist + human gate)"),
    "dashboard_mutation": ("dashboard-csrf-origin", "the dashboard-mutation middleware (CSRF token + Origin allowlist)"),
    "approval_mutation": ("approver-actor-split", "the approval-write path (separate approver from actor)"),
    "browser_submit": ("browser-bridge-killswitch", "the browser/computer-use bridge (kill-switch + approval)"),
    "browser_click": ("browser-bridge-killswitch", "the browser/computer-use bridge (kill-switch + approval)"),
    "computer_use": ("computer-use-killswitch", "the computer-use bridge (kill-switch + approval)"),
}
_CONTROL_POINT_FALLBACK = ("generic-control-gate", "the action call site (kill-switch + human-approval gate)")

# Verdict -> actionability class for DE-NOISE reclassification. A patch-plan row is only a real "fix now"
# instruction when there is genuinely NO control and the sink is reachable/unguarded. Two big noise bands are
# reclassified so they never masquerade as critical fixes:
#   * INFORMATIONAL — a READ_ONLY surface (e.g. get_context_window / summarize_messages): no gate is needed;
#     certify before ship. Not a fix.
#   * REVIEW — a demoted fixed-destination write (CONFIG_DESTINATION_WRITE_REVIEW: LLM-provider API calls with
#     a proven-constant destination) or a NEEDS_CERTIFICATION / non-shell subprocess review: certify, then gate.
#   * HELD — a control may already be present or reachability is unproven: verify first, never blind-change.
# Everything else (BLOCK_LIVE_PROMOTION, UNGUARDED_CRITICAL_LIVE_SINK, GUARD_LOST/NOOP, EXPECTED_GUARD_MISSING)
# is a GATE (actionable now).
_INFORMATIONAL_VERDICTS = {"READ_ONLY_SURFACE"}
_REVIEW_VERDICTS = {"NEEDS_CERTIFICATION", "CONFIG_DESTINATION_WRITE_REVIEW", "SUBPROCESS_NON_SHELL_REVIEW"}
_HELD_VERDICTS = {"CALLER_GUARDED_NOT_PROVEN", "NEEDS_CALL_GRAPH", "NEEDS_ENTRYPOINT_CONFIG",
                  "NEEDS_ENTRYPOINT_REVIEW", "EXPECTED_GUARD_UNPROVEN", "GUARD_DEF_UNRESOLVED",
                  "GUARD_BLOCK_SHAPED_UNVERIFIED"}

# Class ranking for salience (lower == more urgent). GATE leads; INFORMATIONAL is never a fix.
_CLASS_ORDER = {"gate": 0, "review": 1, "held": 2, "informational": 3}

# Per-capability severity weight for the leverage ranking (sites-closed × severity). Mirrors
# install_report._SEVERITY; kept local so patch_plan has no import cycle with the reporting layer.
_SEVERITY = {
    "code_exec": 5, "ssti": 5, "deserialize": 5, "subprocess_exec": 5,
    "secret_exfil": 4, "secret-exfil": 4,
    "payment": 4, "blockchain_tx": 4, "cloud_write": 4, "file_perms": 4, "email_send": 4, "dm": 4,
    "telegram_send": 4, "computer_use": 4, "browser_submit": 3,
    "external_write": 3, "file_write": 3, "file_delete": 3, "tool_invoke": 3, "publish_write": 3,
    "xml_parse": 3, "dashboard_mutation": 3, "db_mutation": 3, "approval_mutation": 4,
    "post": 3, "reply": 3, "comment": 2, "like": 2, "browser_click": 2, "browser_type": 2,
    "queue_mutation": 2, "cron_mutation": 3, "env_mutation": 3, "model_call": 1, "external_read": 1,
}


def control_point(capability: str):
    """The single real CONTROL POINT a capability is fixed at: (fix_group_id, human label). Rows sharing a
    fix_group_id all close under ONE fix. Keyed 1:1 on capability — GROUPING ONLY, never a merge of two
    distinct capabilities. An unmapped capability gets its OWN per-capability fallback slug (never a shared
    bucket) so two distinct capabilities can never collapse into one card."""
    known = _CONTROL_POINT.get(capability)
    if known is not None:
        return known
    slug = (capability or "unknown").replace("_", "-") + "-" + _CONTROL_POINT_FALLBACK[0]
    return (slug, f"the {capability or 'action'} call site (kill-switch + human-approval gate)")


def fix_group_id(capability: str) -> str:
    """Stable slug for the control point (see control_point)."""
    return control_point(capability)[0]


def actionability(verdict: str) -> str:
    """DE-NOISE class of a verdict: 'informational' (no gate needed), 'review' (certify then gate), 'held'
    (verify first) or 'gate' (actionable now)."""
    if verdict in _INFORMATIONAL_VERDICTS:
        return "informational"
    if verdict in _REVIEW_VERDICTS:
        return "review"
    if verdict in _HELD_VERDICTS:
        return "held"
    return "gate"


def recommended_control(capability: str) -> str:
    """The fix-at-source control for a reachable dangerous capability. Falls back to a concrete generic
    control for capabilities not in the dictionary."""
    return _REMEDIATION.get(capability, _FALLBACK)


def wiring_control(capability: str) -> str:
    """Wiring-time guidance for an INSTALL-LIABILITY surface (inert in this repo, live on install). It is
    NOT a fix-now item and is never described as a vulnerability in this repo — the guidance is to gate the
    capability BEFORE untrusted input is wired to it on install."""
    return ("Inert here — gate this before you wire untrusted input to it on install: "
            + recommended_control(capability))


def _suggested_test(capability: str) -> str:
    """A neutral, customer-facing test suggestion (no product-internal lane jargon)."""
    return (f"Add a test that drives {capability} with a hostile input and asserts the control blocks it "
            f"(and that a benign input still passes).")


def build(surfaces):
    """Machine-readable patch plan (hermes_patch_plan.json). Read-only — PLANS a fix, never applies one."""
    items = []
    for s in surfaces:
        # AI-suspected surfaces (model GUESSES, detection_source != "static") are advisory — they never feed
        # the deterministic fix plan / Repairer queue. Their verdict stays AI_SUSPECTED_REVIEW; skip them.
        if getattr(s, "detection_source", "static") != "static":
            continue
        if s.verdict in ("PROTECTED_FULL_PATH", "STATIC_PROOF_ONLY", "PROVIDER_SCOPE",
                         "PROTECTED_TEXT_PATH_ONLY", "PASS_WITH_RESIDUAL_RISK"):
            continue
        # BLOCK_LIVE_PROMOTION == red-equivalent hard block. It must honour the SAME red/amber partition the
        # report uses: an explicit hard-block verdict OR a RED reachable-unguarded sink (is_non_gated_vulnerable
        # — RCE-class / high-impact action) blocks live promotion; a reachable AMBER action (post/reply/like,
        # is_reachable_amber_action) is "review before you ship", NOT red — so it is NEVER flagged
        # block_live_promotion. A bare `verdict == UNGUARDED_CRITICAL_LIVE_SINK` test over-stated the amber
        # social actions as red, contradicting the deterministic verdict for the same file:line.
        block = (s.verdict in ("BLOCK_LIVE_PROMOTION", "GUARD_LOST")
                 or _IR.is_non_gated_vulnerable(s))
        _gid, _cp = control_point(s.capability)
        _guards = getattr(s, "guards", None)
        _guard_names = ([k for k, v in _guards.__dict__.items() if v is True]
                        if _guards is not None and hasattr(_guards, "__dict__") else [])
        items.append(PatchPlanItem(
            surface_id=getattr(s, "id", getattr(s, "stable_id", "")),
            finding=f"{s.capability} at {s.file_path}:{getattr(s, 'line_start', 0)} verdict={s.verdict}",
            severity=getattr(s, "risk_level", getattr(s, "severity", "")),
            why=f"live-capable={getattr(s, 'live_capable', 'unknown')}; guards={_guard_names}",
            required_control=recommended_control(s.capability),
            suggested_file=s.file_path,
            suggested_test=_suggested_test(s.capability),
            human_approval_required=True,
            block_live_promotion=block,
            capability=s.capability,
            verdict=s.verdict,
            fix_group_id=_gid,
            control_point=_cp,
            fix_class=actionability(s.verdict)))
    return items


def _row_get(row, name, default=None):
    """Read a field off a PatchPlanItem OR its dict form (group_plan accepts either)."""
    if isinstance(row, dict):
        return row.get(name, default)
    return getattr(row, name, default)


def _row_location(row) -> str:
    """`file:line` for a plan row, from either the object or dict form."""
    f = _row_get(row, "suggested_file", "")
    finding = _row_get(row, "finding", "") or ""
    ln = ""
    if " at " in finding and ":" in finding:
        try:
            ln = finding.split(" at ", 1)[1].split(" verdict=")[0].rsplit(":", 1)[1]
        except Exception:
            ln = ""
    return f"{f}:{ln}" if ln else f


def group_plan(items):
    """DE-NOISE: collapse the FULL patch-plan inventory into ONE group per (control point × actionability
    class). The inventory is never mutated — each group just POINTS at the rows that close under its one fix.

    Returns a list of group dicts (most-urgent / highest-leverage first), each:
      fix_group_id, control_point, capability, fix_class, control (the one fix), suggested_test (the proof),
      count (sites this one fix closes), block_count, severity, leverage (= count × severity for actionable
      groups, 0 for informational), locations (every file:line in the group), block_live_promotion.

    Grouping is GROUPING ONLY — no row is dropped and two distinct capabilities are never merged (each
    capability has its own control point). `sum(g['count'])` therefore always equals `len(items)`."""
    groups = {}
    for row in items:
        cap = _row_get(row, "capability")
        verdict = _row_get(row, "verdict", "")
        if cap is None:  # tolerate legacy rows: recover capability/verdict from the finding string
            finding = _row_get(row, "finding", "") or ""
            cap = finding.split(" at ", 1)[0] if " at " in finding else finding
            if "verdict=" in finding:
                verdict = finding.split("verdict=", 1)[1].strip()
        gid = _row_get(row, "fix_group_id") or fix_group_id(cap)
        cls = _row_get(row, "fix_class") or actionability(verdict)
        key = (gid, cls)
        g = groups.get(key)
        if g is None:
            g = groups[key] = {
                "fix_group_id": gid, "capability": cap,
                "control_point": _row_get(row, "control_point") or control_point(cap)[1],
                "fix_class": cls,
                "control": (recommended_control(cap) if cls != "informational"
                            else "No gate needed — read-only surface; certify before ship (not a fix)."),
                "suggested_test": _suggested_test(cap),
                "count": 0, "block_count": 0,
                "severity": _SEVERITY.get(cap, 3),
                "locations": [],
            }
        g["count"] += 1
        if _row_get(row, "block_live_promotion"):
            g["block_count"] += 1
        g["locations"].append(_row_location(row))
    out = []
    for g in groups.values():
        # LEVERAGE = sites closed × severity. Only actionable (gate/review) groups earn leverage — an
        # informational read-only surface is never a "fix", so it can never rank into "fix these first".
        g["leverage"] = (g["count"] * g["severity"]) if g["fix_class"] in ("gate", "review") else 0
        g["block_live_promotion"] = g["block_count"] > 0
        out.append(g)
    out.sort(key=lambda g: (_CLASS_ORDER.get(g["fix_class"], 9), -g["leverage"],
                            -g["severity"], g["fix_group_id"]))
    return out


def top_fixes(groups, n: int = 5):
    """FIX THESE FIRST — the top `n` groups ranked purely by LEVERAGE (sites-closed × severity): the single
    fixes that close the most dangerous surface area. Only actionable groups (gate/review) carry leverage, so
    informational read-only and held groups are never eligible. Severity then slug break ties deterministically."""
    actionable = [g for g in groups if g["leverage"] > 0]
    ranked = sorted(actionable, key=lambda g: (-g["leverage"], -g["severity"], g["fix_group_id"]))
    return ranked[:n]
