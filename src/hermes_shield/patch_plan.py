"""Patch-plan generator + remediation dictionary. Read-only: this module PLANS a fix — it never writes
one. It maps a dangerous action-surface to a fix-at-source control, keyed on the REAL capability
vocabulary (code_exec, subprocess_exec, deserialize, ssti, secret_exfil, tool_invoke, external_write,
file_delete, and the mutation caps) — NOT on any product-internal lane names.

The scanner suggests; a human (or the paid repairer, under a human gate) applies. Nothing here is
"auto-fix", and install-liability surfaces get wiring-time guidance, never "fix this vulnerability".
"""
from __future__ import annotations
from .models import PatchPlanItem

# Fix-at-source remediation, keyed on the real dangerous-capability vocabulary. Customer-facing prose:
# concrete, actionable, no product-internal jargon.
_REMEDIATION = {
    "code_exec": "Replace eval/exec with ast.literal_eval or a sandboxed evaluator; if dynamic code is "
                 "genuinely required, allowlist the inputs and human-gate the call.",
    "subprocess_exec": "Run with shell=False and an argument allowlist; never interpolate model or user "
                       "output into the command string.",
    "deserialize": "Use yaml.safe_load / JSON instead of pickle; never unpickle untrusted bytes.",
    "ssti": "Enable autoescape and use a sandboxed template environment; never render model output as a "
            "template.",
    "secret_exfil": "Put an egress allowlist in front of outbound calls and scope secrets to the env that "
                    "needs them; block outbound traffic to non-allowlisted hosts.",
    "tool_invoke": "Put a final-action gate plus human approval on the tool dispatcher before any tool "
                   "call fires.",
    "external_write": "Gate outbound writes behind a destination allowlist plus human approval; never send "
                      "to a host derived from untrusted input.",
    "file_write": "Confine writes to an allowlisted directory, canonicalise the path and reject traversal; "
                  "never write to a path built from untrusted input.",
    "file_delete": "Confine deletes to an allowlisted directory, canonicalise the path and require an "
                   "explicit confirmation; never delete a path built from untrusted input.",
    "publish_write": "Put a human-approval gate before any publish/post action and log the payload for "
                     "review.",
    "queue_mutation": "Require claim-before-write and an approval-hash gate before mutating the queue.",
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
        if s.verdict in ("PROTECTED_FULL_PATH", "STATIC_PROOF_ONLY", "PROVIDER_SCOPE",
                         "PROTECTED_TEXT_PATH_ONLY", "PASS_WITH_RESIDUAL_RISK"):
            continue
        block = s.verdict in ("BLOCK_LIVE_PROMOTION", "GUARD_LOST", "UNGUARDED_CRITICAL_LIVE_SINK")
        items.append(PatchPlanItem(
            surface_id=s.id,
            finding=f"{s.capability} at {s.file_path}:{s.line_start} verdict={s.verdict}",
            severity=s.risk_level,
            why=f"live-capable={s.live_capable}; guards={[k for k,v in s.guards.__dict__.items() if v is True]}",
            required_control=recommended_control(s.capability),
            suggested_file=s.file_path,
            suggested_test=_suggested_test(s.capability),
            human_approval_required=True,
            block_live_promotion=block))
    return items
