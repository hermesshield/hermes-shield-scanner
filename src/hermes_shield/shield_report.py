#!/usr/bin/env python3
"""
Hermes Shield — human-readable report + repo CLI (Testable-Product v0.1).

Runs the read-only scanner on ANY repo path and emits a plain-Markdown report a non-engineer (or a
CISO's auditor) can read: how many dangerous actions, how many have a control, which have NONE, and
which gates look fake. This is the customer-facing artifact (the JSON scan stays for machines).

Honest by construction: it never says "protected" or "contained" — it reports control COVERAGE and
flags what a human must verify. The deterministic core is read-only against the target: it never modifies
the target repo and reports are written only under the operator's output dir (never the target). Optional
tiers have documented side effects: --ai forwards selected in-root code text to your local `claude` CLI;
--deps fetches the repo's own pinned packages.

Usage:  PYTHONPATH=.:ops python3 -m hermes_shield.shield_report --repo /path/to/repo
"""
from __future__ import annotations
import argparse
import sys
from collections import Counter
from pathlib import Path

from . import scan_hermes as SH
from . import patterns as PAT
from . import install_report as IR

_CRIT = set(getattr(PAT, "CRITICAL_CAPS", set())) | {
    "post", "reply", "comment", "like", "dm", "email_send", "telegram_send",
    "browser_click", "browser_type", "browser_submit", "computer_use",
    "queue_mutation", "db_mutation", "cron_mutation", "env_mutation",
    "dashboard_mutation", "approval_mutation"}


# S8.88 — verdict -> customer-facing category, refreshed to the CURRENT pipeline vocabulary. The old map
# keyed on the stale BLOCK_LIVE_PROMOTION / EXPECTED_GUARD_UNPROVEN only and MISSED the primary live-critical
# verdict guard_attribution now emits (UNGUARDED_CRITICAL_LIVE_SINK), plus EXPECTED_GUARD_MISSING and the
# guard-integrity fail-open verdicts — so real no-gate findings were silently bucketed OTHER and dropped.
_NO_GATE = {"UNGUARDED_CRITICAL_LIVE_SINK", "EXPECTED_GUARD_MISSING", "GUARD_LOST", "BLOCK_LIVE_PROMOTION"}
_FAKE_GATE = {"GUARD_INTEGRITY_SUSPECT", "GUARD_NOOP_CONFIRMED", "GUARD_FAIL_OPEN_SUSPECT"}
_UNPROVEN = {"CALLER_GUARDED_NOT_PROVEN", "NEEDS_CALL_GRAPH", "NEEDS_ENTRYPOINT_CONFIG",
             "NEEDS_ENTRYPOINT_REVIEW", "EXPECTED_GUARD_UNPROVEN", "GUARD_DEF_UNRESOLVED",
             "GUARD_BLOCK_SHAPED_UNVERIFIED"}

# Fix-plan scope (HARD): a generated suggestion is only ever surfaced for a CONFIRMED no-control (NO_GATE)
# or fake-gate (FAKE_GATE) finding. UNPROVEN / GATE_UNVERIFIED are excluded on purpose — we never tell
# anyone to "fix" code that may already be protected or whose reachability we could not prove.
_FIX_CATS = ("NO_GATE", "FAKE_GATE")
_FIX_STATUS = "PLANNED — not applied"


def _sink_ln(s) -> int:
    """Cite the SINK line (the dangerous call), matching hermes_shield_report.json's `line`. line_start is
    the enclosing def line — citing it points a reader at `def shell_tool(` not the `subprocess.run(` call.
    Falls back to line_start only when the scanner recorded no distinct sink line."""
    return getattr(s, "sink_line", 0) or getattr(s, "line_start", 0)


def _category(s) -> str:
    v, proven = s.verdict, s.guard_proof.get("status") == "proven"
    if v in _FAKE_GATE:
        return "FAKE_GATE"          # a control is present but is a demonstrable no-op / fail-open
    if proven or v == "PROTECTED_BY_REVIEWED_ENTRYPOINT":
        return "GATE_UNVERIFIED"    # control present; polarity/reachability not verified (review)
    if v in _NO_GATE:
        return "NO_GATE"            # live-capable action with no proven/reviewed control
    if v in _UNPROVEN:
        return "UNPROVEN"           # a control may exist but we can't prove it reaches this action
    return "OTHER"


def _report_model(scan, repo_name: str) -> dict:
    """Structured report model (shared by every output format so they can never disagree)."""
    prod = [s for s in scan["surfaces"] if s.context == "prod" and s.capability in _CRIT]
    seen, rows = set(), []
    for s in prod:
        k = (s.file_path, s.symbol, s.capability)
        if k in seen:
            continue
        seen.add(k)
        rows.append((s, _category(s)))
    # DETERMINISTIC HEADLINE = STATIC ONLY. static_rows was computed but never used — wire it now so the
    # customer-facing counts (total / gated / no_gate / fake / coverage_pct), the rendered category
    # sections and the fix plan are built ONLY from deterministic surfaces. AI-suspected surfaces (model
    # GUESSES, detection_source != "static") are advisory and flow ONLY through ai_rows into the dedicated
    # "AI-suspected — needs review" section. On an AI-off scan static_rows == rows (byte-identical).
    static_rows = [(s, c) for s, c in rows if getattr(s, "detection_source", "static") == "static"]
    cats = Counter(c for _, c in static_rows)
    total = len(static_rows)
    gated = cats["GATE_UNVERIFIED"]
    no_gate = cats["NO_GATE"] + cats["UNPROVEN"]
    fake = cats["FAKE_GATE"]
    ai_rows = [s for s in scan["surfaces"]
               if s.context == "prod" and getattr(s, "detection_source", "static") != "static"]
    # REVIEW-MANUALLY rows (count-reconciliation fix): a prod, STATIC surface whose capability is NOT in the
    # critical set (e.g. dynamic_dispatch, verdict REVIEW) was silently dropped from every rendered section
    # while still counted in the HTML "N mapped" headline — headline != body. Capture it here, deduped the
    # same way, so it lands in a visible "mapped — review manually" section and the counts reconcile.
    review_seen, review_rows = set(), []
    for s in scan["surfaces"]:
        if s.context != "prod" or getattr(s, "detection_source", "static") != "static":
            continue
        if s.capability in _CRIT:
            continue
        k = (s.file_path, s.symbol, s.capability)
        if k in review_seen:
            continue
        review_seen.add(k)
        review_rows.append(s)
    by_cap = Counter(s.capability for s, _ in static_rows)
    # MAPPED = every distinct deterministic (prod+static) surface the body renders: critical rows + review-
    # manually rows. This is the ONE headline number the HTML "N mapped" and the MD top-line both use, so
    # they can never disagree and nothing mapped is silently dropped. AI-suspected surfaces are advisory and
    # counted separately (never folded into this deterministic total).
    mapped = total + len(review_rows)
    return {
        "repo": repo_name, "files_scanned": scan["files_scanned"],
        "total": total, "gated": gated, "no_gate": no_gate, "fake": fake,
        "mapped": mapped, "review_rows": review_rows,
        "coverage_pct": (100 * gated // total) if total else 0,
        "by_capability": dict(by_cap.most_common()),
        "rows": static_rows, "ai_rows": ai_rows,
        "ai_counts": scan.get("ai_tier_counts", {}),
    }


def _fix_plan_rows(rows, scan=None):
    """Build the GENERATED fix plan from categorised report rows [(surface, category)].

    HARD SCOPE: only NO_GATE (no proven/reviewed control) and FAKE_GATE (control present but a demonstrable
    no-op / fail-open) findings get a suggestion — see _FIX_CATS. UNPROVEN / GATE_UNVERIFIED are excluded on
    purpose.

    ONE TIER PER FINDING (P0.1), derived from the SAME shared predicates (install_report) that the banner,
    the "Reachable in-repo" red table and the amber "Reachable actions" band use — NOT a bare verdict test.
    This is the whole point: a bare `verdict == UNGUARDED_CRITICAL_LIVE_SINK` test does NOT honour the
    RED-vs-AMBER capability partition, so an AMBER social action (post/reply/like) carrying that verdict was
    wrongly shown in the RED "fix first — reachable now" table while the deterministic banner + red reachable
    table correctly called it amber — a same-file:line verdict-vs-fix-plan contradiction. The three tiers
    PARTITION every finding exactly as the report does:
      - red   (IR.is_non_gated_vulnerable)   -> reachable-in-repo, fix first (fix-at-source control);
      - amber (IR.is_reachable_amber_action) -> reachable action, review before you ship — reversible/social,
        lower blast-radius than the red band; still a fix-at-source control, never "fix first / reachable now";
      - else  (inert here)                   -> wiring-time — gate on install, with wiring_control() guidance.
    Because guard_attribution only stamps UNGUARDED_CRITICAL_LIVE_SINK onto CRITICAL_CAPS (== red ∪ amber
    caps), no reachable-unguarded finding is silently dropped between these tiers.
    The scanner PLANS these; it does NOT modify code (status = 'PLANNED — not applied')."""
    from . import patch_plan as _PP
    # Reachability-unknown context: an "inert here" row can only honestly be called wiring-time when the repo
    # exposes NO untrusted ingress and NO unresolved dynamic dispatch. If either is present, an RCE-class sink
    # with no traced caller is REACHABILITY-UNKNOWN, not "inert here" — never label an analysis limit inert.
    _RCE = {"code_exec", "deserialize", "subprocess_exec", "ssti"}
    _has_ingress = bool(scan and IR._repo_has_untrusted_ingress(scan))
    _has_dispatch = bool(scan and IR._repo_has_unresolved_dispatch(
        [s for s in scan.get("surfaces", []) if getattr(s, "context", "prod") == "prod"
         and getattr(s, "detection_source", "static") == "static"]))
    out = []
    for s, cat in rows:
        # AI-suspected surfaces (model GUESSES) never generate a fix-plan / Repairer-feed row. Callers pass
        # the already-static headline rows, but we exclude non-static here too (belt and braces).
        if getattr(s, "detection_source", "static") != "static":
            continue
        if cat not in _FIX_CATS:
            continue
        cap = s.capability
        if IR.is_non_gated_vulnerable(s):          # RED — reachable + unguarded, high blast-radius
            band, tier, reachable = "red", "reachable-in-repo", True
            control = _PP.recommended_control(cap)
        elif IR.is_reachable_amber_action(s):      # AMBER — reachable + unguarded, reversible/social
            band, tier, reachable = "amber", "reachable action — review before you ship", True
            control = _PP.recommended_control(cap)
        elif cap in _RCE and (getattr(s, "tainted_reachable", False) or _has_ingress or _has_dispatch):
            # REACHABILITY-UNKNOWN — could NOT be proven inert (ingress / unresolved dispatch present). Never
            # "inert here / gate on install"; verify reachability first, then apply the real fix-at-source.
            band, tier, reachable = "reach-unknown", "reachability unknown — verify, then gate", False
            control = "Reachability not proven (untrusted ingress / unresolved dispatch present) — trace from the ingress first. " + _PP.recommended_control(cap)
        else:                                      # inert here — gate at wiring time, not a fix-now item
            band, tier, reachable = "wiring", "wiring-time — gate on install", False
            control = _PP.wiring_control(cap)
        out.append({
            "file": s.file_path,
            "line": _sink_ln(s),
            "capability": cap,
            "cap_label": _CAP_LABEL.get(cap, cap),
            "reachable": reachable,
            "band": band,
            "tier": tier,
            "category": cat,
            "recommended_control": control,
            "status": _FIX_STATUS,
        })
    return out


def build_report(scan, repo_name: str, validated=None, root=None) -> str:
    """Markdown report (report #1 of the multi-report). `validated` (optional) = the PROVEN-LIVE set from
    the prove lane; when omitted (default) proven_live is 0 and the output is byte-identical to a plain
    scan. `root` = the scanned target dir, so coverage is computed against the TARGET (not the CWD)."""
    m = _report_model(scan, repo_name)
    rows = m["rows"]

    def _list(cat, limit=40):
        items = [f"- `{s.file_path}:{_sink_ln(s)}`  **{s.capability}**  ({s.symbol or 'module-scope'})"
                 for s, c in rows if c == cat]
        extra = f"\n- …and {len(items) - limit} more" if len(items) > limit else ""
        return ("\n".join(items[:limit]) + extra) if items else "- (none)"

    def _review_list(limit=40):
        items = [f"- `{s.file_path}:{_sink_ln(s)}`  **{s.capability}**  ({s.symbol or 'module-scope'})  "
                 f"_(below the critical-capability line — verify manually)_"
                 for s in m.get("review_rows", [])]
        extra = f"\n- …and {len(items) - limit} more" if len(items) > limit else ""
        return ("\n".join(items[:limit]) + extra) if items else "- (none)"

    # S8.88 — carry the two-number honesty model (install-liability + proven-live) from install_report so
    # the customer report cannot over-claim. These caveats are MANDATORY and appear verbatim in every scan.
    try:
        _ir = IR.build_report(Path(root) if root else Path("."), scan, validated)
        _install_liab = _ir.get("install_liability_rce", 0)
        _install_band = _ir.get("install_liability_rating", {}).get("band", "Low")
        _proven = _ir.get("proven_live_poc", 0)
        _reach_unknown = _ir.get("reachability_unknown", 0)
    except Exception:
        _install_liab, _install_band, _proven, _reach_unknown = 0, "Low", 0, 0

    # Fix plan — generated, not applied. NO_GATE + FAKE_GATE only (see _fix_plan_rows scope).
    _fixrows = _fix_plan_rows(rows, scan)

    def _fix_md(limit=30):
        if not _fixrows:
            return "- (none — no no-control / fake-gate findings to plan)"
        lines = []
        for it in _fixrows[:limit]:
            lines.append(
                f"- `{it['file']}:{it['line']}` · **{it['cap_label']}** · tier: {it['tier']} · "
                f"status: **{it['status']}**\n    - Recommended control: {it['recommended_control']}")
        if len(_fixrows) > limit:
            lines.append(f"- …and {len(_fixrows) - limit} more in `hermes_patch_plan.json`")
        return "\n".join(lines)

    fix_md = _fix_md()

    disc = "\n".join(f"- **{cap}** — {n}" for cap, n in m["by_capability"].items()) or "- (none)"
    ai = m["ai_rows"]
    ai_block = ("\n".join(
        f"- `{s.file_path}:{_sink_ln(s)}`  **{s.capability}**  _(model-proposed, AST-verified — VERIFY)_"
        for s in ai[:40]) or "- (none — AI tier off or nothing found)")
    # AI tier health: a broken agent backend is SHOWN, never silent — "(none)" must never masquerade as
    # "the AI tier ran and found nothing" when the backend never launched.
    _aic = m.get("ai_counts") or {}
    _ai_fail = _aic.get("ai_failure") or _aic.get("ai_error")
    if _ai_fail or _aic.get("ai_status") == "failed":
        ai_block = (f"> **AI tier: FAILED — {_ai_fail or 'agent backend error'}.** No AI findings were "
                    f"produced; the deterministic results above are unaffected.\n\n" + ai_block)

    out = f"""# Hermes Shield — Discovery & Coverage Report
**Repo:** `{m['repo']}`  ·  **Files scanned:** {m['files_scanned']}

> Read-only static analysis. Maps to OWASP LLM06 (Excessive Agency). It reports the dangerous ACTIONS an
> AI agent could be tricked into, and whether a control is *written* before each — it does NOT prove a
> control runs/blocks/is deployed. Findings marked _AI_ are model-proposed and MUST be human-verified.

## Summary
- **Action-surfaces mapped (total):** {m.get('mapped', m['total'])}  (matches the HTML headline; every one appears below)
- **Dangerous action-surfaces (critical capability):** {m['total']}
- **Below the critical line — review manually:** {len(m.get('review_rows', []))}  (dynamic dispatch / REVIEW verdicts — mapped, not dropped)
- **Have a control (present, unverified):** {m['gated']}  ({m['coverage_pct']}% coverage)
- **NO control found:** {m['no_gate']}  (each fix-plan item below carries its real tier — fix-first, reachable-action review, or wiring-time)
- **Gate looks FAKE (no-op / fail-open):** {m['fake']}
- **AI-suspected surfaces (model-proposed, review):** {len(ai)}
- **Reachability UNKNOWN (verify manually):** {_reach_unknown}  (RCE-class, could not be proven inert — untrusted ingress / unresolved dispatch present)
- **Install-liability (RCE-class inherited, proven inert):** {_install_liab}  ·  inherited rating: {_install_band}
- **Proven-live (PoC-confirmed) critical:** {_proven}

## Honest scope — read this before you act
- **Install-liability = inert here, live on install.** The {_install_liab} inherited RCE-class surfaces are
  proven NOT reachable from this repo's own entrypoints today AND sit behind no untrusted ingress/unresolved
  dispatch — they are inert here, live on install: a live attack surface the moment a downloader wires
  untrusted input into them. This is NOT a "vulnerability" in this repo and is never reported as one.
- **Reachability UNKNOWN = {_reach_unknown}.** {"No sink is in this state" if not _reach_unknown else f"{_reach_unknown} RCE-class sink(s) could NOT be proven inert"} — an untrusted
  ingress (e.g. an HTTP route) and/or dynamic dispatch the tracer could not resolve is present, so a request
  may reach them. This is **reachability not proven — verify manually**, never "not reachable". An analysis
  limit is not a safety fact.
- **Proven-live = {_proven}.** {"No critical finding here is PoC-confirmed" if not _proven else f"{_proven} critical finding(s) PoC-confirmed"} — proven_live_poc=0 means
  **not demonstrated**, never "secure". A zero is the absence of a proof, not a clean bill of health.

## Fix plan — generated, not applied
> Suggested fix-at-source controls for the confirmed no-control / fake-gate findings. **The scanner plans
> these; it does not modify your code.** The Hermes Shield Repairer — the paid tier, in early access — is
> being built to apply these under a human gate — never auto-fix. Until then each item is guidance you
> apply and review.
{fix_md}

## Discovered attack surfaces by capability
{disc}

## 1. Actions with NO control — start here
{_list('NO_GATE')}

## 2. Gates that look FAKE — verify manually now
{_list('FAKE_GATE')}

## 3. Controls we could not prove reach the action
{_list('UNPROVEN')}

## 4. Controls present but UNVERIFIED (polarity/reachability not machine-checked)
{_list('GATE_UNVERIFIED')}

## 5. Mapped — review manually (below the critical-capability line)
> Surfaces we mapped but that sit below the critical-capability line — dynamic dispatch, REVIEW verdicts.
> They are NOT dropped from the count (the headline total includes them); resolve the dispatch target and
> verify manually. Deterministic (not AI-suspected).
{_review_list()}

## 6. AI-suspected surfaces — model-proposed, human MUST verify
> Found by the AI-assist tier (any coding agent) on files the static rules missed, each AST-verified as a
> real call. NOT counted in the coverage number above. Treat as leads to review, not confirmed findings.
{ai_block}

---
*Honest-scope: "coverage / gap-finder", not a containment proof. Blind spots (dynamic dispatch, runtime
config, cross-process store, non-Python) are not covered and are documented in the threat model. Coverage
is only accurate once YOUR control functions are declared in the guard config.*
"""
    return out


import html as _html

try:  # embedded Sunset brand fonts — cosmetic only, never required
    from .brand_fonts import font_face_css as _font_face_css
except Exception:  # pragma: no cover
    def _font_face_css() -> str:
        return ""

_CAP_LABEL = {"code_exec": "code execution", "subprocess_exec": "shell / subprocess",
              "deserialize": "unsafe deserialize", "ssti": "template injection",
              "tool_invoke": "LLM tool-invoke", "external_write": "outbound write",
              "file_delete": "file delete", "secret_exfil": "secret exfiltration",
              "db_mutation": "database write", "dashboard_mutation": "dashboard write",
              "publish_write": "publish / post", "browser_submit": "browser submit"}


def build_html(scan, repo_name: str, root=None, validated=None) -> str:
    """Self-contained, branded HTML report (report #2) — the customer/exec-facing view. Dark sunset-terminal
    skin (matches hermesshield.ai), antivirus-style status banner first, and leads with the SAME headline
    numbers (reachable / install-liability / OWASP) as the scan — presentation only, the data is untouched.
    `validated` (optional) = the PROVEN-LIVE set from the prove lane; omitted (default) => proven_live 0,
    byte-identical to a plain scan."""
    from datetime import date as _dt_date
    try:
        from .models import SCANNER_VERSION as _ver
    except Exception:  # pragma: no cover
        _ver = "unknown"
    m = _report_model(scan, repo_name)
    try:
        _ir = IR.build_report(Path(root) if root else Path("."), scan, validated)
    except Exception:
        _ir = {}
    reachable = _ir.get("non_gated_vulnerable", m["no_gate"])
    install_liab = _ir.get("install_liability_rce", 0)
    amber_actions = _ir.get("reachable_amber_actions", 0)
    fixed_dest_reviews = _ir.get("reachable_fixed_dest_review", 0)
    reach_unknown = _ir.get("reachability_unknown", 0)
    reach_unknown_reason = _ir.get("reachability_unknown_reason", {}) or {}
    proven = _ir.get("proven_live_poc", 0)
    band = (_ir.get("install_liability_rating") or {}).get("band", "Low")
    overall = _ir.get("overall_rating", "None (no proven-live)")
    # LAUNCH REFRAME (presentation only): the verdict band shows a plain-English display string; the RAW
    # OWASP rating string moves into the small caveat line, verbatim. Never rendered as "all-clear" green.
    overall_display = "No proven-live exploit path" if str(overall).startswith("None") else overall
    # HEADLINE "N mapped" = the deterministic mapped total from the shared report model (critical rows +
    # review-manually rows), so it EQUALS what the body renders and reconciles with the MD top-line.
    total_surfaces = m.get("mapped", len([s for s in scan["surfaces"] if s.context == "prod"]))
    files = scan["files_scanned"]
    # Real coverage the scan computed (scanned source files / scannable source after SKIP_DIRS) — NEVER a
    # hardcoded "100%". A sub-100 figure is honest about unsupported languages / files we did not read.
    cov = _ir.get("coverage_pct", None)
    cov_note = f"{cov}% of scannable source" if cov is not None else "coverage: see report"

    def _pl(n, singular, plural):
        return singular if n == 1 else plural

    # ---- THE STATUS BANNER (antivirus-style verdict, first thing on the page). State is encoded in FORM:
    # colour + icon + plain words. One rule, three states — RED (reachable now / proven-live), AMBER
    # (install-liability only), CALM BLUE (neither). Blue is "no live threat PROVEN", never "secure".
    # CANONICAL verdict — shared with the CLI (install_report.verdict_band) so the HTML banner and the CLI
    # can never disagree. This chooses the band/icon/head; the human-facing sub-copy is built per-band below.
    _vb = IR.verdict_band(reachable, proven, install_liab, amber_actions, fixed_dest_reviews, reach_unknown,
                          nothing_scanned=_ir.get("nothing_scanned", False))
    b_cls, b_icon, b_head = _vb["code"], _vb["icon"], _vb["head"]
    # Reason string for the reachability-unknown band — why we could not prove inert (never a safety claim).
    _ru_why = " and ".join(
        w for w, on in (("an untrusted ingress (e.g. an HTTP route)", reach_unknown_reason.get("untrusted_ingress")),
                        ("dynamic dispatch we could not resolve", reach_unknown_reason.get("unresolved_dispatch"))) if on
    ) or "reachability could not be proven"
    if proven > 0 or reachable > 0:
        n = reachable if reachable else proven
        b_sub = (f"<b>{n} dangerous {_pl(n, 'action', 'actions')}</b> an attacker can reach in this code "
                 f"right now, with nothing in the way. {_pl(n, 'Fix this first.', 'Fix these first.')}")
        if proven:
            b_sub += (f" <b>{proven}</b> {_pl(proven, 'is', 'are')} proven-live — we demonstrated a real "
                      f"attack path.")
    elif amber_actions > 0 or fixed_dest_reviews > 0:
        if amber_actions > 0:
            b_sub = (f"<b>{amber_actions} reversible {_pl(amber_actions, 'action', 'actions')}</b> "
                     f"(post, reply, like) an attacker can reach here with nothing in the way — lower "
                     f"blast-radius than the red band, but review before you ship.")
            if fixed_dest_reviews:
                b_sub += (f" Plus <b>{fixed_dest_reviews}</b> fixed-destination "
                          f"{_pl(fixed_dest_reviews, 'send', 'sends')} (config/constant destination) reachable "
                          f"with tainted content — not exfil, but review.")
        else:
            b_sub = (f"<b>{fixed_dest_reviews} fixed-destination {_pl(fixed_dest_reviews, 'send', 'sends')}</b> "
                     f"(a messaging/external send to a proven config/constant destination) an attacker can "
                     f"reach here with tainted content — not exfil (the destination can't be steered), but "
                     f"review before you ship.")
        if install_liab:
            b_sub += (f" Plus <b>{install_liab}</b> install-liability {_pl(install_liab, 'item', 'items')} "
                      f"that {_pl(install_liab, 'goes', 'go')} live on install.")
    elif reach_unknown > 0:
        # REACHABILITY UNKNOWN — we could NOT prove these inert. Never "nothing is reachable" / "inert here".
        b_sub = (f"<b>{reach_unknown} RCE-class {_pl(reach_unknown, 'sink', 'sinks')}</b> we could <b>not prove "
                 f"inert</b> — the repo has {_ru_why}, so a request may reach {_pl(reach_unknown, 'it', 'them')} "
                 f"along a path we could not trace. <b>Reachability not proven — verify manually.</b> This is not "
                 f"a safety claim.")
        if install_liab:
            b_sub += (f" Plus <b>{install_liab}</b> install-liability {_pl(install_liab, 'item', 'items')} "
                      f"that {_pl(install_liab, 'goes', 'go')} live on install.")
    elif install_liab > 0:
        b_sub = (f"<b>{install_liab} dangerous {_pl(install_liab, 'capability is', 'capabilities are')}</b> "
                 f"inert here but {_pl(install_liab, 'goes', 'go')} live the moment this code is installed "
                 f"and fed untrusted input.")
    else:
        b_sub = ("We mapped everything this code can do and found no attacker-reachable action with no "
                 "control. This is not a guarantee your code is secure — see the map below.")

    # ---- "In plain words" strip — three point-first lines for a non-technical reader.
    pw_found = (f"<b>{total_surfaces:,} {_pl(total_surfaces, 'place', 'places')} this code can act</b> — "
                f"mapped across {files:,} {_pl(files, 'file', 'files')}, read-only, on this machine.")
    if proven > 0 or reachable > 0:
        n = reachable if reachable else proven
        pw_urgent = (f"<b>{n} {_pl(n, 'has', 'have')} no control in the way</b> — a hijacked agent could "
                     f"use {_pl(n, 'it', 'them')} today.")
        pw_do = ("<b>Work the fix plan below, top to bottom</b> — the items marked "
                 "“reachable now — fix first” come first.")
    elif amber_actions > 0 or fixed_dest_reviews > 0:
        if amber_actions > 0:
            pw_urgent = (f"<b>{amber_actions} reversible {_pl(amber_actions, 'action is', 'actions are')} "
                         f"reachable with no control</b> — a hijacked agent could post, reply or like as you "
                         f"today. Lower blast-radius than the red band, but not nothing.")
            if fixed_dest_reviews:
                pw_urgent += (f" Plus <b>{fixed_dest_reviews} fixed-destination "
                              f"{_pl(fixed_dest_reviews, 'send', 'sends')}</b> reachable with tainted content.")
        else:
            pw_urgent = (f"<b>{fixed_dest_reviews} fixed-destination {_pl(fixed_dest_reviews, 'send is', 'sends are')} "
                         f"reachable with no control</b> — a hijacked agent could push tainted content through a "
                         f"messaging/external send today. The destination is fixed (not exfil), but not nothing.")
        pw_do = ("<b>Review the “reachable actions” band below</b> and gate each one before you ship.")
    elif reach_unknown > 0:
        pw_urgent = (f"<b>Reachability not proven for {reach_unknown} RCE-class "
                     f"{_pl(reach_unknown, 'sink', 'sinks')}</b> — the repo has {_ru_why}, so we cannot say "
                     f"{_pl(reach_unknown, 'it is', 'they are')} unreachable. Verify manually; do not treat "
                     f"this as safe.")
        pw_do = ("<b>Trace each “reachability unknown” item from the ingress</b> and confirm with a PoC "
                 "before you rely on it being inert.")
    elif install_liab > 0:
        pw_urgent = (f"<b>Nothing was PROVEN reachable</b> — and {install_liab} install-liability "
                     f"{_pl(install_liab, 'item', 'items')} (dangerous capability that's harmless here but "
                     f"live once installed) {_pl(install_liab, 'needs', 'need')} a gate before shipping.")
        pw_do = ("<b>Gate every item marked “wiring-time”</b> before this code is installed or fed "
                 "untrusted input.")
    else:
        pw_urgent = ("<b>Nothing urgent was found</b> — no attacker-reachable action without a control, "
                     "and no install-liability items.")
        pw_do = ("<b>Keep the map</b> — re-scan whenever the code gains a new way to act, and read the "
                 "honest-scope note at the bottom.")

    _RCE = {"code_exec", "deserialize", "subprocess_exec", "ssti"}
    # STATIC ONLY: the banner (above) and the "Reachable in-repo" + install-liability tables (below) are
    # deterministic — a model GUESS must never appear here. With the writer-side fix an AI surface never
    # carries UNGUARDED_CRITICAL_LIVE_SINK, but we filter defensively (belt and braces) so it can never
    # drive the red banner or the reachable table even if a future path re-stamps its verdict.
    def _is_static(s):
        return getattr(s, "detection_source", "static") == "static"
    # The reachable-unguarded surfaces PARTITION into the red-driving set (is_non_gated_vulnerable: RCE-class
    # + high-impact actions) and the amber action band (is_reachable_amber_action: reversible/social). The
    # union is exactly every prod+static UNGUARDED_CRITICAL_LIVE_SINK — nothing is silently dropped to BLUE.
    live = [s for s in scan["surfaces"] if IR.is_non_gated_vulnerable(s)]
    amber_live = [s for s in scan["surfaces"] if IR.is_reachable_amber_action(s)]
    # everything reachable-unguarded (both bands) — the id set the install-liability table must exclude
    live_ids = {id(s) for s in scan["surfaces"]
                if getattr(s, "verdict", "") == "UNGUARDED_CRITICAL_LIVE_SINK" and _is_static(s)}
    # RCE-class, not reachable-red — the install-liability CANDIDATES. Split the SAME way install_report
    # does: a candidate we could NOT prove inert (untrusted ingress and/or unresolved dispatch present, or
    # the sink is itself tainted_reachable) is REACHABILITY_UNKNOWN — verify manually — NOT install-liability.
    il_all = [s for s in scan["surfaces"] if s.context == "prod" and s.capability in _RCE
              and _is_static(s) and id(s) not in live_ids]
    _has_ingress = IR._repo_has_untrusted_ingress(scan)
    _has_dispatch = IR._repo_has_unresolved_dispatch(
        [s for s in scan["surfaces"] if s.context == "prod" and _is_static(s)])
    reach_unknown_live, il = [], []
    for s in il_all:
        if getattr(s, "tainted_reachable", False) or _has_ingress or _has_dispatch:
            reach_unknown_live.append(s)
        else:
            il.append(s)
    # REVIEW-MANUALLY surfaces (count-reconciliation): mapped prod+static surfaces below the critical line
    # (dynamic_dispatch / REVIEW verdicts) that would otherwise be silently dropped from every section.
    review_live = list(m.get("review_rows", []))

    def esc(x):
        return _html.escape(str(x))

    def rows(items, limit=30):
        out = []
        for s in items[:limit]:
            cap = _CAP_LABEL.get(s.capability, s.capability)
            out.append(f"<tr><td class=mono>{esc(s.file_path)}<span class=ln>:{_sink_ln(s)}</span></td>"
                       f"<td class=cap>{esc(cap)}</td><td class=sym>{esc(s.symbol or 'module-scope')}</td></tr>")
        if len(items) > limit:
            out.append(f"<tr><td colspan=3 class=more>…and {len(items) - limit:,} more in the full data "
                       f"(hermes_action_surface_scan.json)</td></tr>")
        return "".join(out) or "<tr><td colspan=3 class=more>(none)</td></tr>"

    # Fix plan — generated, not applied. NO_GATE + FAKE_GATE only (see _fix_plan_rows scope). Split by the
    # row's REAL band (P0.1) — the SAME red/amber/wiring partition as the banner + reachable tables, so a
    # finding tells ONE story everywhere: red -> fix first; amber -> reachable action, review before ship;
    # wiring -> gate on install. The red table therefore holds ONLY is_non_gated_vulnerable surfaces,
    # matching its "same reachable-unguarded rule as the Reachable in-repo count" claim below.
    _fixrows = _fix_plan_rows(m["rows"], scan)
    _fix_reach = [it for it in _fixrows if it["band"] == "red"]
    _fix_amber = [it for it in _fixrows if it["band"] == "amber"]
    _fix_runknown = [it for it in _fixrows if it["band"] == "reach-unknown"]
    _fix_wiring = [it for it in _fixrows if it["band"] == "wiring"]

    def fixplan_rows(items, badge, empty, limit=30):
        out = []
        for it in items[:limit]:
            out.append(
                f"<tr><td class=mono>{esc(it['file'])}<span class=ln>:{it['line']}</span></td>"
                f"<td class=cap>{esc(it['cap_label'])}</td>"
                f"<td class=tier2>{badge}</td>"
                f"<td class=ctrl>{esc(it['recommended_control'])}</td>"
                f"<td class=plan>{esc(it['status'])}</td></tr>")
        if len(items) > limit:
            out.append(f"<tr><td colspan=5 class=more>…and {len(items) - limit:,} more in the full plan "
                       f"(hermes_patch_plan.json)</td></tr>")
        return "".join(out) or f"<tr><td colspan=5 class=more>{empty}</td></tr>"

    _fixhead = ("<tr><td class=hd>Location</td><td class=hd>Capability</td><td class=hd>Tier</td>"
                "<td class=hd>Recommended control</td><td class=hd>Status</td></tr>")
    fixplan_reach_html = fixplan_rows(
        _fix_reach, "<span class='badge ff'>reachable now — fix first</span>",
        "(none — nothing reachable-unguarded to fix first)")
    # AMBER fix-plan band — reachable + unguarded REVERSIBLE/social actions (post/reply/like). Rendered as a
    # SEPARATE section so an amber action is never shown under the red "fix first — reachable now" table (the
    # verdict-vs-fix-plan contradiction this partition closes). Only shown when present.
    fixplan_amber_block = "" if not _fix_amber else (
        "<h3>Reachable actions — review before you ship "
        "<span class=c>— reversible/social (post, reply, like); lower blast-radius than fix-first</span></h3>"
        "<div class=tier>These are <b>reachable and unguarded now</b>, but reversible or social — a hijacked "
        "agent could post, reply or like as you. Lower blast-radius than the red fix-first band above; "
        "<b>review and gate each one before you ship</b> — not flagged “fix first”.</div>"
        f"<table>{_fixhead}" + fixplan_rows(
            _fix_amber, "<span class='badge rv'>reachable — review before ship</span>", "(none)")
        + "</table>")
    # REACHABILITY-UNKNOWN fix band — an RCE-class sink we could NOT prove inert (untrusted ingress /
    # unresolved dispatch present). Rendered SEPARATELY from the wiring band so it is never mislabelled
    # "inert here" — verify reachability first, then apply the real fix.
    fixplan_runknown_block = "" if not _fix_runknown else (
        "<h3>Reachability unknown — verify, then gate "
        "<span class=c>— NOT proven inert; an untrusted route/dispatch may reach these</span></h3>"
        "<div class=tier>These RCE-class sinks are <b>not proven inert</b> — an untrusted ingress and/or "
        "unresolved dispatch is present. <b>Trace each from the ingress and confirm with a PoC</b> before "
        "treating it as install-liability; then apply the fix-at-source control.</div>"
        f"<table>{_fixhead}" + fixplan_rows(
            _fix_runknown, "<span class='badge ru'>reachability unknown — verify</span>", "(none)")
        + "</table>")
    fixplan_wiring_block = "" if not _fix_wiring else (
        "<h3>Gate on install — wiring-time <span class=c>— inert here, not a fix-now item</span></h3>"
        "<div class=tier>These are <b>not reachable in this repo today</b>, so they are never labelled "
        "“fix first”. Gate each one before untrusted input is wired to it on install.</div>"
        f"<table>{_fixhead}" + fixplan_rows(
            _fix_wiring, "<span class='badge wt'>wiring-time — gate on install</span>", "(none)")
        + "</table>")

    # capability bars
    bycap = m["by_capability"]
    maxc = max(bycap.values()) if bycap else 1
    bars = "".join(
        f"<div class=bar><span class=bl>{esc(_CAP_LABEL.get(c, c))}</span>"
        f"<span class=track><span class=fill style='width:{max(3, 100 * n // maxc)}%'></span></span>"
        f"<span class=bn>{n:,}</span></div>" for c, n in bycap.items())

    # ---- AMBER band: reachable + unguarded REVERSIBLE/social actions (post/reply/like ...). A clear NEW
    # band — never folded into the red table, never silently dropped to BLUE. Rendered only when present.
    amber_band_html = "" if not amber_live else (
        "<h2>▸ Reachable actions — review "
        "<span class=c>— live now, reversible/social (post, reply, like)</span></h2>"
        "<div class=tier>An untrusted input can reach these actions with no control in the way today. They "
        "are <b>reversible or social</b> — lower blast-radius than the red “Reachable in-repo” band above, "
        "but a hijacked agent could still post, reply or like as you. <b>Review and gate each one before you "
        f"ship.</b></div><table>{rows(amber_live)}</table>")

    # ---- FIXED-DESTINATION band: messaging/external sends demoted to CONFIG_DESTINATION_WRITE_REVIEW — the
    # destination is a PROVEN fixed (config/constant) channel so it is not exfil, but the send is still
    # reachable + unguarded with tainted content. A distinct AMBER band — never folded into red, NEVER
    # silently dropped to BLUE (the actions-firewall invariant). Rendered only when present.
    fixed_dest_live = [s for s in scan["surfaces"] if IR.is_reachable_fixed_dest_review(s)]
    fixed_dest_band_html = "" if not fixed_dest_live else (
        "<h2>▸ Fixed-destination sends — review "
        "<span class=c>— live now, config/constant destination (not exfil)</span></h2>"
        "<div class=tier>An untrusted input can reach these messaging/external sends with no control in the "
        "way today. The <b>destination is proven fixed</b> (a config value or constant), so an attacker "
        "cannot steer where the data goes — this is not exfil. But the <b>content is tainted</b> and the "
        "send is unguarded, so a hijacked agent could still push attacker-shaped content through your own "
        f"channel. <b>Review and gate each one before you ship.</b></div><table>{rows(fixed_dest_live)}</table>")

    # ---- REACHABILITY-UNKNOWN band: RCE-class sinks we could NOT prove inert. NEVER print an analysis limit
    # as a safety fact — an untrusted ingress and/or unresolved dynamic dispatch is present, so these are
    # "reachability not proven — verify manually", visually SEPARATE from install-liability and never "inert
    # here / not reachable". Rendered only when present.
    reach_unknown_html = "" if not reach_unknown_live else (
        "<h2 class=ruflag>▸ Reachability unknown — verify manually "
        "<span class=c>— NOT proven inert; an untrusted route/dispatch may reach these</span></h2>"
        f"<div class=tier>These are RCE-class sinks (an attacker running their own code on your machine) we "
        f"<b>could not prove inert</b>: the repo has {esc(_ru_why)}, so an untrusted request may reach them "
        f"along a dispatch path the static tracer could not follow. This is <b>reachability not proven — "
        f"verify manually</b>, NOT “inert here”. A sink reachable from an untrusted route is live here, not "
        f"install-liability. <b>Trace each one from the ingress and confirm with a PoC.</b></div>"
        f"<table>{rows(reach_unknown_live)}</table>")

    # ---- MAPPED — REVIEW MANUALLY: prod surfaces below the critical-capability line (dynamic_dispatch,
    # REVIEW verdicts). Counted in the "N mapped" headline, so they MUST be visible here — never silently
    # dropped. Deterministic (not AI-suspected). Rendered only when present.
    review_html = "" if not review_live else (
        "<h2>▸ Mapped — review manually "
        "<span class=c>— below the critical-capability line (dynamic dispatch / REVIEW)</span></h2>"
        "<div class=tier>Surfaces we mapped but that sit below the critical-capability line — e.g. dynamic "
        "dispatch or a REVIEW verdict. They are <b>counted in the mapped total above</b>, not dropped. "
        "Resolve the dispatch target and <b>verify manually</b>.</div>"
        f"<table>{rows(review_live)}</table>")

    # ---- AI-SUSPECTED — advisory, OUTSIDE the deterministic verdict/counts. Mirrors the MD section. These
    # are model-proposed (any coding agent), AST-verified as real calls, and NEVER touch the banner, the
    # mapped total or any deterministic band. Rendered only when the AI tier produced surfaces.
    ai_live = m.get("ai_rows", [])
    # Always rendered (mirrors the MD section 6), even when empty, so the HTML and MD stay at parity and the
    # segregation is explicit. Advisory only — OUTSIDE the deterministic verdict/counts, never in any band.
    _ai_body = (f"<table>{rows(ai_live)}</table>" if ai_live
                else "<div class=tier>(none — AI tier off or nothing found)</div>")
    ai_html = (
        "<h2 class=aiflag>▸ AI-suspected — advisory, verify "
        "<span class=c>— model-proposed, OUTSIDE the deterministic verdict &amp; counts</span></h2>"
        "<div class=tier>Found by the optional AI-assist tier on files the static rules missed, each "
        "AST-verified as a real call. <b>Not counted</b> in the mapped total, the verdict or any band above "
        "— advisory only. Treat as leads to review, <b>not confirmed findings</b>; a human must verify each "
        f"one.</div>{_ai_body}")

    band_class = {"Low": "lo", "Med": "md", "High": "hi"}.get(band, "lo")
    fonts = _font_face_css()
    scan_date = _dt_date.today().isoformat()

    return f"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Hermes Shield — {esc(repo_name)} · Excessive-Agency Scan</title>
<style>
{fonts}
/* Sunset-terminal skin — the hermesshield.ai identity. Warm dark ink, blaze/heat/blue accents,
   Fraunces headlines, IBM Plex Mono labels, Instrument Sans body. Fonts are embedded (base64 woff2),
   so this report renders identically anywhere and makes NO network request when opened. */
:root{{--night:#1A1008;--panel:#241608;--panel2:#2C1B0B;--line:rgba(234,217,192,.14);
--cream:#EAD9C0;--muted:rgba(234,217,192,.68);--faint:rgba(234,217,192,.46);
--blaze:#FA7D09;--heat:#FF4301;--apricot:#FFC98F;--blue:#2b7de2;--sky:#52bdff;
--serif:"Fraunces",Georgia,serif;--sans:"Instrument Sans",system-ui,sans-serif;
--mono:"IBM Plex Mono",ui-monospace,Menlo,Consolas,monospace}}
*{{box-sizing:border-box}}
body{{margin:0;color:var(--cream);font-family:var(--sans);font-size:16px;line-height:1.6;
background:radial-gradient(1100px 520px at 72% -12%,rgba(250,125,9,.13),transparent 60%),var(--night);
-webkit-font-smoothing:antialiased}}
.wrap{{max-width:1040px;margin:0 auto;padding:44px 24px 88px}}
.mast{{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;
border-bottom:1px solid var(--line);padding-bottom:20px}}
.brand{{font-family:var(--mono);font-weight:600;letter-spacing:.18em;color:var(--blaze);font-size:15px}}
.brand .sh{{color:var(--cream)}}
.mast .sub{{font-family:var(--mono);color:var(--muted);font-size:11.5px;letter-spacing:.08em;text-transform:uppercase}}
/* ---- the status banner: the dominant visual moment, verdict-first ---- */
.banner{{display:flex;gap:22px;align-items:flex-start;border-radius:20px;padding:30px 32px;
margin:32px 0 0;border:1px solid}}
.banner .icon{{font-size:42px;line-height:1;margin-top:4px}}
.banner .k{{font-family:var(--mono);font-size:11px;letter-spacing:.16em;text-transform:uppercase;
color:var(--faint);margin-bottom:8px}}
.banner .head{{font-family:var(--serif);font-weight:600;font-size:clamp(1.8rem,3.8vw,2.5rem);
line-height:1.08;letter-spacing:-.01em}}
.banner .bsub{{font-size:16.5px;margin-top:12px;line-height:1.6;color:var(--muted);max-width:68ch}}
.banner .bsub b{{color:var(--cream)}}
.banner.red{{background:linear-gradient(135deg,rgba(255,67,1,.22),rgba(255,67,1,.05));
border-color:rgba(255,67,1,.55)}}
.banner.red .head,.banner.red .icon{{color:var(--heat)}}
.banner.amber{{background:linear-gradient(135deg,rgba(250,125,9,.2),rgba(250,125,9,.05));
border-color:rgba(250,125,9,.5)}}
.banner.amber .head,.banner.amber .icon{{color:var(--blaze)}}
.banner.blue{{background:linear-gradient(135deg,rgba(43,125,226,.22),rgba(43,125,226,.05));
border-color:rgba(82,189,255,.42)}}
.banner.blue .head,.banner.blue .icon{{color:var(--sky)}}
/* ---- in plain words ---- */
.plain{{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:14px;margin:16px 0 0}}
.pw{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px 18px;
font-size:14.5px;line-height:1.55;color:var(--muted)}}
.pw b{{color:var(--cream)}}
.pw .pk{{font-family:var(--mono);font-size:10px;letter-spacing:.14em;text-transform:uppercase;
color:var(--blaze);display:block;margin-bottom:7px}}
h1{{font-family:var(--serif);font-weight:500;font-size:clamp(1.7rem,3.2vw,2.3rem);line-height:1.14;
letter-spacing:-.01em;margin:52px 0 0;max-width:24ch;color:var(--cream)}}
.tagline{{color:var(--muted);font-size:16.5px;margin:14px 0 0;max-width:62ch;line-height:1.6}}
.meta{{font-family:var(--mono);color:var(--muted);font-size:12.5px;margin:18px 0 28px;line-height:1.8}}
.meta b{{color:var(--cream);font-weight:600}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:16px;margin:0 0 8px}}
.stat{{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:20px 22px}}
.stat .n{{font-family:var(--serif);font-size:42px;font-weight:600;font-variant-numeric:tabular-nums;line-height:1}}
.stat .l{{font-family:var(--mono);font-size:11px;color:var(--cream);margin-top:10px;
text-transform:uppercase;letter-spacing:.09em;font-weight:600}}
.stat .h{{font-size:12.5px;color:var(--muted);margin-top:5px;line-height:1.5}}
.stat.reach{{border-color:{'rgba(255,67,1,.5)' if reachable else 'var(--line)'}}}
.stat.reach .n{{color:{'var(--heat)' if reachable else 'var(--sky)'}}}
.stat.inst .n{{color:var(--blaze)}}.stat.surf .n{{color:var(--cream)}}.stat.cov .n{{color:var(--apricot)}}
.pill{{display:inline-block;font-family:var(--mono);font-size:10.5px;font-weight:600;padding:3px 10px;
border-radius:999px;margin-left:10px;vertical-align:middle;letter-spacing:.05em;text-transform:uppercase}}
.pill.lo{{color:var(--sky);border:1px solid rgba(82,189,255,.4);background:rgba(82,189,255,.08)}}
.pill.md{{color:var(--blaze);border:1px solid rgba(250,125,9,.45);background:rgba(250,125,9,.08)}}
.pill.hi{{color:var(--heat);border:1px solid rgba(255,67,1,.45);background:rgba(255,67,1,.08)}}
.verdict{{background:var(--panel2);border:1px solid var(--line);border-left:4px solid var(--blaze);
border-radius:16px;padding:26px 30px;margin:26px 0 0}}
.verdict .k{{font-family:var(--mono);font-size:11px;letter-spacing:.12em;text-transform:uppercase;
color:var(--blaze)}}
.verdict .v{{font-family:var(--serif);font-size:26px;font-weight:500;margin-top:8px;
color:{('var(--heat)' if 'None' not in overall else 'var(--cream)')}}}
.verdict small{{color:var(--muted);display:block;margin-top:10px;font-size:13.5px;line-height:1.6}}
.verdict small b{{color:var(--cream)}}
h2{{font-family:var(--mono);font-size:11.5px;text-transform:uppercase;letter-spacing:.12em;
color:var(--blaze);margin:56px 0 8px;font-weight:600;border-top:1px solid var(--line);padding-top:30px}}
h2 .c{{color:var(--muted);font-weight:400;letter-spacing:.02em;text-transform:none;margin-left:8px}}
/* Reachability-unknown band — amber-flagged, visually distinct from the deterministic verdict/counts. */
h2.ruflag{{color:var(--blaze);border-left:4px solid var(--blaze);padding-left:14px;
background:linear-gradient(90deg,rgba(250,125,9,.08),transparent 60%)}}
/* AI-suspected band — sky/blue-flagged, advisory, clearly OUTSIDE the deterministic verdict/counts. */
h2.aiflag{{color:var(--sky);border-left:4px solid var(--sky);padding-left:14px;
background:linear-gradient(90deg,rgba(43,125,226,.08),transparent 60%)}}
h3{{font-family:var(--mono);font-size:11px;text-transform:uppercase;letter-spacing:.1em;
color:var(--apricot);margin:28px 0 6px;font-weight:600}}
h3 .c{{color:var(--faint);font-weight:400;letter-spacing:.02em;text-transform:none;margin-left:8px}}
.tier{{color:var(--muted);font-size:14px;margin:0 0 16px;max-width:78ch;line-height:1.65}}
.tier b{{color:var(--cream);font-weight:600}}
table{{border-collapse:collapse;width:100%;font-family:var(--mono);font-size:12.5px;
background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}}
td{{padding:11px 14px;border-bottom:1px solid var(--line);vertical-align:top}}
tr:last-child td{{border-bottom:none}}
.mono{{color:var(--cream)}}.ln{{color:var(--blaze)}}.cap{{color:var(--apricot);white-space:nowrap}}
.sym{{color:var(--muted)}}.more{{color:var(--muted);font-style:italic}}
.hd{{color:var(--faint);font-size:10px;text-transform:uppercase;letter-spacing:.09em;font-weight:600;
background:var(--panel2)}}
.tier2{{white-space:nowrap}}.ctrl{{color:var(--cream);line-height:1.5;font-family:var(--sans)}}
.plan{{color:var(--apricot);white-space:nowrap;font-weight:600}}
.badge{{display:inline-block;font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.05em;
text-transform:uppercase;padding:3px 9px;border-radius:999px;white-space:nowrap}}
.badge.ff{{color:var(--heat);border:1px solid rgba(255,67,1,.5);background:rgba(255,67,1,.1)}}
.badge.rv{{color:var(--blaze);border:1px solid rgba(250,125,9,.5);background:rgba(250,125,9,.1)}}
.badge.wt{{color:var(--blaze);border:1px solid rgba(250,125,9,.5);background:rgba(250,125,9,.1)}}
.badge.ru{{color:var(--heat);border:1px solid rgba(255,67,1,.5);background:rgba(255,67,1,.1)}}
/* ---- the Repairer CTA ---- */
.cta{{background:linear-gradient(135deg,rgba(250,125,9,.16),rgba(255,67,1,.06));
border:1px solid rgba(250,125,9,.5);border-radius:20px;padding:28px 32px;margin:44px 0 0}}
.cta .k{{font-family:var(--mono);font-size:11px;letter-spacing:.14em;text-transform:uppercase;
color:var(--blaze);margin-bottom:4px}}
.cta p{{margin:12px 0 0;color:var(--muted);max-width:78ch;line-height:1.65;font-size:15px}}
.cta b{{color:var(--cream)}}
.cta .link{{font-family:var(--mono);font-size:15px;color:var(--blaze);margin-top:16px;font-weight:600}}
.bars{{display:flex;flex-direction:column;gap:9px;margin-top:8px}}
.bar{{display:grid;grid-template-columns:170px 1fr 56px;align-items:center;gap:14px;
font-family:var(--mono);font-size:12.5px}}
.bl{{color:var(--muted);text-align:right}}
.bn{{color:var(--cream);text-align:right;font-variant-numeric:tabular-nums;font-weight:600}}
.track{{background:rgba(234,217,192,.1);border-radius:5px;height:10px;overflow:hidden}}
.fill{{display:block;height:100%;background:linear-gradient(90deg,var(--blaze),var(--heat))}}
.note{{color:var(--muted);font-size:13px;background:var(--panel);border:1px solid var(--line);
border-left:4px solid var(--blaze);padding:18px 22px;border-radius:0 12px 12px 0;margin-top:44px;line-height:1.65}}
.note b{{color:var(--cream)}}
.foot{{color:var(--faint);font-size:12px;margin-top:34px;border-top:1px solid var(--line);
padding-top:16px;line-height:1.6}}
.foot code,.meta code{{font-family:var(--mono);color:var(--apricot)}}
</style></head><body><div class=wrap>
<div class=mast>
  <div class=brand>HERMES <span class=sh>SHIELD</span></div>
  <div class=sub>excessive-agency scan · OWASP LLM06 · scanned {scan_date} · scanner v{esc(_ver)}</div>
</div>

<div class="banner {b_cls}">
  <div class=icon>{b_icon}</div>
  <div>
    <div class=k>scan verdict · {esc(repo_name)}</div>
    <div class=head>{b_head}</div>
    <div class=bsub>{b_sub}</div>
  </div>
</div>

<div class=plain>
  <div class=pw><span class=pk>What we found</span>{pw_found}</div>
  <div class=pw><span class=pk>What's urgent</span>{pw_urgent}</div>
  <div class=pw><span class=pk>What to do</span>{pw_do}</div>
</div>

<h1>{total_surfaces:,} {_pl(total_surfaces, 'place', 'places')} this code can act &mdash; mapped.</h1>
<div class=tagline>Statically, locally, rated by proven reachability &mdash; your code never leaves this machine.</div>
<div class=meta><b>Repository:</b> <code>{esc(repo_name)}</code> &nbsp;·&nbsp; <b>{files:,}</b> {_pl(files, 'file', 'files')} scanned
&nbsp;·&nbsp; <b>{total_surfaces:,}</b> action-surfaces mapped &nbsp;·&nbsp; static analysis · target code is never
executed · the deterministic core makes no network calls (optional --ai/--deps tiers do — see the docs)</div>

<div class=stats>
  <div class="stat surf"><div class=n>{total_surfaces:,}</div><div class=l>Action-surfaces</div><div class=h>every point the agent can act — the map</div></div>
  <div class="stat inst"><div class=n>{install_liab:,}<span class="pill {band_class}">{band}</span></div><div class=l>Install-liability</div><div class=h>dangerous capability that's harmless here but live once installed — inert here, live on install</div></div>
  <div class="stat reach"><div class=n>{reachable:,}</div><div class=l>Reachable in-repo</div><div class=h>live now — from this repo's own entrypoints</div></div>
  <div class="stat cov"><div class=n>{files:,}</div><div class=l>Files scanned</div><div class=h>{cov_note}</div></div>
</div>

<div class=verdict>
  <div class=k>▸ OWASP LLM06 verdict</div>
  <div class=v>{esc(overall_display)}</div>
  <small>OWASP LLM06 rating: <b>{esc(overall)}</b> · {reachable:,} live {_pl(reachable, 'precondition', 'preconditions')} present ·
  proven-live (we demonstrated a real attack path): {proven:,} · no fully-chained proof-of-concept was run
  beyond those. A clean verdict means <b>not demonstrated exploitable</b> — it is never read as "secure".</small>
</div>

<h2>▸ Reachable in-repo <span class=c>— live now, from this repo's own entrypoints (fix first)</span></h2>
<div class=tier>An untrusted input can reach these dangerous actions with no control in the way, today.</div>
<table>{rows(live)}</table>

{amber_band_html}

{fixed_dest_band_html}

{reach_unknown_html}

<h2>▸ Fix plan <span class=c>— generated, not applied</span></h2>
<div class=tier>Suggested fix-at-source controls for the confirmed no-control / fake-gate findings.
<b>The scanner plans these; it does not modify your code.</b> The Hermes Shield Repairer — the paid tier,
in early access — is being built to apply these under a human gate — never auto-fix. Until then each item
is guidance you apply and review.</div>
<h3>Fix first — reachable now <span class=c>— {len(_fix_reach)} {_pl(len(_fix_reach), 'item', 'items')} · classified by the same reachable-unguarded rule as the “Reachable in-repo” count above</span></h3>
<table>{_fixhead}{fixplan_reach_html}</table>
{fixplan_amber_block}
{fixplan_runknown_block}
{fixplan_wiring_block}

<div class=cta>
  <div class=k>▸ what happens next</div>
  <p><b>This report is the free Scanner.</b> It finds every action-surface and plans the fix.</p>
  <p><b>The Hermes Shield Repairer is coming</b> — the paid tier (early access). It will turn each planned
  control above into a reviewed code change: proposed as a diff, applied only when a human approves, then
  re-scanned to confirm the gap is closed. Never auto-fix.</p>
  <a class=link href="https://hermesshield.ai/repairer">Join the early-access list → hermesshield.ai/repairer</a>
</div>

<h2>▸ Install-liability <span class=c>— RCE-class capability you inherit on install (proven inert here)</span></h2>
<div class=tier>RCE-class (an attacker running their own code on your machine) capabilities that are
<b>proven inert here, live on install</b>: not reachable from this repo's own entrypoints today <b>and</b>
sitting behind no untrusted ingress or unresolved dispatch, but a live attack surface the moment they're
wired into an agent that reads untrusted input. Capped at Med — not a vulnerability in this repo. The fix
is wiring-time: gate each capability before you wire untrusted input to it on install — this is not a
fix-now list. <b>Sinks we could not prove inert appear under “Reachability unknown” above, not here.</b></div>
<table>{rows(il)}</table>

{review_html}

{ai_html}

<h2>▸ Action-surface map <span class=c>— by capability</span></h2>
<div class=bars>{bars}</div>

<div class=note><b>How to read this.</b> Static excessive-agency analysis for OWASP LLM06: it assumes
prompt-injection succeeds and maps what a hijacked agent could then DO — the target is read in place, never
executed. Severity is <b>reachability-rated</b>: <b>reachable-in-repo</b> is live now; <b>install-liability</b>
is inherited on wiring. Reachability is sound-leaning, not complete (dynamic dispatch, reflection and
cross-process flows are not traced) — a "no finding" is not a proof of safety. Non-Python surfaces are
detected but not reachability-reasoned.</div>
<div class=foot>Hermes Shield — static, local analysis. Severity is reachability-rated: findings reflect
traced paths from real entrypoints, not keyword matches. A clean scan indicates no proven-live path, not a
guarantee of security. Raw data: <code>hermes_action_surface_scan.json</code>.</div>
</div></body></html>"""


def main(argv=None):
    import json
    ap = argparse.ArgumentParser(description="Hermes Shield — scan any repo, emit the multi-report")
    ap.add_argument("--repo", required=True, help="path to the repo to scan (read-only)")
    ap.add_argument("--out", default=None,
                    help="output DIRECTORY for the multi-report (report.md + report.html + findings.json); "
                         "if omitted, prints the summary to stdout")
    args = ap.parse_args(argv)
    root = Path(args.repo).resolve()
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2
    scan = SH.run_scan(root)
    md = build_report(scan, root.name, root=root)
    if args.out:
        outdir = Path(args.out)
        outdir.mkdir(parents=True, exist_ok=True)
        (outdir / "report.md").write_text(md, encoding="utf-8")
        (outdir / "report.html").write_text(build_html(scan, root.name, root=root), encoding="utf-8")
        model = _report_model(scan, root.name)
        findings = {"repo": model["repo"], "files_scanned": model["files_scanned"],
                    "summary": {k: model[k] for k in ("total", "gated", "no_gate", "fake", "coverage_pct")},
                    "by_capability": model["by_capability"], "ai_counts": model["ai_counts"],
                    "surfaces": [s.to_dict() for s in scan["surfaces"] if s.context == "prod"]}
        (outdir / "findings.json").write_text(json.dumps(findings, indent=2, default=str), encoding="utf-8")
        print(f"[shield] wrote multi-report -> {outdir}/ (report.md, report.html, findings.json)")
    else:
        print("\n".join(md.splitlines()[:16]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
