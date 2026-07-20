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

# Protected verdicts — patch_plan.build() skips EXACTLY these (a control is proven present), so the report's
# fix plan skips them too. Everything else a static, prod, critical surface carries IS surfaced as a fix-plan
# item at its real tier — so the buyer-facing fix-plan count reconciles with hermes_patch_plan.json and
# nothing mapped is silently dropped from the plan (COMPLETENESS invariant).
_PP_PROTECTED_VERDICTS = {"PROTECTED_FULL_PATH", "STATIC_PROOF_ONLY", "PROVIDER_SCOPE",
                          "PROTECTED_TEXT_PATH_ONLY", "PASS_WITH_RESIDUAL_RISK"}

# ONE HONEST CALLOUT beside every fix plan (Constitution: state as fact, not fear). A control written is not
# a control proven — the ONLY way to KNOW a fix holds is to re-run the attack against it. Surfaced verbatim
# in both the HTML and the MD report next to the plan.
_PROOF_CALLOUT = ("A control applied is not a control proven — a plausible fix can still be bypassed; "
                  "the only way to KNOW is to re-run the attack.")

# ---- PLAIN NAMES (rename engineer-speak; used identically in the MD and HTML report so the two skins
# render the SAME taxonomy). "install-liability" is kept verbatim (it is a load-bearing product term).
PLAIN = {
    "action_surfaces": "dangerous actions your agent can take",
    "reachable": "already reachable by untrusted input (unguarded)",
    "reach_unknown": "needs a human trace — not proven safe",
    "proven_live": "we made it fire (0 = untested, not a clean bill of health)",
}


def _reconciled_counts(m, ir) -> dict:
    """The ONE reconciled count set both the MD and HTML report render from — install_report is the single
    source of truth, so the banner, the scoreboard and the MD top-line can never disagree. `m` supplies the
    mapped total (critical rows + review-manually rows); `ir` supplies every severity-bearing count."""
    return {
        "kind": ir.get("repo_kind", "library"),
        "kind_reason": ir.get("repo_kind_reason", ""),
        "kind_confidence": ir.get("repo_kind_confidence", "low"),
        "mapped": m.get("mapped", m.get("total", 0)),
        "reachable": ir.get("non_gated_vulnerable", 0),
        "amber": ir.get("reachable_amber_actions", 0) + ir.get("reachable_fixed_dest_review", 0),
        "reach_unknown": ir.get("reachability_unknown", 0),
        "install_liab": ir.get("install_liability_rce", 0),
        "install_band": (ir.get("install_liability_rating") or {}).get("band", "Low"),
        "proven": ir.get("proven_live_poc", 0),
        "review": len(m.get("review_rows", [])),
        "ai": len(m.get("ai_rows", [])),
    }


def _exec_headline(c: dict) -> str:
    """ONE reconciled headline sentence shared by both skins (plain text). Never reads 'you are okay': a low
    reachable count is ALWAYS paired with the reachability-unknown count and the proven-live=0 caption."""
    inst = ("install-liability N/A — nobody installs an app" if c["kind"] == "app"
            else f"{c['install_liab']} inherited-on-install")
    return (f"{c['mapped']} actions mapped; {c['reachable']} reachable-now; "
            f"{c['reach_unknown']} need a human trace; {inst}; {c['proven']} proven-live.")


def _exec_verdict(c: dict) -> str:
    """ONE OWASP verdict sentence shared by both skins (plain text), stated as fact, never 'secure'."""
    if c["proven"] > 0:
        return (f"{c['proven']} proven-live — we demonstrated a real attack path. Act now.")
    tail = "act now." if c["reachable"] else (
        "verify the human-trace items before you rely on this being safe." if c["reach_unknown"]
        else "this is not a clean bill of health — proven-live 0 means untested, not safe.")
    return (f"No full exploit demonstrated (proven-live 0), but {c['reachable']} reachable with no control "
            f"and {c['reach_unknown']} not proven safe — {tail}")


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
        # COMPLETENESS (buyer must see the whole plan): a surface is surfaced UNLESS it carries a protected
        # verdict (a control is proven present — patch_plan.build skips exactly these too). This makes the
        # fix-plan count reconcile with hermes_patch_plan.json; the old `cat in {NO_GATE,FAKE_GATE}` gate
        # silently dropped genuine review findings (NEEDS_CERTIFICATION, fixed-dest sends) the JSON carried.
        if getattr(s, "verdict", "") in _PP_PROTECTED_VERDICTS:
            continue
        cap = s.capability
        # STEP 2 (the adversarial proof-test that ALREADY exists in hermes_patch_plan.json). Surfaced on
        # EVERY fix row — it reframes the free directional advice (Step 1) as the EASY half: prove the sink
        # is actually blocked by driving it with hostile input and asserting benign still passes.
        suggested_test = _PP._suggested_test(cap)
        if cat in ("UNPROVEN", "GATE_UNVERIFIED"):
            # HELD (checked FIRST, before any fix-tier) — a control may ALREADY be present, or reachability
            # could not be proven. We never tell you to change code that may already be protected; verify
            # first. Counted (so the plan total reconciles with hermes_patch_plan.json), never surfaced as a
            # fix instruction.
            band, tier, reachable = "held", "held — control may already be present; verify, don't blind-change", False
            control = ("A control may already be present here (or reachability is unproven) — verify with a "
                       "test before you change anything. " + _PP.recommended_control(cap))
        elif IR.is_non_gated_vulnerable(s):        # RED — reachable + unguarded, high blast-radius
            band, tier, reachable = "red", "reachable-in-repo", True
            control = _PP.recommended_control(cap)
        elif IR.is_reachable_amber_action(s) or IR.is_reachable_fixed_dest_review(s):
            # AMBER — reachable + unguarded, reversible/social OR fixed-destination send (review before ship)
            band, tier, reachable = "amber", "reachable action — review before you ship", True
            control = _PP.recommended_control(cap)
        elif cap in _RCE and (getattr(s, "tainted_reachable", False) or _has_ingress or _has_dispatch):
            # REACHABILITY-UNKNOWN — could NOT be proven inert (ingress / unresolved dispatch present). Never
            # "inert here / gate on install"; verify reachability first, then apply the real fix-at-source.
            band, tier, reachable = "reach-unknown", "reachability unknown — verify, then gate", False
            control = "Reachability not proven (untrusted ingress / unresolved dispatch present) — trace from the ingress first. " + _PP.recommended_control(cap)
        elif cap in _RCE:                          # RCE-class proven inert — gate at wiring time (install)
            band, tier, reachable = "wiring", "wiring-time — gate on install", False
            control = _PP.wiring_control(cap)
        else:
            # REVIEW — a critical action with NO control present whose reachability / live-capability we could
            # not establish (e.g. NEEDS_CERTIFICATION, a fixed-dest send not proven tainted-reachable). Not
            # "fix first" (not proven reachable) and NOT "inert" (not proven inert): certify, then gate.
            band, tier, reachable = "review", "review — no control present; certify reachability & gate", False
            control = _PP.recommended_control(cap)
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
            "suggested_test": suggested_test,
            "status": _FIX_STATUS,
        })
    # SALIENCE: work top-to-bottom by band (red > amber > reach-unknown > review > wiring > held), then by
    # capability severity so the hard sinks (RCE-class code_exec/deserialize/subprocess, severity 5) lead each
    # band ABOVE the soft tool_invoke / xml_parse review items (severity 3). Deterministic file+line tie-break
    # keeps output stable.
    _band_order = {"red": 0, "amber": 1, "reach-unknown": 2, "review": 3, "wiring": 4, "held": 5}
    out.sort(key=lambda it: (_band_order.get(it["band"], 9),
                             -IR._SEVERITY.get(it["capability"], 3),
                             it["file"], it["line"]))
    return out


def _fix_cards(scan):
    """DE-NOISE the fix plan for the HUMAN report: collapse the FULL machine inventory (hermes_patch_plan.json,
    one row per dangerous call site) into ONE fix-card per control point via patch_plan.group_plan. Returns
    (groups, top5, inventory_count) so the report can render ~12-15 cards ("this one gate covers 388 call
    sites") reconciled against the JSON, plus a leverage-ranked "FIX THESE FIRST" list. The inventory is never
    mutated — grouping only."""
    from . import patch_plan as _PP
    prod = [s for s in scan.get("surfaces", []) if getattr(s, "context", "prod") == "prod"]
    items = _PP.build(prod)
    groups = _PP.group_plan(items)
    return groups, _PP.top_fixes(groups, 5), len(items)


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
    except Exception:
        _ir = {}
    c = _reconciled_counts(m, _ir)
    # SOURCE coverage (scanned source files / scannable source after SKIP_DIRS) — the SAME real figure the
    # HTML skin prints under "% of scannable source". Kept DISTINCT from CONTROL coverage (m['coverage_pct']
    # = gated/total critical sinks): the control number is never labelled "of scannable source".
    _cov_src = _ir.get("coverage_pct", None)
    _cov_src_note = f"{_cov_src}% of scannable source" if _cov_src is not None else "coverage: see report"
    _install_liab = c["install_liab"]
    _install_band = c["install_band"]
    _proven = c["proven"]
    _reach_unknown = c["reach_unknown"]
    _reachable = c["reachable"]
    # CONTEXT-AWARE install-liability line (kills the inverted "0 · Low" green badge in the MD skin too):
    # an app's install-liability is N/A — nobody installs an app — never a residual-risk score on nothing.
    if c["kind"] == "app":
        _install_liab_line = "N/A — nobody installs an app (its risk is what is reachable now, above)"
    elif _install_liab:
        _install_liab_line = f"{_install_liab}  ·  inherited rating: {_install_band}"
    else:
        _install_liab_line = "0  (no RCE-class capability inherited on install)"

    # Fix plan — generated, not applied. Complete: every mapped surface except proven-protected ones appears
    # (reconciles with hermes_patch_plan.json). Each row carries Step 1 (the control) AND Step 2 (the proof).
    _fixrows = _fix_plan_rows(rows, scan)
    _fix_shown = [it for it in _fixrows if it["band"] != "held"]
    _fix_held = [it for it in _fixrows if it["band"] == "held"]

    def _fix_md(limit=250):   # roll rows up (was capped at 30)
        if not _fixrows:
            return "- (none — no no-control / fake-gate findings to plan)"
        lines = []
        for it in _fix_shown[:limit]:
            lines.append(
                f"- `{it['file']}:{it['line']}` · **{it['cap_label']}** · tier: {it['tier']} · "
                f"status: **{it['status']}**\n"
                f"    - **Step 1 — apply the control:** {it['recommended_control']}\n"
                f"    - **Step 2 — prove it's actually blocked:** a test that drives this sink with hostile "
                f"input and asserts it's blocked (benign still passes). {it['suggested_test']}")
        if len(_fix_shown) > limit:
            lines.append(f"- …and {len(_fix_shown) - limit} more in `hermes_patch_plan.json`")
        if _fix_held:
            lines.append(
                f"- _{len(_fix_held)} further item(s) are **held** from this plan — a control may already be "
                f"present or reachability is unproven, so we do not tell you to change them; verify first "
                f"(they remain in `hermes_patch_plan.json`)._")
        return "\n".join(lines)

    fix_md = _fix_md()

    # DE-NOISE — collapse the FULL inventory into ONE fix-card per control point, plus a leverage-ranked
    # "FIX THESE FIRST — top 5". The machine feed (hermes_patch_plan.json) keeps every row; the human sees
    # ~12-15 cards, each naming the ONE fix and the N call sites it closes.
    _CLASS_LABEL = {"gate": "fix now — no control present", "review": "review — certify, then gate",
                    "held": "held — verify first", "informational": "informational — no gate needed"}
    _groups, _top5, _inv_n = _fix_cards(scan)

    def _top5_md():
        if not _top5:
            return ""
        lines = ["### FIX THESE FIRST — top 5 (ranked by leverage = sites-closed × severity)"]
        for i, g in enumerate(_top5, 1):
            lines.append(
                f"{i}. **{g['control_point']}** — one fix closes **{g['count']} "
                f"{'site' if g['count'] == 1 else 'sites'}** ({g['capability']}, severity {g['severity']}; "
                f"leverage {g['leverage']}).")
        return "\n".join(lines) + "\n"

    def _cards_md():
        if not _groups:
            return "- (none — nothing to plan)"
        lines = []
        for g in _groups:
            head = (f"- **{g['control_point']}** · {_CLASS_LABEL.get(g['fix_class'], g['fix_class'])} · "
                    f"one fix closes **{g['count']} {'site' if g['count'] == 1 else 'sites'}** "
                    f"({g['capability']})")
            lines.append(head)
            lines.append(f"    - **The one control:** {g['control']}")
            if g["fix_class"] != "informational":
                lines.append(
                    f"    - **Prove it blocks:** {g['suggested_test']}")
            _locs = g["locations"][:3]
            _more = g["count"] - len(_locs)
            _tail = f" …and {_more} more of this group in `hermes_patch_plan.json`" if _more > 0 else ""
            lines.append(f"    - **Covers:** `{'`, `'.join(_locs)}`{_tail}")
        return "\n".join(lines)

    top5_md = _top5_md()
    cards_md = _cards_md()
    cards_reconcile_md = (
        f"_**{len(_groups)} fix-{'card' if len(_groups) == 1 else 'cards'}** below de-noise the "
        f"**{_inv_n}-row** machine inventory in `hermes_patch_plan.json` — grouped by the single control "
        f"point each shares; every row is preserved in the JSON (the Repairer feed), nothing is dropped._")

    # QUANTIFY honestly (near the fix plan): the real work each sink demands, and what the Repairer delivers.
    _n_fix = len(_fix_shown)
    fix_quantify_md = (
        f"**{_n_fix} {'sink' if _n_fix == 1 else 'sinks'} in this plan × (write a correct control + write a "
        f"proof it blocks + re-verify closure).** The deterministic Repairer delivers each as a reviewed diff "
        f"with the proof attached." if _n_fix else "")
    # MOVE THE VALUE-ANCHOR UP — surface it beside the FIRST reachable-now finding (the moment of felt
    # difficulty), not only at the bottom. Honest present tense, genuine value, a CTA. Rendered only when
    # there is a reachable-now (red) fix item to anchor to.
    _has_reach_now = any(it["band"] == "red" for it in _fix_shown)
    repairer_anchor_md = ("" if not _has_reach_now else
        "> **Each fix is really two jobs: write a correct control, then prove it blocks.** The deterministic "
        "Repairer does both today on real repos — it applies the control as a reviewed diff, then re-runs the "
        "real attack and proves this sink flips from exploitable to blocked (RED→PROTECTED), re-verified by "
        "the same scanner (human-gated, never auto-fix). The AI-assist tier is in early access.\n"
        "> → Early access: hermesshield.ai/repairer\n")

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

    from datetime import date as _dt_date
    try:
        from .models import SCANNER_VERSION as _ver
    except Exception:
        _ver = "unknown"
    _scan_date = _dt_date.today().isoformat()

    # Reachable-now + reachability-unknown lists straight off install_report's items, so the rendered rows
    # reconcile 1:1 with the scoreboard counts (never the MD's own re-derived taxonomy).
    def _ir_list(items, note):
        out_l = [f"- `{it['file']}:{it['line']}`  **{_CAP_LABEL.get(it['capability'], it['capability'])}**  {note}"
                 for it in items]
        return "\n".join(out_l) if out_l else "- (none)"
    reach_md = _ir_list(_ir.get("non_gated_items", []), "_(reachable now — fix first)_")
    runknown_md = _ir_list(_ir.get("reachability_unknown_items", []),
                           "_(needs a human trace — not proven safe)_")

    # SEVERITY-FIRST SCOREBOARD — each tile carries a severity word; the DANGEROUS number gets the loudest
    # word, the harmless 0 the quietest. Context-aware: an app's install-liability is N/A, never a green 0.
    def _sev_word(n, danger):
        return danger if n else "none"
    _sb = []
    _sb.append(f"| Metric | Count | Severity |")
    _sb.append(f"|---|---|---|")
    _sb.append(f"| {PLAIN['action_surfaces']} (mapped) | **{c['mapped']}** | the map |")
    _sb.append(f"| {PLAIN['reachable']} | **{_reachable}** | {_sev_word(_reachable, 'DANGEROUS — act now')} |")
    _sb.append(f"| {PLAIN['reach_unknown']} | **{_reach_unknown}** | {_sev_word(_reach_unknown, 'UNRESOLVED — verify')} |")
    _sb.append(f"| install-liability | {_install_liab_line} | "
               f"{'N/A (app)' if c['kind'] == 'app' else _sev_word(_install_liab, 'inherited — gate on install')} |")
    _sb.append(f"| {PLAIN['proven_live']} | **{_proven}** | {'PROVEN-LIVE' if _proven else 'not tested (not a clean bill)'} |")
    _sb.append(f"| below-critical-line (review manually) | {c['review']} | review |")
    _sb.append(f"| AI-suspected (advisory) | {c['ai']} | advisory — verify |")
    scoreboard_md = "\n".join(_sb)

    out = f"""# Hermes Shield — Excessive-Agency Report
<!-- SECTION 1 — COVER / IDENTITY -->
**Repo:** `{m['repo']}`  ·  **Files scanned:** {m['files_scanned']}  ·  **Scanned:** {_scan_date}  ·  **Scanner:** v{_ver}
**Repo kind:** `{c['kind']}` ({c['kind_confidence']} confidence — {c['kind_reason']})

> Read-only static analysis — the target code is never executed and the deterministic core makes no network
> calls. Maps to **OWASP LLM06 (Excessive Agency)**: it reports the dangerous ACTIONS an AI agent could be
> tricked into, and whether a control is *written* before each — it does NOT prove a control runs/blocks/is
> deployed. Findings marked _AI_ are model-proposed and MUST be human-verified.

## 2. Executive summary
**{_exec_headline(c)}**

**OWASP LLM06 verdict:** {_exec_verdict(c)}

## 3. Severity-first scoreboard
{scoreboard_md}

- **{_reachable} with NO control found** — reachable now by untrusted input with nothing in the way; each
  fix-plan item below carries its real tier (fix-first / reachable-action review / wiring-time).
- **install-liability = inert here, live on install** — a dangerous capability that is harmless in this repo
  but live the moment someone installs it and wires untrusted input to it. {"For an APP this is N/A: nobody installs an app." if c['kind'] == 'app' else "This is the risk you INHERIT on install — not a vulnerability in this repo."}
- **proven-live = {_proven}** — proven_live=0 means **not demonstrated**, never "secure". A zero is the
  absence of a proof, never a clean bill of health; it is **untested, not safe**.

## 4. {PLAIN['reachable'].capitalize()} — start here
> An untrusted input can reach these dangerous actions with no control in the way, today. Fix these first.
{repairer_anchor_md}
{reach_md}

## 5. {PLAIN['reach_unknown'].capitalize()}
> RCE-class sinks we could **not prove inert** — an untrusted ingress (e.g. an HTTP route) and/or dynamic
> dispatch the tracer could not resolve is present, so a request may reach them along a path we could not
> follow. This is **reachability not proven — verify manually**, never "not reachable". An analysis limit is
> not a safety fact.
{runknown_md}

## 6. Fix plan — generated, not applied
> Fix-at-source controls for the findings that need one. Each is TWO steps: **Step 1** the control, **Step 2**
> the adversarial proof-test that shows it actually blocks.
> **The scanner plans these; it does not modify your code.**
>
> **{_PROOF_CALLOUT}**
>
> {fix_quantify_md}
> The **deterministic Repairer does this today on real repos**: it applies the control as a reviewed diff,
> then **re-runs the real attack and proves the sink flips from exploitable to blocked (RED→PROTECTED),
> re-verified by the same scanner** — under a human gate, never auto-fix. The **AI-assist tier is in early
> access** (hermesshield.ai/repairer).

{cards_reconcile_md}

{top5_md}
### Fix cards — one card per control point (fix these first: top 5, above)
{cards_md}

<details><summary>Full per-site fix rows (every call site — rolled up, not capped)</summary>

{fix_md}

</details>

### Discovered attack surfaces by capability
{disc}

### AI-suspected surfaces — advisory, human MUST verify
> Found by the optional AI-assist tier (any coding agent) on files the static rules missed, each AST-verified
> as a real call. **NOT counted** in the scoreboard above — advisory only. Treat as leads to review, not
> confirmed findings.
{ai_block}

## 7. Methodology, scope & honest blind spots
Static excessive-agency analysis for OWASP LLM06: it assumes prompt-injection succeeds and maps what a
hijacked agent could then DO — the target is read in place, never executed. Severity is **reachability-rated**:
reachable-in-repo is live now; install-liability is inherited on wiring.

**Blind spots (not covered — a "no finding" is not a proof of safety):** dynamic dispatch, runtime config,
cross-process stores and non-Python surfaces are not reachability-reasoned. Source coverage ({_cov_src_note})
is how much scannable source we actually read; **control coverage** ({m['coverage_pct']}% of critical sinks
with a declared guard) is only accurate once YOUR control functions are declared in the guard config.

---
*Honest-scope: "coverage / gap-finder", not a containment proof.*
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
    c = _reconciled_counts(m, _ir)
    repo_kind = c["kind"]
    is_app = repo_kind == "app"
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
                 f"right now, no control we can credit. {_pl(n, 'Fix this first.', 'Fix these first.')}")
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

    def rows(items, limit=250):   # roll rows up (was capped at 30) — only pathological inventories overflow
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
    _fix_review = [it for it in _fixrows if it["band"] == "review"]
    _fix_wiring = [it for it in _fixrows if it["band"] == "wiring"]
    _fix_held = [it for it in _fixrows if it["band"] == "held"]
    _fix_shown = [it for it in _fixrows if it["band"] != "held"]

    def fixplan_rows(items, badge, empty, limit=250):   # roll rows up (was capped at 30)
        out = []
        for it in items[:limit]:
            # EVERY fix row is TWO steps: Step 1 (the control — free directional advice) and Step 2 (the
            # adversarial proof-test that ALREADY exists in hermes_patch_plan.json). Step 2 reframes the free
            # advice as the EASY half — prove the sink is actually blocked, not just that a control is present.
            ctrl = (f"<div class=fstep><span class=fsn>Step 1 — apply the control</span>"
                    f"{esc(it['recommended_control'])}</div>"
                    f"<div class=fstep><span class=fsn>Step 2 — prove it's actually blocked</span>"
                    f"a test that drives this sink with hostile input and asserts it's blocked (benign still "
                    f"passes). {esc(it['suggested_test'])}</div>")
            out.append(
                f"<tr><td class=mono>{esc(it['file'])}<span class=ln>:{it['line']}</span></td>"
                f"<td class=cap>{esc(it['cap_label'])}</td>"
                f"<td class=tier2>{badge}</td>"
                f"<td class=ctrl>{ctrl}</td>"
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
    # REVIEW fix band — a critical action with NO control present whose reachability / live-capability we could
    # NOT establish (e.g. NEEDS_CERTIFICATION, a fixed-destination send not proven tainted-reachable). Neither
    # "fix first" (not proven reachable) nor "inert" (not proven inert): certify reachability, then gate.
    # Surfaced (not silently dropped) so the buyer-facing plan is COMPLETE. Only shown when present.
    fixplan_review_block = "" if not _fix_review else (
        "<h3>Review — no control present, reachability not established "
        "<span class=c>— certify reachability, then gate; not proven reachable, not proven inert</span></h3>"
        "<div class=tier>These critical actions have <b>no control in front of them</b>, but we could not "
        "establish whether an untrusted input reaches them. This is <b>not “fix first”</b> (not proven "
        "reachable) and <b>not “inert”</b> (not proven inert). <b>Certify reachability, then gate each one "
        "before you ship.</b></div>"
        f"<table>{_fixhead}" + fixplan_rows(
            _fix_review, "<span class='badge rw'>review — certify &amp; gate</span>", "(none)")
        + "</table>")
    fixplan_wiring_block = "" if not _fix_wiring else (
        "<h3>Gate on install — wiring-time <span class=c>— inert here, not a fix-now item</span></h3>"
        "<div class=tier>These are <b>not reachable in this repo today</b>, so they are never labelled "
        "“fix first”. Gate each one before untrusted input is wired to it on install.</div>"
        f"<table>{_fixhead}" + fixplan_rows(
            _fix_wiring, "<span class='badge wt'>wiring-time — gate on install</span>", "(none)")
        + "</table>")
    # HELD reconciliation — items in hermes_patch_plan.json we deliberately do NOT surface as a fix
    # instruction because a control may already be present or reachability is unproven (we never tell you to
    # change protected code). Stated plainly so the buyer-facing count is complete and honest.
    fixplan_held_block = "" if not _fix_held else (
        f"<div class=held><b>{len(_fix_held)} further {_pl(len(_fix_held), 'item', 'items')} "
        f"held from this plan.</b> A control may already be present, or reachability could not be proven — so "
        f"we do <b>not</b> tell you to change {_pl(len(_fix_held), 'it', 'them')}; verify first. "
        f"{_pl(len(_fix_held), 'It remains', 'They remain')} in <code>hermes_patch_plan.json</code>.</div>")
    # COMPLETENESS line — the buyer sees the whole plan reconcile against the machine-readable artefact.
    _n_shown, _n_held = len(_fix_shown), len(_fix_held)
    # NB: this per-site table is rolled up per call site, so its row count is NOT the JSON inventory total.
    # The ONE machine-inventory reconcile claim is made once, above, by fixcards_reconcile_html (_inv_n =
    # len(patch_plan.build(prod)) — the real row count written to hermes_patch_plan.json). Do not re-assert a
    # second, different "(N total)" here or the two claims contradict.
    fixplan_count_html = (
        f"<div class=fpcount><b>{_n_shown} fix-plan {_pl(_n_shown, 'item', 'items')}</b> below"
        + (f", <b>{_n_held}</b> held" if _n_held else "")
        + " — every mapped surface that needs a control appears here, rolled up per call site "
        "(the full machine inventory is <code>hermes_patch_plan.json</code>, reconciled above).</div>")
    # DE-NOISE — collapse the FULL machine inventory (hermes_patch_plan.json) into ONE fix-card per control
    # point + a leverage-ranked "FIX THESE FIRST — top 5". The card view is what a human reads; the per-site
    # tables below stay for the auditor. Grouping only — every JSON row is preserved.
    _CLASS_BADGE = {
        "gate": "<span class='badge fn'>fix now — no control</span>",
        "review": "<span class='badge rw'>review — certify &amp; gate</span>",
        "held": "<span class='badge hv'>held — verify first</span>",
        "informational": "<span class='badge in'>informational — no gate needed</span>"}
    _groups, _top5, _inv_n = _fix_cards(scan)
    fixcards_reconcile_html = (
        f"<div class=fpcount><b>{len(_groups)} fix-{_pl(len(_groups), 'card', 'cards')}</b> below de-noise "
        f"the <b>{_inv_n}-row</b> machine inventory in <code>hermes_patch_plan.json</code> — grouped by the "
        f"single control point each shares. Every row is preserved in the JSON (the Repairer feed); nothing "
        f"is dropped.</div>")
    if _top5:
        _t5 = "".join(
            f"<li><b>{esc(g['control_point'])}</b> — one fix closes <b>{g['count']} "
            f"{_pl(g['count'], 'site', 'sites')}</b> "
            f"<span class=c>({esc(g['capability'])}, severity {g['severity']}; leverage {g['leverage']})</span></li>"
            for g in _top5)
        fixcards_top5_html = (
            "<div class=top5><div class=k>▸ FIX THESE FIRST — top 5 "
            "<span class=c>ranked by leverage = sites-closed × severity</span></div>"
            f"<ol>{_t5}</ol></div>")
    else:
        fixcards_top5_html = ""

    def _card_html(g):
        _locs = g["locations"][:3]
        _more = g["count"] - len(_locs)
        _tail = (f" <span class=more>…and {_more:,} more of this group in "
                 f"<code>hermes_patch_plan.json</code></span>" if _more > 0 else "")
        _covers = ", ".join(f"<span class=mono>{esc(l)}</span>" for l in _locs)
        _proof = ("" if g["fix_class"] == "informational" else
                  f"<div class=fstep><span class=fsn>Step 2 — prove it blocks</span>{esc(g['suggested_test'])}</div>")
        return (
            f"<div class=fixcard>"
            f"<div class=fchead>{_CLASS_BADGE.get(g['fix_class'], '')}"
            f"<b>{esc(g['control_point'])}</b>"
            f"<span class=sites>one fix closes <b>{g['count']} {_pl(g['count'], 'site', 'sites')}</b></span></div>"
            f"<div class=fstep><span class=fsn>Step 1 — the one control</span>{esc(g['control'])}</div>"
            f"{_proof}"
            f"<div class=fccovers>Covers: {_covers}{_tail}</div>"
            f"</div>")
    fixcards_html = "".join(_card_html(g) for g in _groups) or "<div class=more>(none — nothing to plan)</div>"

    # QUANTIFY honestly — the real work each sink demands, and exactly what the Repairer delivers (present
    # tense; the deterministic tier is real today, the AI tier is early access — never overclaimed).
    fix_quantify_html = ("" if not _n_shown else (
        f"<b>{_n_shown} {_pl(_n_shown, 'sink', 'sinks')} in this plan × (write a correct control + write a "
        f"proof it blocks + re-verify closure).</b> The deterministic Repairer delivers each as a reviewed "
        f"diff with the proof attached."))
    # ONE HONEST CALLOUT beside the plan — fact, not fear (Constitution).
    proof_callout_html = f"<div class=proofcall>{esc(_PROOF_CALLOUT)}</div>"
    # MOVE THE VALUE-ANCHOR UP — a compact Repairer anchor beside the FIRST reachable-now finding (the moment
    # of felt difficulty), not only the bottom CTA. Honest present tense + a CTA. Only when a red item exists.
    _has_reach_now = any(it["band"] == "red" for it in _fix_shown)
    repairer_anchor_html = ("" if not _has_reach_now else (
        "<div class=anchor><div class=k>▸ the fix is two jobs — the Repairer does both</div>"
        "<p><b>Writing a control is the easy half; proving it blocks is the half people skip.</b> The "
        "<b>deterministic Repairer does both today on real repos</b>: it applies the control as a reviewed "
        "diff, then <b>re-runs the real attack and proves this sink flips from exploitable to blocked "
        "(RED→PROTECTED), re-verified by the same scanner</b> — human-gated, never auto-fix. The AI-assist "
        "tier is in early access.</p>"
        "<a class=link href=\"https://hermesshield.ai/repairer\">Early access → hermesshield.ai/repairer</a>"
        "</div>"))

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
    # CONTEXT-AWARE install-liability stat + KILL THE INVERTED "0 · Low" GREEN PILL.
    #   * APP  — nobody installs an app, so install-liability is N/A. NEVER a green "0 · Low" badge (that
    #            reads as a clean bill of health). The tile shows "N/A" with a muted app note.
    #   * LIBRARY with >0 inherited — the inherited-rating pill rides the count (Low/Med/High).
    #   * LIBRARY with 0 inherited — the count 0 with NO pill (a rating on an empty set is meaningless), and
    #            crucially NO green "Low" badge on a harmless zero.
    if is_app:
        il_stat_n = "N/A"
        il_pill = '<span class="pill na">app</span>'
        il_stat_h = "nobody installs an app — its risk is what is reachable now, not what it inherits"
    else:
        il_stat_n = f"{install_liab:,}"
        il_pill = f'<span class="pill {band_class}">{band}</span>' if install_liab else ""
        il_stat_h = ("dangerous capability that's harmless here but live once installed — inert here, live "
                     "on install" if install_liab
                     else "no RCE-class capability inherited on install")
    fonts = _font_face_css()
    scan_date = _dt_date.today().isoformat()
    exec_headline = _exec_headline(c)
    exec_verdict = _exec_verdict(c)

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
/* app install-liability pill — muted/neutral, NEVER the green "Low" that reads as a clean bill of health. */
.pill.na{{color:var(--muted);border:1px solid var(--line);background:rgba(234,217,192,.05)}}
/* ---- executive summary block (section 2): one reconciled headline + one verdict, side by side ---- */
.execsum{{background:var(--panel2);border:1px solid var(--line);border-left:4px solid var(--blaze);
border-radius:0 16px 16px 0;padding:20px 26px;margin:24px 0 0}}
.execsum .k{{font-family:var(--mono);font-size:11px;letter-spacing:.14em;text-transform:uppercase;
color:var(--blaze);margin-bottom:10px}}
.execsum .k .c{{color:var(--muted);text-transform:none;letter-spacing:.02em}}
.execsum .exline{{font-family:var(--serif);font-size:clamp(1.15rem,2.4vw,1.5rem);line-height:1.35;
color:var(--cream);font-weight:500}}
.execsum .exverdict{{color:var(--muted);font-size:15px;margin-top:12px;line-height:1.6}}
.execsum .exverdict b{{color:var(--cream)}}
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
h2.ruflag{{color:var(--blaze);border-left:4px solid var(--blaze);padding-left:14px;margin-left:-18px}}
/* AI-suspected band — sky/blue-flagged, advisory, clearly OUTSIDE the deterministic verdict/counts. */
h2.aiflag{{color:var(--sky);border-left:4px solid var(--sky);padding-left:14px;margin-left:-18px}}
h3{{font-family:var(--mono);font-size:11px;text-transform:uppercase;letter-spacing:.1em;
color:var(--apricot);margin:28px 0 6px;font-weight:600}}
h3 .c{{color:var(--faint);font-weight:400;letter-spacing:.02em;text-transform:none;margin-left:8px}}
.tier{{color:var(--muted);font-size:14px;margin:0 0 16px;max-width:78ch;line-height:1.65}}
.tier b{{color:var(--cream);font-weight:600}}
/* TRUNCATION/LAYOUT — every table is its own horizontal-scroll container (display:block + overflow-x:auto,
   the standard responsive trick: internal rows still form a table via anonymous table boxes) so a long mono
   path can never force the whole page to scroll sideways. */
.scroll{{overflow-x:auto;-webkit-overflow-scrolling:touch;max-width:100%}}
table{{border-collapse:collapse;width:100%;font-family:var(--mono);font-size:12.5px;
background:var(--panel);border:1px solid var(--line);border-radius:12px;
display:block;overflow-x:auto;-webkit-overflow-scrolling:touch;max-width:100%}}
td{{padding:11px 14px;border-bottom:1px solid var(--line);vertical-align:top}}
tr:last-child td{{border-bottom:none}}
/* mono paths wrap instead of forcing width — word-break/overflow-wrap:anywhere. */
.mono{{color:var(--cream);overflow-wrap:anywhere;word-break:break-word}}
.ln{{color:var(--blaze)}}.cap{{color:var(--apricot)}}
.sym{{color:var(--muted);overflow-wrap:anywhere;word-break:break-word}}.more{{color:var(--muted);font-style:italic}}
.hd{{color:var(--faint);font-size:10px;text-transform:uppercase;letter-spacing:.09em;font-weight:600;
background:var(--panel2)}}
/* status/tier no longer nowrap — they may wrap on a narrow viewport rather than blow out the row. */
.tier2{{}}.ctrl{{color:var(--cream);line-height:1.5;font-family:var(--sans)}}
.plan{{color:var(--apricot);font-weight:600}}
.badge{{display:inline-block;font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.05em;
text-transform:uppercase;padding:3px 9px;border-radius:999px;white-space:nowrap}}
.badge.ff{{color:var(--heat);border:1px solid rgba(255,67,1,.5);background:rgba(255,67,1,.1)}}
.badge.rv{{color:var(--blaze);border:1px solid rgba(250,125,9,.5);background:rgba(250,125,9,.1)}}
.badge.wt{{color:var(--blaze);border:1px solid rgba(250,125,9,.5);background:rgba(250,125,9,.1)}}
.badge.ru{{color:var(--heat);border:1px solid rgba(255,67,1,.5);background:rgba(255,67,1,.1)}}
.badge.rw{{color:var(--apricot);border:1px solid rgba(255,201,143,.5);background:rgba(255,201,143,.09)}}
/* ---- DE-NOISE fix-card class badges (distinct from the per-site table badges above) ---- */
.badge.fn{{color:var(--heat);border:1px solid rgba(255,67,1,.5);background:rgba(255,67,1,.1)}}
.badge.hv{{color:var(--muted);border:1px solid rgba(160,160,160,.4);background:rgba(160,160,160,.08)}}
.badge.in{{color:var(--sky);border:1px solid rgba(82,189,255,.45);background:rgba(82,189,255,.08)}}
/* ---- fix-row two-step control cell (Step 1 = control, Step 2 = the proof-test) ---- */
.fstep{{margin:0 0 8px}}.fstep:last-child{{margin-bottom:0}}
.fsn{{display:block;font-family:var(--mono);font-size:9.5px;font-weight:600;letter-spacing:.08em;
text-transform:uppercase;color:var(--blaze);margin-bottom:3px}}
.fstep:last-child .fsn{{color:var(--sky)}}
/* ---- the fix plan is THE action — elevate it into a prominent warm card ---- */
.fixwrap{{border:1px solid rgba(250,125,9,.34);border-left:4px solid var(--blaze);
background:linear-gradient(180deg,rgba(250,125,9,.06),rgba(250,125,9,.015));
border-radius:6px 20px 20px 6px;padding:6px 26px 30px;margin:52px 0 0}}
h2.fixh2{{font-size:15px;letter-spacing:.05em;color:var(--cream);border-top:none;padding-top:24px;margin:0 0 6px}}
h2.fixh2 .c{{color:var(--blaze);text-transform:none;letter-spacing:.02em}}
.fixwrap .ctrl{{font-size:13.5px}}
/* ---- the honest proof callout (fact, not fear) ---- */
.proofcall{{background:rgba(82,189,255,.07);border:1px solid rgba(82,189,255,.32);border-left:4px solid var(--sky);
border-radius:0 12px 12px 0;padding:14px 20px;margin:0 0 18px;color:var(--cream);font-size:14.5px;
line-height:1.55;font-weight:500}}
.fpcount{{color:var(--muted);font-size:13px;margin:0 0 14px}}.fpcount b{{color:var(--cream)}}
.fpcount code,.held code{{font-family:var(--mono);color:var(--apricot)}}
/* ---- DE-NOISE: fix cards (one per control point) + top-5 leverage list ---- */
.top5{{background:rgba(250,125,9,.08);border:1px solid rgba(250,125,9,.34);border-left:4px solid var(--blaze);
border-radius:0 12px 12px 0;padding:14px 22px;margin:0 0 20px}}
.top5 .k{{font-weight:700;color:var(--cream);font-size:13px;letter-spacing:.04em;margin:0 0 8px}}
.top5 .k .c{{color:var(--blaze);font-weight:600;letter-spacing:.02em}}
.top5 ol{{margin:0;padding-left:22px}}.top5 li{{color:var(--cream);font-size:14px;line-height:1.7}}
.top5 .c{{color:var(--muted)}}
.fixcards{{display:flex;flex-direction:column;gap:12px;margin:0 0 20px}}
.fixcard{{border:1px solid rgba(250,125,9,.22);border-radius:6px 14px 14px 6px;
background:rgba(250,125,9,.03);padding:12px 18px}}
.fchead{{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:0 0 8px}}
.fchead b{{color:var(--cream);font-size:14.5px}}
.fchead .sites{{margin-left:auto;color:var(--muted);font-size:12.5px}}.fchead .sites b{{color:var(--apricot)}}
.fccovers{{color:var(--muted);font-size:12px;margin:8px 0 0}}
.fccovers .mono{{font-family:var(--mono);color:var(--apricot)}}
.fccovers .more{{color:var(--muted)}}.fccovers code{{font-family:var(--mono);color:var(--apricot)}}
details.fulldetail{{margin:8px 0 0}}details.fulldetail>summary{{cursor:pointer;color:var(--muted);
font-size:13px;padding:6px 0;user-select:none}}details.fulldetail>summary:hover{{color:var(--cream)}}
.held{{color:var(--muted);font-size:13.5px;background:var(--panel);border:1px solid var(--line);
border-radius:12px;padding:14px 18px;margin:18px 0 0;line-height:1.6}}.held b{{color:var(--cream)}}
/* ---- moved-up Repairer value-anchor (beside the first reachable-now finding) ---- */
.anchor{{background:linear-gradient(135deg,rgba(250,125,9,.14),rgba(255,67,1,.05));
border:1px solid rgba(250,125,9,.42);border-radius:16px;padding:20px 24px;margin:18px 0 0}}
.anchor .k{{font-family:var(--mono);font-size:10.5px;letter-spacing:.13em;text-transform:uppercase;
color:var(--blaze);margin-bottom:6px}}
.anchor p{{margin:8px 0 0;color:var(--muted);max-width:80ch;line-height:1.6;font-size:14.5px}}
.anchor b{{color:var(--cream)}}
.anchor .link{{display:inline-block;font-family:var(--mono);font-size:13.5px;color:var(--blaze);
margin-top:12px;font-weight:600}}
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
/* ---- NARROW / MOBILE breakpoint ---- */
@media (max-width:640px){{
  .wrap{{padding:24px 14px 56px}}
  .banner{{flex-direction:column;gap:12px;padding:22px 18px}}
  .banner .icon{{font-size:34px}}
  .stats{{grid-template-columns:1fr 1fr}}
  .plain{{grid-template-columns:1fr}}
  .bar{{grid-template-columns:110px 1fr 42px;gap:8px;font-size:11px}}
  table{{font-size:11.5px}}
  h1{{font-size:1.5rem}}
}}
/* ---- PRINT / PDF — ink-on-white for CISO archiving; drop the dark sunset skin, keep the structure ---- */
@media print{{
  @page{{margin:14mm}}
  html,body{{background:#fff !important;color:#111 !important}}
  .wrap{{max-width:none;padding:0}}
  *{{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
  .banner,.execsum,.verdict,.stat,.pw,.fixwrap,.top5,.fixcard,.anchor,.cta,.note,.proofcall,.held,table{{
    background:#fff !important;border:1px solid #bbb !important;box-shadow:none !important}}
  .banner .head,.banner .icon,h1,h2,h3,.brand,.mono,.stat .n,.execsum .exline,.verdict .v{{color:#111 !important}}
  .banner.red{{border-left:5px solid #b00 !important}}
  .banner.amber{{border-left:5px solid #b45f00 !important}}
  .banner.blue{{border-left:5px solid #04408a !important}}
  .badge,.pill{{border:1px solid #666 !important;color:#111 !important;background:#f0f0f0 !important}}
  .tagline,.tier,.h,.meta,.foot,.execsum .exverdict{{color:#333 !important}}
  a[href]::after{{content:" (" attr(href) ")";font-size:10px;color:#555}}
  details{{display:block}}
  details>summary{{display:none}}
}}
</style></head><body><div class=wrap>
<!-- SECTION 1 — COVER / IDENTITY -->
<div class=mast>
  <div class=brand>HERMES <span class=sh>SHIELD</span></div>
  <div class=sub>excessive-agency scan · OWASP LLM06 · scanned {scan_date} · scanner v{esc(_ver)} · {esc(repo_kind)} repo</div>
</div>

<!-- SECTION 2 — EXECUTIVE SUMMARY (one reconciled headline + one verdict that agree) -->
<div class="banner {b_cls}">
  <div class=icon>{b_icon}</div>
  <div>
    <div class=k>scan verdict · {esc(repo_name)} · {esc(repo_kind)}</div>
    <div class=head>{b_head}</div>
    <div class=bsub>{b_sub}</div>
  </div>
</div>

<div class=execsum>
  <div class=k>▸ Executive summary <span class=c>— one reconciled headline; every number below matches it</span></div>
  <div class=exline>{esc(exec_headline)}</div>
  <div class=exverdict><b>OWASP LLM06 verdict:</b> {esc(exec_verdict)}</div>
</div>

<div class=plain>
  <div class=pw><span class=pk>What we found</span>{pw_found}</div>
  <div class=pw><span class=pk>What's urgent</span>{pw_urgent}</div>
  <div class=pw><span class=pk>What to do</span>{pw_do}</div>
</div>

<!-- SECTION 3 — SEVERITY-FIRST SCOREBOARD -->
<h1>{total_surfaces:,} {_pl(total_surfaces, 'place', 'places')} this code can act &mdash; mapped.</h1>
<div class=tagline>Statically, locally, rated by proven reachability &mdash; your code never leaves this machine.</div>
<div class=meta><b>Repository:</b> <code>{esc(repo_name)}</code> &nbsp;·&nbsp; <b>{files:,}</b> {_pl(files, 'file', 'files')} scanned
&nbsp;·&nbsp; <b>{total_surfaces:,}</b> action-surfaces mapped &nbsp;·&nbsp; static analysis · target code is never
executed · the deterministic core makes no network calls (optional --ai/--deps tiers do — see the docs)</div>

<div class=stats>
  <div class="stat surf"><div class=n>{total_surfaces:,}</div><div class=l>Action-surfaces</div><div class=h>every point the agent can act — the map</div></div>
  <div class="stat inst"><div class=n>{il_stat_n}{il_pill}</div><div class=l>Install-liability</div><div class=h>{il_stat_h}</div></div>
  <div class="stat reach"><div class=n>{reachable:,}</div><div class=l>Reachable now</div><div class=h>already reachable by untrusted input, unguarded — from this repo's own entrypoints</div></div>
  <div class="stat cov"><div class=n>{files:,}</div><div class=l>Files scanned</div><div class=h>{cov_note}</div></div>
</div>

<div class=verdict>
  <div class=k>▸ OWASP LLM06 verdict</div>
  <div class=v>{esc(overall_display)}</div>
  <small>OWASP LLM06 rating: <b>{esc(overall)}</b> · {reachable:,} live {_pl(reachable, 'precondition', 'preconditions')} present ·
  proven-live (we demonstrated a real attack path): {proven:,} · no fully-chained proof-of-concept was run
  beyond those. A clean verdict means <b>not demonstrated exploitable</b> — it is never read as "secure".</small>
</div>

<!-- SECTION 4 — ALREADY REACHABLE BY UNTRUSTED INPUT (unguarded) — start here -->
<h2>▸ Already reachable by untrusted input <span class=c>— Reachable in-repo: unguarded, live now, from this repo's own entrypoints (fix first)</span></h2>
<div class=tier>An untrusted input can reach these dangerous actions with no control in the way, today.</div>
<div class=scroll><table>{rows(live)}</table></div>
{repairer_anchor_html}

{amber_band_html}

{fixed_dest_band_html}

<!-- SECTION 5 — NEEDS A HUMAN TRACE (not proven safe) -->
{reach_unknown_html}

<!-- SECTION 6 — FIX PLAN (de-noised cards + top 5; full per-site rows rolled up) -->
<section class=fixwrap>
<h2 class=fixh2>▸ Fix plan <span class=c>— generated, not applied</span></h2>
<div class=tier>Fix-at-source controls for the findings that need one — <b>every row is two steps</b>: Step 1
the control (the free directional advice), Step 2 the adversarial proof-test that shows it actually blocks.
<b>The scanner plans these; it does not modify your code.</b></div>
{proof_callout_html}
<div class=tier>{fix_quantify_html} The <b>deterministic Repairer does this today on real repos</b>: it applies
the control as a reviewed diff, then <b>re-runs the real attack and proves the sink flips from exploitable
to blocked (RED→PROTECTED), re-verified by the same scanner</b> — human-gated, never auto-fix. The
<b>AI-assist tier is in early access</b>.</div>
{fixcards_reconcile_html}
{fixcards_top5_html}
<h3>Fix cards <span class=c>— one card per control point</span></h3>
<div class=fixcards>{fixcards_html}</div>
<details class=fulldetail><summary>Full per-site fix rows (every call site)</summary>
{fixplan_count_html}
<h3>Fix first — reachable now <span class=c>— {len(_fix_reach)} {_pl(len(_fix_reach), 'item', 'items')} · classified by the same reachable-unguarded rule as the “Reachable in-repo” count above</span></h3>
<table>{_fixhead}{fixplan_reach_html}</table>
{fixplan_amber_block}
{fixplan_runknown_block}
{fixplan_review_block}
{fixplan_wiring_block}
{fixplan_held_block}
</details>
</section>

<div class=cta>
  <div class=k>▸ what happens next</div>
  <p><b>This report is the free Scanner.</b> It finds every action-surface and plans the fix — control plus
  proof-test — for each one.</p>
  <p><b>The Hermes Shield Repairer closes them.</b> The <b>deterministic Repairer works today on real
  repos</b>: it turns each planned control into a reviewed diff, applied only when a human approves, then
  <b>re-runs the real attack and proves the sink flips from exploitable to blocked (RED→PROTECTED),
  re-verified by the same scanner</b>. Never auto-fix. The <b>AI-assist tier is in early access</b>.</p>
  <a class=link href="https://hermesshield.ai/repairer">Join the early-access list → hermesshield.ai/repairer</a>
</div>

<h2>▸ Install-liability <span class=c>— {'N/A for an app — nobody installs an app' if is_app else 'RCE-class capability you inherit on install (proven inert here)'}</span></h2>
<div class=tier>{"<b>This repo is an app, not a library.</b> Nobody installs an app and wires their own untrusted input to it, so install-liability does not apply here — the honest risk is what is <b>reachable now</b> (section 4 above), not what a downloader would inherit. Listed for completeness only." if is_app else "RCE-class (an attacker running their own code on your machine) capabilities that are <b>proven inert here, live on install</b>: not reachable from this repo's own entrypoints today <b>and</b> sitting behind no untrusted ingress or unresolved dispatch, but a live attack surface the moment they're wired into an agent that reads untrusted input. Capped at Med — not a vulnerability in this repo. The fix is wiring-time: gate each capability before you wire untrusted input to it on install — this is not a fix-now list. <b>Sinks we could not prove inert appear under “Reachability unknown” above, not here.</b>"}</div>
<div class=scroll><table>{rows(il)}</table></div>

{review_html}

{ai_html}

<h2>▸ Action-surface map <span class=c>— by capability</span></h2>
<div class=bars>{bars}</div>

<!-- SECTION 7 — METHODOLOGY / SCOPE + HONEST BLIND SPOTS -->
<h2>▸ Methodology, scope &amp; honest blind spots</h2>
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
