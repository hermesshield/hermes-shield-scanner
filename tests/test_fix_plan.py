"""
test_fix_plan — the "Fix plan — generated, not applied" section + remediation dictionary.

Locks the guarantees the memo promised:
  1. the remediation dictionary maps each RCE-class capability to a SPECIFIC (non-generic) fix-at-source
     control, in the real capability vocabulary — no product-internal lane jargon;
  2. the report fix-plan is scoped HARD to NO_GATE + FAKE_GATE only (never UNPROVEN / GATE_UNVERIFIED);
  3. every fix-plan item's status is exactly "PLANNED — not applied";
  4. install-liability guidance is wiring-time and NEVER calls the surface a vulnerability or claims
     auto-fix.
"""
from __future__ import annotations
from types import SimpleNamespace

from hermes_shield import patch_plan as PP  # noqa: E402
from hermes_shield import shield_report as SR  # noqa: E402


def _surf(cap, **kw):
    d = dict(capability=cap, verdict="UNGUARDED_CRITICAL_LIVE_SINK", context="prod",
             detection_source="static", guard_proof={"status": "none"}, symbol="run",
             file_path="pkg/x.py", line_start=10, sink_line=10, tainted_reachable=True,
             language="python")
    d.update(kw)
    return SimpleNamespace(**d)


# ---- 1. remediation dictionary: specific, non-generic, real vocabulary ----

_SPECIFIC = {
    "code_exec": "ast.literal_eval",
    "subprocess_exec": "shell=False",
    "deserialize": "safe_load",
    "ssti": "autoescape",
    "secret_exfil": "egress allowlist",
    "tool_invoke": "final-action gate",
    "external_write": "destination allowlist",
    "file_delete": "confine deletes",
}


def test_rce_caps_map_to_specific_controls():
    for cap, signature in _SPECIFIC.items():
        control = PP.recommended_control(cap)
        # each mapped cap yields a control distinct from the generic fallback...
        assert control != PP._FALLBACK, f"{cap} fell through to the generic fallback"
        # ...and contains its concrete, fix-at-source signature phrase
        assert signature.lower() in control.lower(), f"{cap} control missing '{signature}': {control}"


def test_unknown_cap_uses_specific_fallback_not_jargon():
    fb = PP.recommended_control("some_unknown_capability")
    assert fb == PP._FALLBACK
    # the fallback is still actionable (kill-switch + human gate), not a shrug
    assert "kill-switch" in fb.lower() and "human-approval" in fb.lower()


def test_no_internal_lane_jargon_in_customer_output():
    # the old dict was keyed on Hermes lanes (post/reply/telegram_send) with "mock-lane" test hints
    for cap in ("code_exec", "subprocess_exec", "deserialize", "external_write"):
        assert "mock-lane" not in PP._suggested_test(cap)
        assert "lane" not in PP.recommended_control(cap).lower()


# ---- 2. scope: COMPLETE plan (reconciles with hermes_patch_plan.json), honestly tiered ----
# The buyer must see the WHOLE plan. Only a PROVEN-protected verdict is dropped (patch_plan.build skips
# exactly those too). Everything else is surfaced at its real tier — with two honesty rules:
#   * UNPROVEN / GATE_UNVERIFIED are HELD: counted for completeness, but never turned into a fix instruction
#     (a control may already be present / reachability unproven — we never tell you to change protected code);
#   * a genuine review finding (e.g. NEEDS_CERTIFICATION) is SHOWN, not silently dropped.

def test_fix_plan_is_complete_and_honestly_tiered():
    rows = [
        (_surf("code_exec"), "NO_GATE"),                                           # reachable -> red (shown)
        (_surf("subprocess_exec", verdict="GUARD_NOOP_CONFIRMED"), "FAKE_GATE"),    # fake gate  (shown)
        (_surf("dashboard_mutation", verdict="NEEDS_CERTIFICATION",
               tainted_reachable=False), "OTHER"),                                  # review     (shown)
        (_surf("deserialize", verdict="CALLER_GUARDED_NOT_PROVEN"), "UNPROVEN"),    # HELD (counted)
        (_surf("ssti", verdict="PROTECTED_BY_REVIEWED_ENTRYPOINT"), "GATE_UNVERIFIED"),  # HELD (counted)
        (_surf("code_exec", verdict="PROTECTED_FULL_PATH",
               file_path="pkg/safe.py"), "GATE_UNVERIFIED"),                        # PROTECTED -> dropped
    ]
    out = SR._fix_plan_rows(rows)
    shown = [it for it in out if it["band"] != "held"]
    held = [it for it in out if it["band"] == "held"]

    # PROTECTED verdict is the ONLY thing dropped (matches patch_plan.build's skip set)
    assert len(out) == 5, "every non-protected surface must appear (shown or held) — completeness"
    assert all("safe.py" != it["file"] for it in out), "a proven-protected verdict is never surfaced"

    # shown findings carry their real, honest tier — the review finding is NOT dropped
    shown_caps = {it["capability"] for it in shown}
    assert shown_caps == {"code_exec", "subprocess_exec", "dashboard_mutation"}
    review = next(it for it in shown if it["capability"] == "dashboard_mutation")
    assert review["band"] == "review" and "certify" in review["tier"].lower()

    # UNPROVEN / GATE_UNVERIFIED are HELD — counted, but never a fix instruction
    assert {it["capability"] for it in held} == {"deserialize", "ssti"}


# ---- 3. status string is exact ----

def test_every_fix_plan_item_is_planned_not_applied():
    rows = [(_surf("code_exec"), "NO_GATE"), (_surf("subprocess_exec"), "FAKE_GATE")]
    out = SR._fix_plan_rows(rows)
    assert out, "expected fix-plan items"
    for it in out:
        assert it["status"] == "PLANNED — not applied"
        assert it["tier"] == "reachable-in-repo"
        # each carries a concrete control + human-readable capability label
        assert it["recommended_control"] and it["recommended_control"] != PP._FALLBACK
        assert it["cap_label"]


# ---- 4. install-liability guidance is wiring-time, never vulnerability / auto-fix ----

def test_install_liability_guidance_is_wiring_time_only():
    for cap in ("code_exec", "subprocess_exec", "deserialize", "ssti", "secret_exfil"):
        g = PP.wiring_control(cap).lower()
        assert "wire" in g, f"{cap} wiring guidance missing wiring language: {g}"
        assert "vulnerab" not in g, f"{cap} wiring guidance wrongly calls it a vulnerability"
        assert "auto-fix" not in g, f"{cap} wiring guidance wrongly implies auto-fix"


# ---- render smoke: the section is present + honest in both formats ----

def test_report_renders_fix_plan_section_in_both_formats():
    scan = {"surfaces": [_surf("code_exec"), _surf("subprocess_exec", file_path="pkg/tools.py")],
            "files_scanned": 2, "ai_tier_counts": {}}
    md = SR.build_report(scan, "demo")
    html = SR.build_html(scan, "demo")
    for doc in (md, html):
        assert "Fix plan" in doc and "generated, not applied" in doc
        assert "PLANNED — not applied" in doc
        # honesty: plans, does not modify code; repairer is human-gated, never auto-fix
        assert "does not modify your code" in doc
        assert "never" in doc and "auto-fix" in doc          # "…under a human gate — never auto-fix"
        # a real fix-at-source control is rendered
        assert "ast.literal_eval" in doc


# ---- 5. RED / AMBER / WIRING partition — the fix-plan tier reuses the SHARED predicates ----
# Regression guard for the confirmed cross-surface gap: a reachable AMBER social action (post/reply/like)
# carrying UNGUARDED_CRITICAL_LIVE_SINK must NOT be shown in the RED "fix first — reachable now" tier (the
# deterministic banner + red reachable table call it amber). The bare-verdict test used to over-state it.

from hermes_shield import install_report as IR  # noqa: E402


def test_fix_plan_band_reuses_shared_predicates_not_bare_verdict():
    red = _surf("payment")     # RED band cap  (_VULN_CAPS)  -> is_non_gated_vulnerable
    amber = _surf("post")      # AMBER band cap (_AMBER_ACTION_CAPS) -> is_reachable_amber_action
    # both carry the SAME verdict UNGUARDED_CRITICAL_LIVE_SINK — the bare-verdict test could not tell them apart
    assert red.verdict == amber.verdict == "UNGUARDED_CRITICAL_LIVE_SINK"
    out = {it["capability"]: it for it in SR._fix_plan_rows([(red, "NO_GATE"), (amber, "NO_GATE")])}

    # RED: high-impact action -> fix-first, agreeing with the shared predicate
    assert IR.is_non_gated_vulnerable(red) is True
    assert out["payment"]["band"] == "red"
    assert out["payment"]["tier"] == "reachable-in-repo"

    # AMBER: reversible/social action -> reachable-action review, NEVER the red fix-first tier
    assert IR.is_reachable_amber_action(amber) is True
    assert IR.is_non_gated_vulnerable(amber) is False
    assert out["post"]["band"] == "amber"
    assert out["post"]["tier"] != "reachable-in-repo"
    assert "review" in out["post"]["tier"].lower()


def test_html_amber_action_routed_to_review_not_red_fix_first():
    """The exact contradiction closed: an amber `post` sink must NOT render in the red 'fix first' table."""
    scan = {"surfaces": [_surf("post")], "files_scanned": 1, "ai_tier_counts": {}}
    html = SR.build_html(scan, "demo")
    # the red fix-first table has NOTHING to fix first — the amber action is not red
    assert "nothing reachable-unguarded to fix first" in html
    assert "badge ff" not in html          # no red fix-first badge span is emitted
    # it is routed to the amber fix-plan review section instead
    assert "badge rv" in html
    assert "Reachable actions — review before you ship" in html


def test_patch_plan_block_flag_honours_red_amber_partition():
    """The Repairer queue (hermes_patch_plan.json) block flag must match the report: a RED action blocks
    live promotion; a reachable AMBER action is review-before-ship and is NEVER block_live_promotion."""
    def _pp(cap, **kw):
        d = dict(id="s1", capability=cap, verdict="UNGUARDED_CRITICAL_LIVE_SINK", context="prod",
                 detection_source="static", file_path="pkg/x.py", line_start=10, risk_level="HIGH",
                 live_capable=True, guards=SimpleNamespace(kill_switch=False), tainted_reachable=True,
                 language="python")
        d.update(kw)
        return SimpleNamespace(**d)

    red = PP.build([_pp("payment")])
    amber = PP.build([_pp("post")])
    assert red and red[0].block_live_promotion is True     # high-impact -> red-equivalent hard block
    assert amber and amber[0].block_live_promotion is False  # reversible/social -> review, never red-block
    # both still require human approval (nothing is silently dropped)
    assert red[0].human_approval_required and amber[0].human_approval_required


def test_patch_plan_explicit_hard_block_verdicts_still_block():
    """The red/amber partition must NOT weaken the explicit hard-block verdicts (BLOCK_LIVE_PROMOTION,
    GUARD_LOST) — those keep blocking regardless of capability band."""
    def _pp(cap, verdict, **kw):
        d = dict(id="s1", capability=cap, verdict=verdict, context="prod", detection_source="static",
                 file_path="pkg/x.py", line_start=10, risk_level="HIGH", live_capable=True,
                 guards=SimpleNamespace(kill_switch=False), tainted_reachable=True, language="python")
        d.update(kw)
        return SimpleNamespace(**d)
    for v in ("BLOCK_LIVE_PROMOTION", "GUARD_LOST"):
        items = PP.build([_pp("post", v)])   # even an amber cap under a hard-block verdict blocks
        assert items and items[0].block_live_promotion is True
