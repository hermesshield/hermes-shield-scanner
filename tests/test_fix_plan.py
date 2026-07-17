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


# ---- 2. scope: NO_GATE + FAKE_GATE only ----

def test_fix_plan_scope_is_no_gate_and_fake_gate_only():
    rows = [
        (_surf("code_exec"), "NO_GATE"),
        (_surf("subprocess_exec"), "FAKE_GATE"),
        (_surf("deserialize"), "UNPROVEN"),        # must be excluded
        (_surf("ssti"), "GATE_UNVERIFIED"),        # must be excluded
        (_surf("tool_invoke"), "OTHER"),           # must be excluded
    ]
    out = SR._fix_plan_rows(rows)
    caps = {it["capability"] for it in out}
    assert caps == {"code_exec", "subprocess_exec"}
    # the excluded categories never leak a suggestion
    assert "deserialize" not in caps and "ssti" not in caps and "tool_invoke" not in caps


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
