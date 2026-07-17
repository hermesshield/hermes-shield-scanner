"""Regression: AI-suspected surfaces (model GUESSES) must NEVER leak into the DETERMINISTIC headline.

The defect (adversarial review): an ai_suspected surface was run through the SAME deterministic verdict
machinery as static findings, could pick up UNGUARDED_CRITICAL_LIVE_SINK in the shared .verdict field, and
then flip the customer-facing RED banner, inflate the reachable count + coverage %, and feed the fix plan.
The honesty promise is: static = deterministic/provable; AI = advisory, never in the static headline.

This test locks BOTH halves of the fix:
  (A) WRITER — guard_attribution never stamps a deterministic verdict on a non-static surface; it records
      the "AI suggests, engine checks reachability" signal in the SEPARATE advisory field s.ai_reachability
      and leaves .verdict == "AI_SUSPECTED_REVIEW".
  (B) CONSUMERS — install_report / shield_report (_report_model, build_html, _fix_plan_rows) count ONLY
      detection_source == "static", so even a re-stamped AI verdict cannot drive the banner / reachable
      count / coverage / fix plan. The AI surface STILL appears in the dedicated AI-suspected section.
"""
from __future__ import annotations

from hermes_shield import guard_attribution as GA
from hermes_shield import install_report as IR
from hermes_shield import shield_report as SR
from hermes_shield.cross_module import build_graphs
from hermes_shield.models import ActionSurface


# ---------------------------------------------------------------------------------------------------
# (A) WRITER: guard_attribution keeps a model GUESS out of the deterministic .verdict field.
# ---------------------------------------------------------------------------------------------------
def test_guard_attribution_leaves_ai_verdict_advisory(tmp_path):
    """An ai_suspected surface that IS tainted + unguarded (would otherwise be UNGUARDED_CRITICAL_LIVE_SINK)
    keeps .verdict == AI_SUSPECTED_REVIEW; the reachability check lands in the advisory s.ai_reachability."""
    (tmp_path / "unguarded.py").write_text(
        "import subprocess\n"
        "def post_reply(item):\n"
        "    subprocess.run(['post', item])\n")
    graphs = build_graphs(tmp_path, ["unguarded.py"])

    ai = ActionSurface(id="ai::unguarded.py::3", file_path="unguarded.py", line_start=3,
                       capability="post", context="prod", detection_source="ai_suspected",
                       verdict="AI_SUSPECTED_REVIEW")
    ai.tainted_reachable = True

    GA.apply(tmp_path, [ai], graphs)

    # the deterministic verdict field is UNTOUCHED — the model guess stays advisory
    assert ai.verdict == "AI_SUSPECTED_REVIEW"
    assert ai.live_promotion_verdict != "BLOCK"
    # ...but the "engine checks reachability" signal is PRESERVED in the advisory field
    assert ai.ai_reachability, "advisory reachability must be recorded for the AI surface"
    assert ai.ai_reachability["critical_guard_on_path"] == "no"
    assert ai.ai_reachability["would_be_verdict"] == "UNGUARDED_CRITICAL_LIVE_SINK"


def test_guard_attribution_static_surface_still_flagged(tmp_path):
    """Control: the SAME sink as a STATIC surface still gets the deterministic UNGUARDED_CRITICAL verdict —
    the fix removes the AI leak without softening the deterministic core."""
    (tmp_path / "unguarded.py").write_text(
        "import subprocess\n"
        "def post_reply(item):\n"
        "    subprocess.run(['post', item])\n")
    graphs = build_graphs(tmp_path, ["unguarded.py"])
    st = ActionSurface(id="static", file_path="unguarded.py", line_start=3, capability="post",
                       context="prod", detection_source="static")
    st.tainted_reachable = True
    GA.apply(tmp_path, [st], graphs)
    assert st.verdict == "UNGUARDED_CRITICAL_LIVE_SINK"
    assert st.severity_rank == 0


# ---------------------------------------------------------------------------------------------------
# (B) CONSUMERS: a WORST-CASE re-stamped AI verdict still cannot enter the headline.
# ---------------------------------------------------------------------------------------------------
def _static_install_liability():
    """A static RCE-class surface that is inert here (install-liability) — NOT reachable-unguarded. It gives
    the report a stable deterministic baseline (AMBER banner) independent of the AI surface."""
    s = ActionSurface(id="static-il", file_path="pkg/app.py", line_start=10, sink_line=10,
                      symbol="loader", capability="code_exec", context="prod",
                      detection_source="static", verdict="PASS_WITH_RESIDUAL_RISK")
    s.tainted_reachable = False
    return s


def _ai_worst_case():
    """An ai_suspected surface carrying the WORST-CASE deterministic verdict (as if a writer re-stamped it).
    The consumers must still refuse to count it in the headline."""
    s = ActionSurface(id="ai::pkg/evil.py::7", file_path="pkg/evil.py", line_start=7, sink_line=7,
                      symbol="", capability="code_exec", context="prod",
                      detection_source="ai_suspected", verdict="UNGUARDED_CRITICAL_LIVE_SINK")
    s.tainted_reachable = True
    return s


def _scan(surfaces):
    return {"surfaces": surfaces, "files_scanned": 1, "ai_tier_counts": {}}


def test_ai_surface_never_in_deterministic_headline(tmp_path):
    static = _static_install_liability()
    ai = _ai_worst_case()

    scan_off = _scan([static])                 # AI-off baseline
    scan_on = _scan([static, ai])              # AI-on: adds the worst-case AI surface

    ir_off = IR.build_report(tmp_path, scan_off)
    ir_on = IR.build_report(tmp_path, scan_on)

    # 1. the live-threat kicker is not driven by the AI guess
    assert ir_on["non_gated_vulnerable"] == 0
    # 2. install_report headline numbers are IDENTICAL to the AI-off run
    assert ir_on["total_action_surfaces"] == ir_off["total_action_surfaces"]
    assert ir_on["coverage_pct"] == ir_off["coverage_pct"]
    assert ir_on["overall_rating"] == ir_off["overall_rating"]

    # 3. shield_report deterministic model: total + coverage unchanged vs AI-off
    m_off = SR._report_model(scan_off, "demo")
    m_on = SR._report_model(scan_on, "demo")
    assert m_on["total"] == m_off["total"]
    assert m_on["coverage_pct"] == m_off["coverage_pct"]
    assert m_on["no_gate"] == m_off["no_gate"]

    # 4. the RED/AMBER/BLUE banner is NOT red, and is byte-identical to the AI-off banner
    html_off = SR.build_html(scan_off, "demo", root=str(tmp_path))
    html_on = SR.build_html(scan_on, "demo", root=str(tmp_path))
    assert '<div class="banner red">' not in html_on, "AI guess must not flip the banner RED"
    off_cls = html_off.split('<div class="banner ', 1)[1][:5]
    on_cls = html_on.split('<div class="banner ', 1)[1][:5]
    assert off_cls == on_cls
    # the AI surface's file must NOT appear in the deterministic "Reachable in-repo" table
    reachable_table = html_on.split("Reachable in-repo", 1)[1].split("Fix plan", 1)[0]
    assert "pkg/evil.py" not in reachable_table

    # 5. NO fix-plan row is generated for the AI surface
    fixrows = SR._fix_plan_rows(m_on["rows"])
    assert all(fr["file"] != "pkg/evil.py" for fr in fixrows)

    # 6. ...but the AI surface STILL appears in the dedicated AI-suspected review section
    assert any(s.file_path == "pkg/evil.py" for s in m_on["ai_rows"])
    md_on = SR.build_report(scan_on, "demo", root=str(tmp_path))
    ai_section = md_on.split("AI-suspected surfaces", 1)[1]
    assert "pkg/evil.py" in ai_section, "the AI surface must remain visible in its own review section"


def test_patch_plan_excludes_ai_surface():
    from hermes_shield import patch_plan as PP
    ai = _ai_worst_case()
    items = PP.build([ai])
    assert items == [], "an AI-suspected surface must never feed the deterministic patch plan"
