"""Lock the RENDERER contract: a backend FAILURE in either optional AI tier is shown CONSISTENTLY on every
customer/operator surface, and is NEVER conflated with a genuine nothing-found.

The per-file `--ai` tier and the `--ai-deep` finder already record a fail-loud status
(ai_tier_counts.ai_status="failed" / ai_finder.ai_finder_status="failed"). Fable found three RENDERERS that
still read that failure as "nothing found":

  1. build_html (shield_report) — the customer HTML report (summary.py points buyers to it) printed
     "(none — AI tier off or nothing found)" even when the AI tier FAILED.
  2. the non-TTY / piped / CI console (scan_hermes) — had a finder line but NO per-file `--ai` line, so a
     failed per-file tier was invisible off a TTY.
  3. hermes_shield_report.json (install_report.build_report) — carried no AI-tier status at all, so a
     machine consumer could not see a failure.

These tests lock all three PLUS the honesty invariant: a tier that RAN and found zero surfaces still reads
as nothing-found (status "ok"), never FAILED, everywhere. All backends are synthetic — no CLI is launched.
"""
from __future__ import annotations

from hermes_shield import install_report as IR
from hermes_shield import scan_hermes as SH
from hermes_shield import shield_report as SR
from hermes_shield.models import ActionSurface


_REFUSAL = ("API Error: safeguards flagged this message as violating our usage policies. Claude Code can't "
            "respond to this request. https://www.anthropic.com/legal/aup")


def _static_surface():
    """One static, inert RCE-class surface so the report has a stable deterministic baseline to render."""
    s = ActionSurface(id="static-il", file_path="pkg/app.py", line_start=10, sink_line=10,
                      symbol="loader", capability="code_exec", context="prod",
                      detection_source="static", verdict="PASS_WITH_RESIDUAL_RISK")
    s.tainted_reachable = False
    return s


def _scan(ai_tier_counts=None, ai_finder=None, ai_surfaces=None):
    surfaces = [_static_surface()] + list(ai_surfaces or [])
    scan = {"surfaces": surfaces, "files_scanned": 1, "ai_tier_counts": ai_tier_counts or {}}
    if ai_finder is not None:
        scan["ai_finder"] = ai_finder
    return scan


# ---------------------------------------------------------------------------------------------------
# ai_tier_health — the shared single source of truth (never conflate FAILURE with nothing-found)
# ---------------------------------------------------------------------------------------------------
def test_ai_tier_health_per_file_failure():
    h = IR.ai_tier_health(_scan(ai_tier_counts={"ai_status": "failed", "ai_failure": _REFUSAL}))
    assert h["per_file_status"] == "failed"
    assert h["any_failed"] is True
    assert "per-file --ai tier" in h["failure_reason"] and "usage policies" in h["failure_reason"]


def test_ai_tier_health_finder_failure():
    h = IR.ai_tier_health(_scan(ai_finder={"ai_finder_status": "failed", "ai_finder_error": "backend absent"}))
    assert h["finder_status"] == "failed"
    assert h["any_failed"] is True
    assert "--ai-deep finder" in h["failure_reason"]


def test_ai_tier_health_genuine_nothing_found_is_ok_not_failed():
    # tier RAN (ai_calls>0) and found zero surfaces -> "ok", NEVER "failed".
    h = IR.ai_tier_health(_scan(ai_tier_counts={"ai_status": "ok", "ai_calls": 2, "ai_surfaces_added": 0}))
    assert h["per_file_status"] == "ok"
    assert h["any_failed"] is False
    assert h["failure_reason"] is None


def test_ai_tier_health_off_when_no_tier_ran():
    h = IR.ai_tier_health(_scan())
    assert h["per_file_status"] == "off" and h["finder_status"] == "off"
    assert h["any_failed"] is False


# ---------------------------------------------------------------------------------------------------
# (1) HTML customer report — a FAILED tier shows a visible banner, not "(none — nothing found)"
# ---------------------------------------------------------------------------------------------------
def test_html_shows_failed_banner_not_none(tmp_path):
    scan = _scan(ai_tier_counts={"ai_status": "failed", "ai_failure": _REFUSAL})
    html = SR.build_html(scan, "demo", root=str(tmp_path))
    assert "AI tier: FAILED" in html
    assert "usage policies" in html
    # the misleading empty-state line must NOT appear when the tier FAILED
    assert "AI tier off or nothing found" not in html


def test_html_finder_failure_shows_failed_banner(tmp_path):
    scan = _scan(ai_finder={"ai_finder_status": "failed", "ai_finder_error": "claude CLI not found"})
    html = SR.build_html(scan, "demo", root=str(tmp_path))
    assert "AI tier: FAILED" in html
    assert "claude CLI not found" in html
    assert "AI tier off or nothing found" not in html


def test_html_genuine_nothing_found_reads_as_nothing(tmp_path):
    scan = _scan(ai_tier_counts={"ai_status": "ok", "ai_calls": 1, "ai_surfaces_added": 0})
    html = SR.build_html(scan, "demo", root=str(tmp_path))
    assert "AI tier: FAILED" not in html
    assert "AI tier off or nothing found" in html


# ---------------------------------------------------------------------------------------------------
# (1b) MD customer report — same guard, mirrored
# ---------------------------------------------------------------------------------------------------
def test_md_shows_failed_banner_not_none(tmp_path):
    scan = _scan(ai_tier_counts={"ai_status": "failed", "ai_failure": _REFUSAL})
    md = SR.build_report(scan, "demo", root=str(tmp_path))
    assert "AI tier: FAILED" in md
    assert "AI tier off or nothing found" not in md


def test_md_genuine_nothing_found_reads_as_nothing(tmp_path):
    scan = _scan(ai_tier_counts={"ai_status": "ok", "ai_calls": 1, "ai_surfaces_added": 0})
    md = SR.build_report(scan, "demo", root=str(tmp_path))
    assert "AI tier: FAILED" not in md
    assert "AI tier off or nothing found" in md


# ---------------------------------------------------------------------------------------------------
# (2) non-TTY / piped / CI console — a per-file FAILED line, mirroring the finder line
# ---------------------------------------------------------------------------------------------------
def test_console_shows_per_file_failed_line():
    lines = SH._ai_tier_console_lines(_scan(ai_tier_counts={"ai_status": "failed", "ai_failure": _REFUSAL}))
    assert any(l.startswith("  AI tier (--ai): FAILED") for l in lines)


def test_console_shows_finder_failed_line():
    lines = SH._ai_tier_console_lines(_scan(ai_finder={"ai_finder_status": "failed",
                                                        "ai_finder_error": "backend absent"}))
    assert any("AI finder: FAILED" in l for l in lines)


def test_console_genuine_nothing_found_is_ok_line_not_failed():
    lines = SH._ai_tier_console_lines(
        _scan(ai_tier_counts={"ai_status": "ok", "ai_calls": 2, "ai_surfaces_added": 0}))
    assert any(l.startswith("  AI tier (--ai): ok") for l in lines)
    assert not any("FAILED" in l for l in lines)


def test_console_silent_when_no_ai_tier_ran():
    assert SH._ai_tier_console_lines(_scan()) == []


# ---------------------------------------------------------------------------------------------------
# (3) hermes_shield_report.json — the exact object serialised carries the failed status
# ---------------------------------------------------------------------------------------------------
def test_json_report_carries_failed_status(tmp_path):
    scan = _scan(ai_tier_counts={"ai_status": "failed", "ai_failure": _REFUSAL},
                 ai_finder={"ai_finder_status": "failed", "ai_finder_error": "backend absent"})
    report = IR.build_report(tmp_path, scan)
    assert "ai_tier" in report
    assert report["ai_tier"]["per_file_status"] == "failed"
    assert report["ai_tier"]["finder_status"] == "failed"
    assert report["ai_tier"]["any_failed"] is True


def test_json_report_genuine_nothing_found_is_ok(tmp_path):
    scan = _scan(ai_tier_counts={"ai_status": "ok", "ai_calls": 1, "ai_surfaces_added": 0})
    report = IR.build_report(tmp_path, scan)
    assert report["ai_tier"]["per_file_status"] == "ok"
    assert report["ai_tier"]["any_failed"] is False
    # AI-suspected advisory data must never enter the deterministic counts
    assert report["non_gated_vulnerable"] == 0


def test_json_report_ai_tier_off_by_default(tmp_path):
    report = IR.build_report(tmp_path, _scan())
    assert report["ai_tier"]["per_file_status"] == "off"
    assert report["ai_tier"]["finder_status"] == "off"


# ---------------------------------------------------------------------------------------------------
# mixed: finder FAILED while the per-file tier found a surface -> banner AND the row both render
# ---------------------------------------------------------------------------------------------------
def test_html_failed_banner_and_surviving_rows_coexist(tmp_path):
    ai = ActionSurface(id="ai::pkg/x.py::7", file_path="pkg/x.py", line_start=7, sink_line=7,
                       symbol="", capability="code_exec", context="prod",
                       detection_source="ai_suspected", verdict="AI_SUSPECTED_REVIEW")
    scan = _scan(ai_tier_counts={"ai_status": "ok", "ai_calls": 1, "ai_surfaces_added": 1},
                 ai_finder={"ai_finder_status": "failed", "ai_finder_error": "backend absent"},
                 ai_surfaces=[ai])
    html = SR.build_html(scan, "demo", root=str(tmp_path))
    assert "AI tier: FAILED" in html          # the finder failure is shown
    assert "pkg/x.py" in html                 # the per-file survivor is still rendered
    assert "AI tier off or nothing found" not in html
