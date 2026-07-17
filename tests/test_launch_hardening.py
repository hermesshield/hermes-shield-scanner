"""
test_launch_hardening — launch-hardening + friction pass (presentation, AI fail-loud, PowerShell hint).

Locks:
  - the AI agent backend FAILS LOUD (AIAgentError with a reason), never a silent "" that masquerades as
    "AI ran and found nothing" — while the deterministic core scan still completes (fail-open),
  - the per-tier failure is VISIBLE in the results panel and the customer report,
  - the results panel leads with the MAP (action-surfaces headline), display-maps a "None (...)" rating to
    "No proven-live exploit path" (amber, never green), and never prints a "found nothing" zero-state,
  - the customer HTML leads with action-surfaces and keeps the RAW OWASP string in the caveat line,
  - the Windows open-hint is PowerShell-safe (Invoke-Item, not the cmd-only `start`),
  - the tested honesty phrases survive verbatim.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from hermes_shield import ai_assist, ai_tier, summary
from hermes_shield import scan_hermes as SH
from hermes_shield import shield_report as SR


# ---------------------------------------------------------------- AI tier: fail LOUD, scan fail-open

def test_claude_agent_missing_cli_raises_loud(monkeypatch):
    monkeypatch.setattr(ai_assist.shutil, "which", lambda name: None)
    propose = ai_assist.claude_agent()
    with pytest.raises(ai_assist.AIAgentError) as exc:
        propose("prompt", 5)
    assert "not found" in str(exc.value)


def test_claude_agent_launch_failure_raises_loud(monkeypatch):
    monkeypatch.setattr(ai_assist.shutil, "which", lambda name: "/nonexistent/claude")

    def boom(*a, **kw):
        raise FileNotFoundError("no such file")

    monkeypatch.setattr(ai_assist.subprocess, "run", boom)
    with pytest.raises(ai_assist.AIAgentError) as exc:
        ai_assist.claude_agent()("prompt", 5)
    assert "failed to launch" in str(exc.value)


def test_ai_tier_records_visible_failure_not_silent_zero(tmp_path):
    (tmp_path / "app.py").write_text(
        "import subprocess\n\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n", encoding="utf-8")

    def broken_agent(prompt, timeout):
        raise ai_assist.AIAgentError("claude CLI not found on PATH")

    surfaces = []
    counts = ai_tier.apply(tmp_path, surfaces, budget=5, agent=broken_agent,
                           cache_dir=tmp_path / "out")
    assert counts["ai_status"] == "failed"
    assert "not found" in counts["ai_failure"]
    assert counts["ai_surfaces_added"] == 0


def test_core_scan_completes_when_ai_backend_broken(tmp_path, monkeypatch):
    target = tmp_path / "repo"
    target.mkdir()
    (target / "app.py").write_text("import os\ndef f(x):\n    os.system(x)\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_SHIELD_AI_TIER", "1")
    monkeypatch.delenv("HERMES_SHIELD_AI_TIER_CACHE_ONLY", raising=False)
    monkeypatch.setattr(ai_assist.shutil, "which", lambda name: None)
    scan = SH.run_scan(target, out_dir=tmp_path / "out")
    # the deterministic core completed and still found the static sink
    assert scan["files_scanned"] == 1
    assert any(s.capability == "subprocess_exec" for s in scan["surfaces"])
    # ...and the AI tier failure is recorded, never silent
    assert scan["ai_tier_counts"].get("ai_status") == "failed"
    assert scan["ai_tier_counts"].get("ai_failure")


def _panel(report=None, scan=None, colour=False):
    report = report or {}
    scan = {"files_scanned": 1, "surfaces": [], **(scan or {})}
    return summary.render_results(report, scan, ".", "0.0-test", colour=colour)


def test_summary_shows_ai_tier_failure():
    txt = _panel(scan={"ai_tier_counts": {"ai_status": "failed",
                                          "ai_failure": "claude CLI not found on PATH"}})
    assert "AI tier: FAILED" in txt
    assert "claude CLI not found on PATH" in txt


def test_customer_report_shows_ai_tier_failure():
    scan = {"surfaces": [], "files_scanned": 1,
            "ai_tier_counts": {"ai_status": "failed", "ai_failure": "claude CLI not found on PATH"}}
    md = SR.build_report(scan, "demo")
    assert "AI tier: FAILED" in md


# ---------------------------------------------------------------- results panel: lead with the MAP

def _surf(cap, verdict, **kw):
    d = dict(capability=cap, verdict=verdict, context="prod", detection_source="static",
             guard_proof={"status": "none"}, symbol="run", file_path="pkg/x.py",
             line_start=10, sink_line=10, tainted_reachable=True, language="python")
    d.update(kw)
    return SimpleNamespace(**d)


def test_summary_leads_with_map_headline():
    txt = _panel(report={"non_gated_vulnerable": 2, "install_liability_rce": 17,
                         "install_liability_rating": {"band": "Med"},
                         "overall_rating": "None (no proven-live)"},
                 scan={"surfaces": [object()] * 5})
    assert "5 action-surfaces mapped · 17 install-liability [Med] · 2 reachable-proven" in txt


def test_summary_rating_display_mapped_amber_never_green():
    txt = _panel(report={"overall_rating": "None (no proven-live)"})
    assert "No proven-live exploit path" in txt
    assert "None (no proven-live)" not in txt          # raw string stays in the audit artefacts only
    # honesty caveat survives verbatim
    assert "not demonstrated exploitable — a clean scan is never read as “secure”" in txt
    # amber/neutral, never green
    assert summary._rating_colour("None (no proven-live)") != summary._GRN


def test_summary_zero_state_install_liability():
    txt = _panel(report={"non_gated_vulnerable": 0, "install_liability_rce": 17,
                         "install_liability_rating": {"band": "Med"},
                         "overall_rating": "None (no proven-live)"})
    assert "17 RCE-class surfaces need gating before install — see the report" in txt


def test_summary_zero_zero_still_says_mapped():
    txt = _panel(report={"non_gated_vulnerable": 0, "install_liability_rce": 0,
                         "overall_rating": "None (no proven-live)"},
                 scan={"surfaces": [object()] * 3})
    assert "3 action-surfaces mapped — full map in the report" in txt


# ---------------------------------------------------------------- open-hint: PowerShell-safe

def test_open_hint_powershell_safe(monkeypatch):
    monkeypatch.setattr(summary.sys, "platform", "win32")
    cmd, _note = summary._open_hint("report.html")
    assert cmd == "Invoke-Item report.html"
    assert not cmd.startswith("start")                 # cmd builtin — fails in PowerShell (Win11 default)


# ---------------------------------------------------------------- customer HTML: map first, raw in caveat

def test_html_leads_with_action_surfaces():
    scan = {"surfaces": [_surf("code_exec", "NEEDS_CALL_GRAPH")], "files_scanned": 1,
            "ai_tier_counts": {}}
    html = SR.build_html(scan, "demo")
    # dynamic h1 leads with the map (singular/plural agnostic: "place"/"places")
    assert "this code can act" in html
    # stats grid: action-surfaces card comes before the reachable card
    assert html.index('class="stat surf"') < html.index('class="stat reach"')


def test_html_verdict_display_mapped_raw_in_caveat():
    scan = {"surfaces": [_surf("code_exec", "NEEDS_CALL_GRAPH")], "files_scanned": 1,
            "ai_tier_counts": {}}
    html = SR.build_html(scan, "demo")
    assert "No proven-live exploit path" in html
    assert "None (no proven-live)" in html             # raw OWASP string kept, in the caveat line
    assert "not demonstrated exploitable" in html
