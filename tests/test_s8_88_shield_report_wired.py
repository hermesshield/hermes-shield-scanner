"""
test_s8_88_shield_report_wired — the customer/auditor report (Gate #5) is WIRED + honest (ITEM 3 / S8.88).

Locks:
  - the verdict->category map is refreshed to the LIVE vocabulary: UNGUARDED_CRITICAL_LIVE_SINK and
    EXPECTED_GUARD_MISSING now bucket as NO_GATE (the stale map missed them -> dropped to OTHER),
  - the report carries the two mandatory honest caveats VERBATIM,
  - a real scan (scan_hermes --scan) EMITS the customer report md + html under the out-dir (the wiring).
"""
from __future__ import annotations
import sys
from pathlib import Path
from types import SimpleNamespace


from hermes_shield import shield_report as SR  # noqa: E402
from hermes_shield import scan_hermes as SH  # noqa: E402


def _surf(cap, verdict, **kw):
    d = dict(capability=cap, verdict=verdict, context="prod", detection_source="static",
             guard_proof={"status": "none"}, symbol="run", file_path="pkg/x.py",
             line_start=10, sink_line=10, tainted_reachable=True, language="python")
    d.update(kw)
    return SimpleNamespace(**d)


def test_category_refreshed_to_live_vocab():
    # the primary live-critical verdict must bucket NO_GATE (was silently OTHER under the stale map)
    assert SR._category(_surf("code_exec", "UNGUARDED_CRITICAL_LIVE_SINK")) == "NO_GATE"
    assert SR._category(_surf("code_exec", "EXPECTED_GUARD_MISSING")) == "NO_GATE"
    assert SR._category(_surf("code_exec", "GUARD_NOOP_CONFIRMED")) == "FAKE_GATE"
    assert SR._category(_surf("code_exec", "GUARD_FAIL_OPEN_SUSPECT")) == "FAKE_GATE"
    assert SR._category(_surf("code_exec", "NEEDS_CALL_GRAPH")) == "UNPROVEN"


def test_report_carries_honest_caveats_verbatim():
    scan = {"surfaces": [_surf("code_exec", "UNGUARDED_CRITICAL_LIVE_SINK")],
            "files_scanned": 1, "ai_tier_counts": {}}
    md = SR.build_report(scan, "demo")
    # install-liability caveat — never "vulnerability"
    assert "inert here, live on install" in md
    # proven-live caveat — zero is "not demonstrated", never "secure"
    assert "not demonstrated" in md
    assert "never \"secure\"" in md
    # the refreshed category is actually surfaced
    assert "NO control found" in md
    # html renders without error
    assert "Hermes Shield" in SR.build_html(scan, "demo")


def test_html_red_action_sink_drives_red_banner_and_reachable_table():
    """ACTIONS-FIREWALL: a reachable + unguarded HIGH-IMPACT action (email_send) now drives the RED banner
    and appears in the 'Reachable in-repo' table — no longer silently BLUE."""
    scan = {"surfaces": [_surf("email_send", "UNGUARDED_CRITICAL_LIVE_SINK")],
            "files_scanned": 1, "ai_tier_counts": {}}
    html = SR.build_html(scan, "demo")
    assert 'class="banner red"' in html
    assert "Action needed" in html
    # the sink is listed in the reachable table (its capability label is rendered)
    assert "email_send" in html or "Send email" in html


def test_html_amber_action_sink_drives_amber_band_never_blue():
    """ACTIONS-FIREWALL: a reachable + unguarded REVERSIBLE/social action (post) drives the NEW amber
    'Reachable actions — review' band — an amber banner and a dedicated section, never the BLUE all-clear."""
    scan = {"surfaces": [_surf("post", "UNGUARDED_CRITICAL_LIVE_SINK")],
            "files_scanned": 1, "ai_tier_counts": {}}
    html = SR.build_html(scan, "demo")
    assert 'class="banner amber"' in html
    assert 'class="banner blue"' not in html
    assert "Reachable actions — review" in html         # the new band heading
    assert "reversible/social" in html


def test_scan_emits_customer_report(tmp_path):
    target = tmp_path / "mini"
    target.mkdir()
    (target / "app.py").write_text("import os\ndef f(x):\n    os.system(x)\n")
    outdir = tmp_path / "out"
    rc = SH.main(["--scan", "--root", str(target), "--out", str(outdir), "--quiet"])
    assert rc == 0
    md = outdir / "outputs" / "shield_customer_report.md"
    html = outdir / "outputs" / "shield_customer_report.html"
    assert md.exists() and html.exists(), "customer report must be emitted by the wired pipeline"
    body = md.read_text()
    assert "inert here, live on install" in body
    assert "not demonstrated" in body
