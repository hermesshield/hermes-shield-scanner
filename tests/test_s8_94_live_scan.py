#!/usr/bin/env python3
"""
S8.94 — the opt-in `--live` cinematic scan experience.

Locks the two things that matter:
  (A) ADDITIVE ONLY — with --live absent, the scan's stdout is byte-for-byte today's behaviour; and even
      WITH --live, a piped (non-TTY) run leaves stdout identical + clean (the HUD/finale are TTY-only), so
      JSON piping and every existing stdout-reading test/script keep working.
  (B) HONESTY INVARIANTS — the big "surfaces mapped" number is never danger/never red; RED appears in
      exactly one place and only from the DETERMINISTIC reachable-unguarded count; an AI-suspected guess
      can never turn a verdict red; a clean fixture is BLUE ("no live threat proven", never "secure"); the
      collapse funnel only ever narrows (the reachable tally can go DOWN when a guarded candidate is
      filtered out).
  (C) ROBUSTNESS — non-TTY falls back to line-buffered stderr checkpoints with NO cursor codes on stdout;
      the sticky HUD tears down cleanly (cursor restored) and Ctrl-C exits 130.
"""
from __future__ import annotations

import io
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from hermes_shield import install_report as IR
from hermes_shield import live_scan as LV
from hermes_shield import scan_hermes as SH
from hermes_shield import shield_cli


# ---------------------------------------------------------------- helpers

def _surf(cap="code_exec", verdict="UNGUARDED_CRITICAL_LIVE_SINK", source="static",
          reachable=True, **kw):
    d = dict(capability=cap, verdict=verdict, context="prod", detection_source=source,
             tainted_reachable=reachable, file_path="pkg/app.py", line_start=10, sink_line=10,
             symbol="run", language="python", guard_proof={"status": "none"})
    d.update(kw)
    return SimpleNamespace(**d)


def _report(surfaces, files=3, root=None):
    scan = {"surfaces": surfaces, "files_scanned": files}
    rep = IR.build_report(root or Path("."), scan)
    return rep, scan


# ================================================================ (A) additive-only

def _fixture(tmp_path: Path) -> Path:
    fx = tmp_path / "fx"
    fx.mkdir()
    (fx / "app.py").write_text("import os\ndef f(x):\n    os.system(x)\n", encoding="utf-8")
    return fx


def test_default_scan_stdout_unchanged_and_live_is_additive(tmp_path, capsys):
    """capsys => stdout is not a TTY. The --live run must produce the SAME clean stdout as the default run
    (the cinematic HUD/finale are TTY-only); live only ADDS stderr checkpoints."""
    fx = _fixture(tmp_path)
    out = tmp_path / "o"

    assert shield_cli.main(["scan", str(fx), "--out", str(out)]) == 0
    default_out = capsys.readouterr().out

    assert shield_cli.main(["scan", str(fx), "--live", "--out", str(out)]) == 0
    cap = capsys.readouterr()
    live_out, live_err = cap.out, cap.err

    assert live_out == default_out, "--live must not change piped stdout (additive only)"
    assert "\x1b[" not in default_out, "default piped stdout must carry no ANSI/cursor codes"
    assert "\x1b[" not in live_out, "--live piped stdout must stay clean (JSON-safe)"
    assert "[shield-scan" in default_out
    # the live checkpoints go to STDERR, line-buffered, never stdout
    assert "[shield-live]" in live_err


# ================================================================ (B) honesty invariants

def test_verdict_band_thresholds_match_report():
    assert IR.verdict_band(reachable=1, proven=0, install_liab=9)["code"] == "red"
    assert IR.verdict_band(reachable=0, proven=1, install_liab=0)["code"] == "red"
    assert IR.verdict_band(reachable=0, proven=0, install_liab=3)["code"] == "amber"
    assert IR.verdict_band(reachable=0, proven=0, install_liab=0)["code"] == "blue"
    # the canonical head strings the HTML report also renders
    assert IR.verdict_band(1, 0, 0)["head"] == "Action needed"
    assert IR.verdict_band(0, 0, 1)["head"] == "Review before you ship"
    assert IR.verdict_band(0, 0, 0)["head"] == "No live threat proven"


def test_red_only_from_deterministic_reachable_unguarded(tmp_path):
    """A STATIC reachable-unguarded sink -> non_gated_vulnerable == 1 -> RED."""
    rep, scan = _report([_surf(source="static")], root=tmp_path)
    assert rep["non_gated_vulnerable"] == 1
    band = IR.verdict_band(rep["non_gated_vulnerable"], rep["proven_live_poc"],
                           rep["install_liability_rce"])
    assert band["code"] == "red"


def test_ai_suspected_guess_can_never_turn_red_or_amber(tmp_path):
    """The SAME critical shape but detection_source != 'static' is filtered out of the deterministic
    headline: non_gated == 0, install == 0 -> BLUE. An AI guess counts only in the grey needs-review tally."""
    ai = _surf(source="ai_suspected", verdict="AI_SUSPECTED_REVIEW")
    rep, scan = _report([ai], root=tmp_path)
    assert rep["non_gated_vulnerable"] == 0
    band = IR.verdict_band(rep["non_gated_vulnerable"], rep["proven_live_poc"],
                           rep["install_liability_rce"])
    assert band["code"] == "blue"
    # the AI surface DOES show up — but only in the grey "needs review (AI)" tally
    tally = LV.signal_tally(rep, scan)
    assert tally["needs_review"] == 1 and tally["reachable"] == 0
    # and the rendered finale never goes red for it
    buf = io.StringIO()
    LV.render_finale(rep, scan, tmp_path / "o", "0.0-test", stream=buf)
    txt = buf.getvalue()
    assert "NO LIVE THREAT PROVEN" in txt
    assert LV._HEAT not in txt  # no earned-red anywhere (colour is off on a non-TTY buffer anyway)


@pytest.mark.parametrize("cap", ["post", "email_send", "payment", "dm", "blockchain_tx"])
def test_live_red_stream_uses_same_predicate_as_report_non_gated(tmp_path, cap):
    """GUARD-TEAM GAP (invariant #2): guard_attribution writes UNGUARDED_CRITICAL_LIVE_SINK onto ANY
    prod+static+tainted+unguarded CRITICAL_CAPS surface — a BROADER set than install_report._VULN_CAPS.
    The report's non_gated_vulnerable only counts _VULN_CAPS, so an agent-action sink (post/email_send/
    payment/...) that is unguarded resolves the finale to BLUE / 0. The `--live` red stream must NOT flash
    red for it — Act 1 (HUD) and Act 3 (finale) must agree. Both are driven by the ONE shared predicate
    install_report.is_non_gated_vulnerable, so this can never diverge."""
    # a capability outside _VULN_CAPS but which guard_attribution can still stamp UNGUARDED_CRITICAL
    assert cap not in IR._VULN_CAPS
    s = _surf(cap=cap, verdict="UNGUARDED_CRITICAL_LIVE_SINK", source="static", reachable=True)
    rep, scan = _report([s], root=tmp_path)

    # deterministic report: this cap is NOT a non_gated_vulnerable -> BLUE finale
    assert rep["non_gated_vulnerable"] == 0
    band = IR.verdict_band(rep["non_gated_vulnerable"], rep["proven_live_poc"],
                           rep["install_liability_rce"])
    assert band["code"] == "blue"

    # the shared predicate (the SAME one scan_hermes' live stream selects red events with) agrees: no red
    assert IR.is_non_gated_vulnerable(s) is False
    live_events = [x for x in scan["surfaces"] if IR.is_non_gated_vulnerable(x)]
    assert live_events == []

    # and the rendered finale never shows earned-red for it
    buf = io.StringIO()
    LV.render_finale(rep, scan, tmp_path / "o", "0.0-test", stream=buf)
    assert LV._HEAT not in buf.getvalue()


def test_shared_predicate_still_reds_a_genuine_rce_sink(tmp_path):
    """The fix must not over-tighten: a real _VULN_CAPS sink (code_exec) that is static+prod+unguarded
    remains non_gated_vulnerable == 1 and the shared predicate returns True (Act 1 and Act 3 both RED)."""
    s = _surf(cap="code_exec", verdict="UNGUARDED_CRITICAL_LIVE_SINK", source="static", reachable=True)
    rep, scan = _report([s], root=tmp_path)
    assert rep["non_gated_vulnerable"] == 1
    assert IR.is_non_gated_vulnerable(s) is True


def test_big_surfaces_number_is_never_red(tmp_path):
    """Invariant #1: the big 'surfaces mapped' breadth number is orange, never red — even on a RED verdict
    with a large map."""
    surfaces = [_surf(source="static")] + [_surf(cap="post", verdict="READ_ONLY_SURFACE",
                                                 reachable=False, symbol=f"s{i}") for i in range(40)]
    rep, scan = _report(surfaces, root=tmp_path)
    assert rep["non_gated_vulnerable"] == 1  # RED verdict present
    out = _render_collapse_coloured(rep, scan)
    # the 'surfaces mapped' line carries the orange (breadth) colour, never heat-red
    mapped_line = next(ln for ln in out.splitlines() if "surfaces mapped" in ln)
    assert LV._O in mapped_line and LV._HEAT not in mapped_line


def test_red_appears_in_exactly_one_place_in_the_collapse(tmp_path):
    """Invariant #2: on a coloured render, heat-red appears ONLY on the bottom 'reachable AND unguarded'
    funnel line — nowhere else."""
    rep, scan = _report([_surf(source="static")], root=tmp_path)
    out = _render_collapse_coloured(rep, scan)
    red_lines = [ln for ln in out.splitlines() if LV._HEAT in ln]
    assert red_lines, "a RED result must show heat-red at least once"
    assert all("reachable AND unguarded" in ln or "the number that matters" in ln for ln in red_lines)


def test_blue_on_clean_fixture_even_with_a_huge_map(tmp_path):
    """Invariant #4: a clean repo (nothing reachable-unguarded, nothing install-liability) is BLUE, and the
    copy is 'no live threat proven', explicitly NOT a clean bill of health — regardless of map size."""
    clean = [_surf(cap="post", verdict="READ_ONLY_SURFACE", reachable=False, symbol=f"s{i}")
             for i in range(500)]
    rep, scan = _report(clean, root=tmp_path)
    band = IR.verdict_band(rep["non_gated_vulnerable"], rep["proven_live_poc"],
                           rep["install_liability_rce"])
    assert band["code"] == "blue"
    buf = io.StringIO()
    LV.render_finale(rep, scan, tmp_path / "o", "0.0-test", stream=buf)
    txt = buf.getvalue()
    assert "NO LIVE THREAT PROVEN" in txt
    assert "clean bill of health" in txt.lower()
    # a clean collapse never emits heat-red
    assert LV._HEAT not in _render_collapse_coloured(rep, scan)


def test_funnel_only_narrows_and_can_collapse_to_zero(tmp_path):
    """Invariant #5 + 'the counter MUST be able to collapse to 0'. Values are monotonic non-increasing and,
    when a candidate is guarded, the reachable tally strictly DROPS to the unguarded number."""
    # clean -> collapses to 0 at the bottom
    clean_rep, clean_scan = _report(
        [_surf(cap="post", verdict="READ_ONLY_SURFACE", reachable=False, symbol=f"s{i}") for i in range(9)],
        root=tmp_path)
    f0 = LV.funnel(clean_rep, clean_scan)
    vals0 = [v for _, v, _ in f0["stages"]]
    assert vals0 == sorted(vals0, reverse=True)  # non-increasing
    assert f0["unguarded"] == 0                  # collapses to zero

    # a guarded reachable candidate must be visibly filtered: reachable > unguarded (an honest DOWN)
    guarded = SimpleNamespace(**{**_surf().__dict__, "verdict": "PROTECTED_FULL_PATH",
                                 "tainted_reachable": True, "guard_proof": {"status": "proven"},
                                 "symbol": "g"})
    unguarded = _surf(symbol="u")
    rep, scan = _report([guarded, unguarded], root=tmp_path)
    f = LV.funnel(rep, scan)
    assert f["reachable"] > f["unguarded"], "a guarded reachable candidate must drop the reachable tally"
    assert f["guarded"] >= 1


# ================================================================ (C) robustness / accessibility

def test_non_tty_stream_live_no_cursor_codes_and_checkpoints_to_stderr(capsys):
    """Non-TTY: stream_live emits NO sticky HUD / cursor codes to the (non-tty) stdout stream and streams
    line-buffered checkpoints to stderr instead."""
    events = [
        {"phase": "map", "start": True},
        {"phase": "map", "file": "a.py", "count": 1, "files": 1, "surfaces": 1, "new": []},
        {"phase": "map", "done": True, "files": 1, "surfaces": 1},
        {"phase": "reach", "start": True, "total": 1},
        {"phase": "reach", "live": ("code_exec", "a.py", 10)},
        {"phase": "reach", "done": True, "total": 1},
    ]

    def run_fn(progress=None):
        if progress:
            for e in events:
                progress(e)
        return {"surfaces": [], "files_scanned": 1}

    out = io.StringIO()  # a plain buffer: isatty() -> False
    scan = LV.stream_live(run_fn, stream=out)
    assert scan == {"surfaces": [], "files_scanned": 1}
    assert out.getvalue() == "", "non-TTY stdout stream must stay completely clean"
    err = capsys.readouterr().err
    assert "\x1b[" not in err            # checkpoints are plain text, no cursor codes
    assert "[shield-live]" in err        # real checkpoints landed on stderr


def test_render_collapse_and_finale_non_tty_have_no_cursor_codes(tmp_path):
    rep, scan = _report([_surf(source="static")], root=tmp_path)
    for fn in (lambda b: LV.render_collapse(rep, scan, stream=b),
               lambda b: LV.render_finale(rep, scan, tmp_path / "o", "0.0-test", stream=b)):
        buf = io.StringIO()
        fn(buf)
        v = buf.getvalue()
        assert "\x1b[?25" not in v and "\x1b[J" not in v and "\x1b[38" not in v


def test_hud_tears_down_cleanly_restoring_cursor():
    """The sticky region hides the cursor on enter and ALWAYS restores it on leave, flushing any pending
    log lines — so an interrupted scan never leaves a corrupted terminal."""
    class _TtyBuf(io.StringIO):
        def isatty(self):
            return True

    buf = _TtyBuf()
    hud = LV._Hud(buf, colour=False)
    hud.enter()
    hud.log("permanent-line")
    hud.frame(["h1", "h2", "h3", "h4", "h5"])
    hud.leave()
    v = buf.getvalue()
    assert "\x1b[?25l" in v and "\x1b[?25h" in v   # cursor hidden then restored
    assert v.rstrip().endswith("\x1b[?25h") or "\x1b[?25h" in v
    assert "permanent-line" in v                    # the upward log survived teardown


def test_live_ctrl_c_exits_130(tmp_path, monkeypatch, capsys):
    """Ctrl-C during a --live scan tears down and exits 130 with a clear message (never a traceback)."""
    fx = _fixture(tmp_path)

    def boom(*a, **kw):
        raise KeyboardInterrupt()

    monkeypatch.setattr(LV, "stream_live", boom)
    rc = SH.main(["--scan", "--root", str(fx), "--live", "--out", str(tmp_path / "o")])
    assert rc == 130
    assert "scan interrupted" in capsys.readouterr().err


def test_live_quiet_is_one_line_verdict_plus_report(tmp_path, capsys):
    """--live --quiet: exactly one honest verdict line + the report path (default --quiet stays silent).
    The `os.system(x)` fixture is inert here (install-liability), so this is the honest AMBER path."""
    fx = _fixture(tmp_path)
    rc = SH.main(["--scan", "--root", str(fx), "--live", "--quiet", "--out", str(tmp_path / "o")])
    assert rc == 0
    out = capsys.readouterr().out.strip().splitlines()
    assert len(out) == 1
    line = out[0]
    heads = ("ACTION NEEDED", "REVIEW BEFORE YOU SHIP", "NO LIVE THREAT PROVEN")
    assert any(h in line for h in heads)
    assert "reachable & unguarded" in line
    assert "shield_customer_report.html" in line
    # this fixture is inert here -> the honest AMBER verdict
    assert "REVIEW BEFORE YOU SHIP" in line


def test_live_quiet_default_without_live_stays_silent(tmp_path, capsys):
    """Guard the additive contract from the other side: plain --quiet (no --live) prints NOTHING to stdout,
    exactly as today — the one-liner is a --live-only behaviour."""
    fx = _fixture(tmp_path)
    rc = SH.main(["--scan", "--root", str(fx), "--quiet", "--out", str(tmp_path / "o")])
    assert rc == 0
    assert capsys.readouterr().out == ""


# ---------------------------------------------------------------- coloured-render helper

def _render_collapse_coloured(rep, scan):
    """Force a coloured, non-animated collapse render into a buffer so colour-placement invariants can be
    asserted deterministically. Colour is normally TTY-gated, so use a tiny isatty() shim (NO_COLOR unset in
    the test env keeps _use_colour True)."""
    class _TtyBuf(io.StringIO):
        def isatty(self):
            return True
    tbuf = _TtyBuf()
    LV.render_collapse(rep, scan, stream=tbuf, animate=False)
    return tbuf.getvalue()
