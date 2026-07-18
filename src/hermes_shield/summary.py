#!/usr/bin/env python3
"""Hermes Shield — live scan progress + results panel (S8.92).

Two jobs, both cosmetic (they never change the scan or its numbers):
  1. run_with_progress() — while the scan runs (in a worker thread) show an animated spinner cycling the
     REAL pipeline phases + elapsed time, so a scan *feels* like work is happening.
  2. render_results() — after the scan, print a boxed, colour-coded results panel (files, action surfaces,
     the two-tier risk model, OWASP verdict) and a clear "report written → <paths>" pointer, so results
     visibly LAND instead of scrolling past as a one-line dict.

Honesty: the phase labels name the real stages the scanner performs; every number shown comes straight
from the real report. Falls back to plain output when piped / NO_COLOR / non-TTY, so scripts stay clean.
"""
from __future__ import annotations
import itertools
import os
import sys
import threading
import time
from pathlib import Path

_O = "\033[38;5;208m"     # orange (brand)
_A = "\033[38;5;215m"     # amber
_GRN = "\033[38;5;71m"
_RED = "\033[38;5;203m"
_YEL = "\033[38;5;214m"
_BLU = "\033[38;5;74m"
_GRY = "\033[38;5;245m"
_DIM = "\033[38;5;240m"
_B = "\033[1m"
_R = "\033[0m"


def _open_hint(path: str):
    """OS-aware 'open this report' hint. macOS -> `open`, WSL -> `explorer.exe` (opens on the Windows side),
    other Linux -> `xdg-open`, Windows -> `Invoke-Item` (works in PowerShell, the Win11 default shell —
    `start` is a cmd builtin that fails there). Never prints a wrong-OS instruction; falls back to a
    neutral hint if the platform can't be determined."""
    plat = sys.platform
    if plat == "darwin":
        return f"open {path}", ""
    if plat.startswith("win"):
        return f"Invoke-Item {path}", ""
    if plat.startswith("linux"):
        try:
            if "microsoft" in Path("/proc/version").read_text(encoding="utf-8", errors="ignore").lower():
                return f"explorer.exe {path}", "   (WSL → Windows)"
        except Exception:
            pass
        return f"xdg-open {path}", ""
    return path, "   (open in your browser)"


def _colour(stream) -> bool:
    if os.getenv("NO_COLOR") or os.getenv("HERMES_SHIELD_NO_BANNER"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def phases_for(tiers: dict) -> list[str]:
    p = ["Mapping action surfaces", "Tracing reachability", "Attributing guards"]
    if tiers.get("ai"):
        p.append("Running AI recall tier")
    if tiers.get("semgrep"):
        p.append("Running semgrep comparator")
    if tiers.get("deps"):
        p.append("Scanning inherited dependencies")
    p.append("Rating against OWASP LLM06")
    return p


def run_with_progress(fn, phases: list[str], stream=None):
    """Run fn() in a worker thread; animate a spinner over `phases` until it returns. Returns fn()'s value
    (re-raises its exception). No TTY / NO_COLOR -> just call fn() plainly. Never leaves the cursor dirty."""
    stream = stream or sys.stdout
    if not _colour(stream):
        return fn()

    box: dict = {}

    def worker():
        try:
            box["v"] = fn()
        except BaseException as e:  # capture EVERYTHING so a scan error still tidies the line
            box["e"] = e

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    spin = itertools.cycle("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
    start = time.time()
    dwell, idx, last = 1.1, 0, start
    try:
        stream.write("\033[?25l")  # hide cursor
        while t.is_alive():
            now = time.time()
            if now - last >= dwell and idx < len(phases) - 1:
                idx += 1
                last = now
            el = f"{now - start:4.1f}s"
            line = f"  {_O}{next(spin)}{_R} {_A}{phases[idx]}{_R} {_DIM}…{_R}  {_GRY}{el}{_R}"
            stream.write("\r\033[K" + line)
            stream.flush()
            time.sleep(0.08)
    finally:
        t.join()
        stream.write("\r\033[K\033[?25h")  # clear line, restore cursor
        stream.flush()
    if "e" in box:
        raise box["e"]
    return box.get("v")


def _band_colour(band: str) -> str:
    return {"Low": _GRN, "Med": _YEL, "High": _RED}.get(band, _GRY)


def _rating_colour(rating: str) -> str:
    r = (rating or "").lower()
    if "none" in r:
        return _A     # AMBER/neutral, never green — green reads "all-clear", which a scan never asserts
    if "high" in r or "critical" in r:
        return _RED
    if "med" in r:
        return _YEL
    return _A


def render_results(report: dict, scan: dict, out_dir, version: str, colour: bool = True) -> str:
    """Boxed results panel + report-location pointer. Pure string; caller decides where to print it."""
    def c(code, s):
        return f"{code}{s}{_R}" if colour else str(s)

    files = scan.get("files_scanned", 0)
    surfaces = len(scan.get("surfaces", []))
    cov = report.get("coverage_pct", "")
    reach = report.get("non_gated_vulnerable", 0)
    il = report.get("install_liability_rce", 0)
    # reachable AMBER band: reversible/social actions + fixed-destination sends demoted on proven config/
    # constant destination. These are reachable + unguarded (never BLUE); the HTML report bands the repo
    # AMBER on them, so the default TTY panel must surface them too — otherwise an amber-only repo reads
    # "0 reachable" in the terminal while the report says AMBER.
    amber_actions = report.get("reachable_amber_actions", 0)
    fixed_dest = report.get("reachable_fixed_dest_review", 0)
    band = (report.get("install_liability_rating") or {}).get("band", "")
    rating = report.get("overall_rating", "")
    target = os.path.basename(str(report.get("root", "")) or scan.get("root", "")) or "target"
    dep = scan.get("dep_scan") or {}
    dep_il = dep.get("inherited_install_liability")

    reach_c = _GRN if reach == 0 else _RED
    W = 60
    L = []
    L.append("")
    bar = "✓ SCAN COMPLETE"
    ver = f"HERMES SHIELD v{version}"
    pad = max(1, W - 2 - len(bar) - len(ver))
    L.append("  " + c(_GRN, "╭─ ") + c(_O + _B, bar) + " " + c(_GRN, "─" * pad) + " " + c(_DIM, ver) + c(_GRN, " ─╮"))
    L.append("")
    # LAUNCH REFRAME: lead with the MAP, not the verdict — the map is the scan's primary product.
    # Presentation only; every number comes straight from the real report (numbers never change here).
    band_sfx = f" [{band}]" if band else ""
    L.append("  " + c(_B, f"{surfaces} action-surfaces mapped") + c(_DIM, " · ") +
             c(_A + _B, f"{il} install-liability{band_sfx}") + c(_DIM, " · ") +
             c((_RED if reach else _GRY) + _B, f"{reach} reachable-proven"))
    L.append("")
    # left-aligned rows — labels ljust'd on the PLAIN text before colour, so alignment can never drift
    def row(label, value_segs, note=""):
        lab = label.ljust(13)
        line = "    " + c(_GRY, lab)
        if note:
            line += c(_DIM, note.ljust(15))
        line += "".join(c(code, txt) for txt, code in value_segs)
        return line
    L.append(row("Target", [(target, _A)]))
    L.append(row("Scanned", [(f"{files} files", _B), (f"   ·   {cov}% coverage" if cov != "" else "", _DIM)]))
    L.append(row("Surfaces", [(f"{surfaces} action-surfaces mapped", _B)]))
    L.append("")
    L.append("    " + c(_O, "RISK"))
    L.append("      " + c(reach_c, "● ") + c(_GRY, "Reachable in-repo".ljust(20)) +
             c(_DIM, "live now".ljust(14)) + c(reach_c + _B, f"{reach}"))
    band_txt = "  " + c(_band_colour(band), band) if band else ""
    L.append("      " + c(_A, "● ") + c(_GRY, "Install-liability".ljust(20)) +
             c(_DIM, "on install".ljust(14)) + c(_A + _B, f"{il}") + band_txt)
    if dep_il:
        L.append("      " + c(_A, "● ") + c(_GRY, "Inherited via deps".ljust(20)) +
                 c(_DIM, "pinned pkgs".ljust(14)) + c(_A + _B, f"{dep_il}"))
    if amber_actions:
        L.append("      " + c(_A, "● ") + c(_GRY, "Reachable actions".ljust(20)) +
                 c(_DIM, "review".ljust(14)) + c(_A + _B, f"{amber_actions}"))
    if fixed_dest:
        L.append("      " + c(_A, "● ") + c(_GRY, "Fixed-dest sends".ljust(20)) +
                 c(_DIM, "review".ljust(14)) + c(_A + _B, f"{fixed_dest}"))
    L.append("")
    # Display-map "None (no proven-live)" -> "No proven-live exploit path" (AMBER/neutral, NOT green —
    # green reads "all-clear"). Cosmetic mapping only: the raw overall_rating string in the audit artefacts
    # (hermes_shield_report.md/json) is untouched.
    disp, disp_c = (("No proven-live exploit path", _A) if str(rating).startswith("None")
                    else (rating, _rating_colour(rating)))
    L.append("    " + c(_GRY, "OWASP LLM06".ljust(13)) + c(_DIM, "Excessive Agency".ljust(20)) +
             c(disp_c + _B, disp))
    L.append("      " + c(_DIM, "└ not demonstrated exploitable — a clean scan is never read as “secure”"))
    # Zero-state: a clean-looking scan still says what it FOUND — never "found nothing".
    if reach == 0 and il > 0:
        L.append("      " + c(_A, f"→ {il} RCE-class surfaces need gating before install — see the report"))
    elif reach == 0 and (amber_actions or fixed_dest):
        _n = amber_actions + fixed_dest
        L.append("      " + c(_A, f"→ {_n} reachable action{'s' if _n != 1 else ''} — "
                                   f"review before you ship (see the report)"))
    elif reach == 0:
        L.append("      " + c(_GRY, f"→ {surfaces} action-surfaces mapped — full map in the report"))
    # AI tier health: a broken agent backend is SHOWN, never silent (the deterministic scan is unaffected).
    _ai = scan.get("ai_tier_counts") or {}
    _ai_fail = _ai.get("ai_failure") or _ai.get("ai_error")
    if _ai_fail or _ai.get("ai_status") == "failed":
        L.append("      " + c(_RED, "AI tier: FAILED — ") + c(_GRY, str(_ai_fail or "agent backend error")[:80]) +
                 c(_DIM, "  (static results above are unaffected)"))
    L.append("")

    # report location — relative path so it reads clean
    try:
        rel = os.path.relpath(str(out_dir), os.getcwd())
    except Exception:
        rel = str(out_dir)
    md = os.path.join(rel, "hermes_shield_report.md")
    html = os.path.join(rel, "shield_customer_report.html")
    L.append("  " + c(_O, "▸ ") + c(_B, "Report written") + c(_GRY, " →"))
    L.append("      " + c(_BLU, md))
    L.append("      " + c(_BLU, html) + "   " + c(_GRN, "← open this for the full breakdown"))
    L.append("")
    _open_cmd, _open_note = _open_hint(html)
    L.append("      " + c(_DIM, "open it:  ") + c(_A, _open_cmd) + c(_DIM, _open_note))
    L.append("")
    return "\n".join(L)
