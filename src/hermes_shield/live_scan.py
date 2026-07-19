#!/usr/bin/env python3
"""Hermes Shield — the opt-in `--live` cinematic scan experience (S8.94).

A "wow, this is really working — and I should look at this" live CLI, gated behind the NEW `--live` flag so
the DEFAULT scan output is byte-for-byte unchanged (additive only; this drives a production tool). The drama
is the SUBTRACTION, never the addition — a fear-monger only adds; we MAP breadth, then narrow, in front of
the operator, down to the one number that matters.

Three acts, all from REAL scan data (run_scan / install_report.build_report):
  1. stream_live()     — while the scan runs: an upward log of files being read (with per-file surface
                         counts) + a STICKY 5-line HUD pinned to the bottom (spinner · current file · clock;
                         the BIG climbing "action-surfaces mapped" number; the honest signal tally).
  2. render_collapse() — after the map: animate the honest narrowing on screen from the real report —
                         mapped -> dangerous -> reachable -> reachable AND unguarded. The number can (and
                         often does) collapse to 0.
  3. render_finale()   — the RED / AMBER / BLUE verdict (via the SHARED install_report.verdict_band so the
                         CLI and the HTML report can never disagree), a point-first plain-words block, the
                         report path (orange, first), and the honest free-scanner -> paid-Repairer hand-off.

HONESTY INVARIANTS (structural — a guard team will try to break these):
  1. The big "surfaces mapped" number is NEVER danger and NEVER coloured red (breadth, not danger).
  2. RED appears in EXACTLY ONE place ("reachable & unguarded") and ONLY from the deterministic verdict
     (non_gated_vulnerable = static UNGUARDED_CRITICAL_LIVE_SINK). An AI-suspected guess can never turn
     anything red — it is filtered out in build_report and counts only in the grey "needs review (AI)" tally.
  3. Every counter increment maps to a REAL analysed artefact emitted by the scan (no timed/fake climb).
  4. A clean repo -> BLUE even with a huge surfaces number. Zero is "no live path proven", never "secure".
  5. The reachable tally can go DOWN on screen — the collapse subtracts the already-guarded candidates.

Robustness/accessibility:
  - Non-TTY / piped / CI -> NO sticky HUD; line-buffered checkpoints go to STDERR, stdout stays clean.
  - NO_COLOR honoured -> colour stripped, the ⚠/▲/●/·/↩/▸ glyph + text markers survive so meaning does too.
  - Ctrl-C tears the sticky region down cleanly and re-raises (the CLI prints "scan interrupted", exits 130).

Pure stdlib. It only REPORTS the scan; it never changes a single number.
"""
from __future__ import annotations
import itertools
import os
import queue
import re
import shutil
import sys
import threading
import time

from . import install_report as _IR

# ANSI SGR escape sequences carry zero visible width; the clamp below skips them when counting columns.
_ANSI_RE = re.compile(r"\033\[[0-9;?]*[A-Za-z]")


def _clamp_visible(line: str, width: int) -> str:
    """Truncate `line` to at most `width` VISIBLE columns, preserving ANSI SGR codes (which have no width)
    and closing with a reset if we cut. Keeps a long file path from spilling the sticky HUD past its fixed
    row count — a wrapped HUD line would desync the cursor math in _Hud.frame and corrupt the region."""
    if width <= 0:
        return line
    out, visible, i, n, cut = [], 0, 0, len(line), False
    while i < n:
        m = _ANSI_RE.match(line, i)
        if m:
            out.append(m.group(0))
            i = m.end()
            continue
        if visible >= width:
            cut = True
            break
        out.append(line[i])
        visible += 1
        i += 1
    s = "".join(out)
    if cut:
        s += _R
    return s

# --- Sunset-terminal palette (matches banner.py / summary.py) ---
_O = "\033[38;5;208m"     # blaze orange — the map / breadth (never danger)
_A = "\033[38;5;215m"     # amber — install-liability
_HEAT = "\033[38;5;203m"  # heat red — reserved for EARNED reachable-unguarded only
_GRN = "\033[38;5;71m"
_BLU = "\033[38;5;74m"
_SKY = "\033[38;5;117m"
_GRY = "\033[38;5;245m"
_DIM = "\033[38;5;240m"
_B = "\033[1m"
_R = "\033[0m"

_SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_HUD_H = 5           # sticky HUD height (lines)
_LOG_CAP = 200       # cap the permanent upward log so a huge repo can't flood the scrollback
_FIND_CAP = 8        # highlight at most this many RCE-class findings inline


def _tty(stream) -> bool:
    return bool(getattr(stream, "isatty", lambda: False)())


def _use_colour(stream) -> bool:
    """Colour on only for an interactive TTY that hasn't opted out. NO_COLOR / HERMES_SHIELD_NO_BANNER
    strip colour but (per the a11y contract) the glyphs + words still carry the meaning."""
    if os.getenv("NO_COLOR") or os.getenv("HERMES_SHIELD_NO_BANNER"):
        return False
    return _tty(stream)


def _short(cap: str) -> str:
    return {"code_exec": "exec()", "subprocess_exec": "subprocess/shell", "deserialize": "deserialize",
            "ssti": "template-injection", "secret_exfil": "secret-exfil"}.get(cap, cap)


# ---------------------------------------------------------------------------
# The honest funnel — every number straight from the deterministic report model.
# Guaranteed monotonic non-increasing (each stage is a subset of the previous), so the collapse can only
# ever narrow. reachable/unguarded are STATIC-ONLY (build_report filters detection_source == "static").
# ---------------------------------------------------------------------------

def funnel(report: dict, scan: dict) -> dict:
    mapped = len(scan.get("surfaces", []))                       # breadth — all mapped action-surfaces
    vulnerable = int(report.get("vulnerable_surfaces", 0))       # dangerous-capability (RCE/act) surfaces
    non_gated = int(report.get("non_gated_vulnerable", 0))       # reachable AND unguarded (the RED number)
    gated = int(report.get("gated_vulnerable", 0))               # reachable but a guard downgraded it
    reachable = gated + non_gated                                # reachable from untrusted input
    # defensive clamp — a subset can never exceed its parent (protects the on-screen narrowing invariant)
    vulnerable = min(vulnerable, mapped)
    reachable = min(reachable, vulnerable)
    non_gated = min(non_gated, reachable)
    gated = reachable - non_gated
    return {
        "mapped": mapped, "vulnerable": vulnerable, "reachable": reachable,
        "guarded": gated, "unguarded": non_gated,
        "stages": [
            ("surfaces mapped", mapped, "breadth, not danger"),
            ("dangerous-capability surfaces", vulnerable, "can act on the world"),
            ("reachable from untrusted input", reachable, "an injected prompt could steer"),
            ("reachable AND unguarded", non_gated, "nothing in the way"),
        ],
    }


def signal_tally(report: dict, scan: dict) -> dict:
    """The honest signals. Only `reachable` is ever RED, and only from the deterministic count.
    `amber_actions` (reachable+unguarded reversible/social actions) drives the AMBER band with install.
    AI-suspected surfaces feed the grey `needs_review` tally exclusively — never red, never amber."""
    reachable = int(report.get("non_gated_vulnerable", 0))
    install = int(report.get("install_liability_rce", 0))
    amber_actions = int(report.get("reachable_amber_actions", 0))
    fixed_dest_reviews = int(report.get("reachable_fixed_dest_review", 0))
    ai = sum(1 for s in scan.get("surfaces", [])
             if getattr(s, "detection_source", "static") != "static"
             and getattr(s, "context", "prod") == "prod")
    return {"reachable": reachable, "install": install, "amber_actions": amber_actions,
            "fixed_dest_reviews": fixed_dest_reviews,
            "reachability_unknown": int(report.get("reachability_unknown", 0)),
            "needs_review": ai, "proven": int(report.get("proven_live_poc", 0))}


# ---------------------------------------------------------------------------
# ACT 1 — the sticky-HUD live scan.
# ---------------------------------------------------------------------------

def stream_live(run_fn, tiers=None, stream=None):
    """Drive run_fn(progress=cb) -> scan dict with the cinematic HUD on a TTY. Off a TTY (piped / CI) there
    is NO sticky region: line-buffered checkpoints go to STDERR and stdout is left completely clean, so JSON
    piping still works. Returns the scan dict (re-raises the scan's exception; KeyboardInterrupt is torn down
    cleanly then re-raised)."""
    stream = stream or sys.stdout
    # TWO axes: a TTY (can we animate / drive the cursor?) vs colour (may we emit SGR?). NO_COLOR strips
    # colour but KEEPS the sticky HUD + glyphs on a TTY (a11y: meaning survives without colour). Only a
    # genuine non-TTY (piped / CI) drops the HUD for line-buffered stderr checkpoints.
    if not _tty(stream):
        return _run_plain_with_checkpoints(run_fn)
    return _run_with_hud(run_fn, stream, colour=_use_colour(stream))


def _run_plain_with_checkpoints(run_fn):
    """Non-TTY / NO_COLOR fallback: stdout stays clean; genuine phase checkpoints stream to STDERR,
    line-buffered (flushed each line), so CI logs show real progress without any cursor codes."""
    def cb(ev):
        try:
            if ev.get("phase") == "map" and ev.get("done"):
                sys.stderr.write(f"[shield-live] mapped {ev.get('surfaces', 0)} action-surfaces "
                                 f"across {ev.get('files', 0)} files\n")
                sys.stderr.flush()
            elif ev.get("phase") == "reach" and ev.get("done"):
                sys.stderr.write(f"[shield-live] reachability traced across {ev.get('total', 0)} surfaces\n")
                sys.stderr.flush()
            elif ev.get("phase") == "reach" and "live" in ev:
                cap, rel, line = ev["live"]
                sys.stderr.write(f"[shield-live]   reachable-unguarded: {rel}:{line} [{_short(cap)}]\n")
                sys.stderr.flush()
        except Exception:
            pass
    return run_fn(progress=cb)


def _run_with_hud(run_fn, stream, colour: bool):
    q: "queue.Queue" = queue.Queue()
    box: dict = {}

    def worker():
        try:
            box["v"] = run_fn(progress=lambda ev: q.put(ev))
        except BaseException as e:  # noqa: BLE001 — capture EVERYTHING so the region always tears down
            box["e"] = e
        finally:
            q.put({"_end": True})

    t = threading.Thread(target=worker, daemon=True)
    t.start()

    hud = _Hud(stream, colour)
    spin = itertools.cycle(_SPIN)
    st = {"phase": "map", "files": 0, "surfaces": 0, "cur": "", "reach": 0, "traced": 0, "total": 0,
          "step": "", "start": time.time()}
    logged = 0
    finds = 0
    interrupted = False
    try:
        hud.enter()
        while True:
            try:
                while True:
                    ev = q.get_nowait()
                    if ev.get("_end"):
                        raise StopIteration
                    logged, finds = _consume(ev, st, hud, logged, finds)
            except queue.Empty:
                pass
            except StopIteration:
                break
            hud.frame(_hud_lines(st, next(spin), colour))
            time.sleep(0.08)
    except KeyboardInterrupt:
        interrupted = True
    finally:
        hud.leave()
    if interrupted:
        raise KeyboardInterrupt()
    if "e" in box:
        raise box["e"]
    return box.get("v")


def _consume(ev, st, hud, logged, finds):
    """Fold one real progress event into the HUD state, emitting permanent upward-log lines for the
    interesting ones (files that found surfaces; RCE-class finds; confirmed reachable-unguarded sinks)."""
    ph = ev.get("phase")
    if ev.get("start"):
        st["phase"] = ph
        st["step"] = ""
        if ph == "map":
            hud.log(f"  {_c(_O, hud.col)}▸{_c('', 1)} {_c(_B, hud.col)}Mapping action-surfaces{_r(hud.col)}"
                    f"  {_c(_DIM, hud.col)}· static · no code executed · no network egress{_r(hud.col)}")
        elif ph == "reach":
            st["total"] = ev.get("total", st["total"]) or st["total"]
            hud.log(f"  {_c(_O, hud.col)}▸{_r(hud.col)} {_c(_B, hud.col)}Tracing reachability & attributing "
                    f"guards{_r(hud.col)}")
        return logged, finds
    if ev.get("done"):
        if ph == "map":
            hud.log(f"  {_c(_GRN, hud.col)}✓{_r(hud.col)} {_c(_B, hud.col)}Mapped "
                    f"{ev.get('surfaces', st['surfaces']):,} action-surfaces{_r(hud.col)} across "
                    f"{ev.get('files', st['files']):,} files")
            st["surfaces"] = ev.get("surfaces", st["surfaces"])
            st["files"] = ev.get("files", st["files"])
        else:
            hud.log(f"  {_c(_GRN, hud.col)}✓{_r(hud.col)} {_c(_B, hud.col)}Reachability traced{_r(hud.col)}"
                    f" across {ev.get('total', st['total']):,} surfaces")
        return logged, finds
    if ph == "map":
        st["files"] = ev.get("files", st["files"])
        st["surfaces"] = ev.get("surfaces", st["surfaces"])
        st["cur"] = ev.get("file") or st["cur"]
        cnt = ev.get("count", 0)
        # upward log: files that actually contributed a surface (0-surface files just refresh the HUD).
        if ev.get("file") and cnt and logged < _LOG_CAP:
            logged += 1
            hud.log(f"       {_c(_GRY, hud.col)}↩ read{_r(hud.col)} {_c('', hud.col)}{ev['file']}{_r(hud.col)}"
                    f"   {_c(_O, hud.col)}+{cnt}{_r(hud.col)} {_c(_DIM, hud.col)}surface"
                    f"{'' if cnt == 1 else 's'}{_r(hud.col)}")
        for cap, rel, line in ev.get("new", []):
            if finds >= _FIND_CAP:
                break
            finds += 1
            hud.log(f"       {_c(_A, hud.col)}⚠{_r(hud.col)} {_c(_GRY, hud.col)}{rel}:{line}{_r(hud.col)}"
                    f"   {_c(_A, hud.col)}{_short(cap)}{_r(hud.col)} "
                    f"{_c(_DIM, hud.col)}RCE-class — candidate, not yet proven{_r(hud.col)}")
    elif ph == "reach":
        if "step" in ev:
            st["step"] = ev["step"]
        if "traced" in ev:
            st["traced"] = ev.get("traced", st["traced"])
            st["total"] = ev.get("total", st["total"]) or st["total"]
        if "live" in ev:
            # EARNED red: a deterministic UNGUARDED_CRITICAL_LIVE_SINK confirmed by guard-attribution.
            cap, rel, line = ev["live"]
            st["reach"] += 1
            hud.log(f"       {_c(_HEAT, hud.col)}●{_r(hud.col)} {_c(_HEAT + _B, hud.col)}reachable & "
                    f"unguarded{_r(hud.col)}  {_c(_GRY, hud.col)}{rel}:{line}{_r(hud.col)}   "
                    f"{_c(_A, hud.col)}{_short(cap)}{_r(hud.col)}")
    return logged, finds


def _hud_lines(st, spin_ch, colour):
    """The 5 sticky HUD lines. Line 1 spinner+file+clock; line 2 the BIG orange breadth number; line 3 the
    honest tally; line 4 a rule; line 5 the trust footer."""
    el = f"{time.time() - st['start']:5.1f}s"
    if st["phase"] == "map":
        head = f"Mapping · {st['cur'] or '…'}"
    elif st["phase"] == "reach":
        step = {"call-graph": "building the call graph", "cross-module": "cross-module guard-proof",
                "taint": "inter-procedural taint", "guards": "attributing guards"}.get(st["step"],
                                                                                        "tracing paths")
        head = f"Tracing reachability · {step}"
        if st["total"]:
            head += f"  {st['traced']:,}/{st['total']:,}"
    else:
        head = "Scanning…"

    big = f"{st['surfaces']:,}"
    reach = st["reach"]
    # RED only when EARNED (reach >= 1); calm grey dot until then. install-liability / needs-review are only
    # known after the report is built, so during the scan they read "—" (honest: not yet computed).
    reach_dot = (_HEAT if reach else _GRY)
    L = [
        f"  {_c(_O, colour)}{spin_ch}{_r(colour)} {_c(_A, colour)}{head}{_r(colour)}"
        f"   {_c(_DIM, colour)}{el}{_r(colour)}",
        f"  {_c(_O + _B, colour)}{big:>9}{_r(colour)}  {_c(_GRY, colour)}action-surfaces mapped{_r(colour)}"
        f"   {_c(_DIM, colour)}breadth, not danger{_r(colour)}",
        f"  {_c(reach_dot + _B, colour)}● {reach}{_r(colour)} "
        f"{_c(_GRY, colour)}reachable & unguarded{_r(colour)}   "
        f"{_c(_A, colour)}▲ —{_r(colour)} {_c(_GRY, colour)}install-liability{_r(colour)}   "
        f"{_c(_GRY, colour)}· — needs review (AI){_r(colour)}",
        f"  {_c(_DIM, colour)}{'─' * 58}{_r(colour)}",
        f"  {_c(_DIM, colour)}▪ static analysis · target code is never executed · no network egress{_r(colour)}",
    ]
    return L


class _Hud:
    """A sticky N-line footer: permanent log lines scroll UP; the HUD is redrawn in place at the bottom each
    frame. Technique: keep the cursor parked on the line just below the HUD; each redraw moves up N lines,
    clears to end of screen, re-emits any new permanent lines (which push the HUD down) then the HUD."""

    def __init__(self, stream, colour: bool):
        self.s = stream
        self.col = colour
        self._pending: list = []
        self._drawn = False

    def _w(self, s):
        try:
            self.s.write(s)
        except Exception:
            pass

    def enter(self):
        self._w("\033[?25l")  # hide cursor
        self.s.flush()

    def log(self, line: str):
        self._pending.append(line)

    def frame(self, hud_lines):
        if self._drawn:
            self._w(f"\033[{_HUD_H}F")   # up to the first HUD line, column 0
            self._w("\033[J")            # clear from here to end of screen
        for ln in self._pending:
            self._w(ln + "\n")
        self._pending = []
        # Clamp each HUD line to the terminal width (minus one column so a full-width line can't wrap on
        # terminals that scroll at the last column). A wrapped line would occupy >1 physical row and desync
        # the `\033[{_HUD_H}F` cursor math, corrupting the sticky region — long file paths are the usual cause.
        _w = max(1, shutil.get_terminal_size((80, 24)).columns - 1)
        self._w("\n".join(_clamp_visible(ln, _w) for ln in hud_lines) + "\n")
        self._drawn = True
        self.s.flush()

    def leave(self):
        # tear the HUD down: reclaim its region, flush any last permanent lines, restore the cursor.
        if self._drawn:
            self._w(f"\033[{_HUD_H}F")
            self._w("\033[J")
        for ln in self._pending:
            self._w(ln + "\n")
        self._pending = []
        self._w("\033[?25h")  # restore cursor
        self.s.flush()


# small colour helpers that no-op when colour is off (keeps glyphs, drops SGR)
def _c(code, colour):
    return code if colour else ""


def _r(colour):
    return _R if colour else ""


# ---------------------------------------------------------------------------
# ACT 2 — the collapse. The centrepiece: subtract, on screen, from real data.
# ---------------------------------------------------------------------------

def render_collapse(report: dict, scan: dict, stream=None, animate=None):
    stream = stream or sys.stdout
    colour = _use_colour(stream)
    # animate whenever we're on a TTY (cursor control is not colour); NO_COLOR keeps the shrink, drops SGR.
    animate = _tty(stream) if animate is None else animate
    f = funnel(report, scan)
    stages = f["stages"]
    # BLOCKER 3: the red funnel collapses to `unguarded` (non_gated_vulnerable). On an amber-only repo that
    # is 0 — but reachable AMBER actions / fixed-destination sends still remain, and Act 3 will render AMBER.
    # A blue "0 · no live path proven" coda here would flatly contradict that. Count the amber remainder so
    # the closing coda can be amber-aware instead of a false all-clear.
    amber_remaining = int(report.get("reachable_amber_actions", 0)) + int(report.get("reachable_fixed_dest_review", 0))

    def w(s):
        try:
            stream.write(s)
        except Exception:
            pass

    w("\n")
    w(f"  {_c(_O, colour)}▸ THE NARROWING{_r(colour)}  "
      f"{_c(_DIM, colour)}— a fear-monger only adds; we subtract, from your real scan{_r(colour)}\n\n")

    # the animated shrink: a single big number counting DOWN through the funnel stops, redrawn in place.
    if animate:
        vals = [v for _, v, _ in stages]
        w("\033[?25l")
        try:
            for a, b in zip(vals, vals[1:]):
                steps = 14
                for i in range(steps + 1):
                    n = int(round(a + (b - a) * (i / steps)))
                    w(f"\r\033[K  {_c(_O + _B, colour)}{n:>9,}{_r(colour)}  "
                      f"{_c(_GRY, colour)}narrowing…{_r(colour)}")
                    stream.flush()
                    time.sleep(0.02)
            w("\r\033[K")
        finally:
            w("\033[?25h")
            stream.flush()

    # the static funnel — breadth at the top (orange, never red), the earned number at the bottom.
    prev = None
    for i, (label, val, note) in enumerate(stages):
        last = i == len(stages) - 1
        arrow = _c(_GRY, colour)
        if prev is not None and prev > val:
            w(f"  {arrow}     ↓ −{prev - val:,} filtered out{_r(colour)}\n")
        elif prev is not None:
            w(f"  {arrow}     ↓{_r(colour)}\n")
        # the bottom line is the ONLY place red may appear, and ONLY when it is EARNED (val > 0). A collapse
        # to zero closes calm-blue — never red — because nothing was proven.
        if last and val > 0:
            num_c = _HEAT
            mark = f"   {_c(_HEAT, colour)}← the number that matters{_r(colour)}"
        elif last and amber_remaining > 0:
            # BLOCKER 3: 0 red, but reachable amber actions remain -> amber-aware coda, never a blue all-clear
            # (Act 2 must not contradict Act 3's AMBER verdict on an amber-only repo).
            num_c = _A
            _noun = "action remains" if amber_remaining == 1 else "actions remain"
            mark = (f"   {_c(_A, colour)}← 0 red · {amber_remaining} reachable {_noun} — "
                    f"review{_r(colour)}")
        elif last:
            num_c = _BLU
            mark = f"   {_c(_BLU, colour)}← collapsed to 0 · no live path proven{_r(colour)}"
        else:
            num_c = _O
            mark = ""
        w(f"  {_c(num_c + _B, colour)}{val:>9,}{_r(colour)}  {_c(_GRY, colour)}{label}{_r(colour)}   "
          f"{_c(_DIM, colour)}{note}{_r(colour)}{mark}\n")
        prev = val
    # explicit honest drop line so the guarded-candidate subtraction is never invisible.
    if f["guarded"] > 0:
        w(f"\n  {_c(_DIM, colour)}note: {f['guarded']:,} reachable "
          f"{'candidate was' if f['guarded'] == 1 else 'candidates were'} filtered out — a guard already "
          f"stands in the way.{_r(colour)}\n")
    w("\n")


# ---------------------------------------------------------------------------
# ACT 3 — the verdict + point-first block + report path + Repairer hand-off.
# ---------------------------------------------------------------------------

def render_finale(report: dict, scan: dict, out_dir, version: str, stream=None):
    stream = stream or sys.stdout
    colour = _use_colour(stream)
    sig = signal_tally(report, scan)
    reachable, proven, install, ai = sig["reachable"], sig["proven"], sig["install"], sig["needs_review"]
    amber_actions = sig["amber_actions"]
    fixed_dest_reviews = sig["fixed_dest_reviews"]
    reach_unknown = sig["reachability_unknown"]
    vb = _IR.verdict_band(reachable, proven, install, amber_actions, fixed_dest_reviews, reach_unknown)
    band_c = {"red": _HEAT, "amber": _A, "blue": _BLU}[vb["code"]]

    def w(s):
        try:
            stream.write(s)
        except Exception:
            pass

    def c(code, s):
        return f"{code}{s}{_R}" if colour else str(s)

    # ---- verdict banner (the antivirus-style beat; head UPPER-cased for the CLI) ----
    head = vb["head"].upper()
    rule = "─" * 58 if colour else "-" * 58
    w(c(band_c, f"  ┏{rule}┓") + "\n")
    w(f"  {c(band_c + _B, vb['icon'] + '  ' + head)}\n")
    if vb["code"] == "red":
        n = reachable if reachable else proven
        w("  " + c(_GRY, f"{n} dangerous {'action' if n == 1 else 'actions'} an attacker can reach in this "
                         f"code right now, with nothing in the way.") + "\n")
        if proven:
            w("  " + c(_GRY, f"{proven} proven-live — we demonstrated a real attack path.") + "\n")
    elif vb["code"] == "amber" and amber_actions:
        w("  " + c(_GRY, f"{amber_actions} reversible {'action an attacker' if amber_actions == 1 else 'actions an attacker'} "
                         f"can reach here with nothing in the way — social/post-style {'action' if amber_actions == 1 else 'actions'} "
                         f"(post, reply, like). Lower blast-radius than the red band, but review before you ship.") + "\n")
        if fixed_dest_reviews:
            w("  " + c(_GRY, f"Plus {fixed_dest_reviews} fixed-destination {'send' if fixed_dest_reviews == 1 else 'sends'} "
                             f"(config/constant destination) reachable with tainted content — not exfil, but review.") + "\n")
        if install:
            w("  " + c(_GRY, f"Plus {install} install-liability {'item goes' if install == 1 else 'items go'} "
                             f"live the moment this code is installed and fed untrusted input.") + "\n")
    elif vb["code"] == "amber" and fixed_dest_reviews:
        w("  " + c(_GRY, f"{fixed_dest_reviews} fixed-destination {'send an attacker' if fixed_dest_reviews == 1 else 'sends an attacker'} "
                         f"can reach here with tainted content — a messaging/external send to a proven config/constant "
                         f"destination. Not exfil (the destination can't be steered), but review before you ship.") + "\n")
        if install:
            w("  " + c(_GRY, f"Plus {install} install-liability {'item goes' if install == 1 else 'items go'} "
                             f"live the moment this code is installed and fed untrusted input.") + "\n")
    elif vb["code"] == "amber":
        w("  " + c(_GRY, f"Nothing is reachable here today — but {install} install-liability "
                         f"{'item goes' if install == 1 else 'items go'} live the moment this code is "
                         f"installed and fed untrusted input.") + "\n")
    else:
        w("  " + c(_GRY, "No attacker-reachable action with no control. This is NOT a clean bill of "
                         "health — it means no live path was proven. See the map.") + "\n")
    w(c(band_c, f"  ┗{rule}┛") + "\n\n")

    # ---- point-first plain words: coloured dot -> number -> plain verb ----
    w(f"  {c(_O, '▸ IN PLAIN WORDS')}\n")
    reach_dot = _HEAT if reachable else _GRY
    w("      " + c(reach_dot + _B, f"● {reachable}") + " " +
      c(_GRY, "reachable & unguarded") + "  " +
      c(reach_dot, "→ fix these first" if reachable else "→ nothing reachable-unguarded proven") + "\n")
    amber_dot = _A if amber_actions else _GRY
    w("      " + c(amber_dot + _B, f"▲ {amber_actions}") + " " + c(_GRY, "reachable actions (review)") + "  " +
      c(amber_dot, "→ reversible/social — review before you ship" if amber_actions
        else "→ none reachable") + "\n")
    fdd_dot = _A if fixed_dest_reviews else _GRY
    w("      " + c(fdd_dot + _B, f"▲ {fixed_dest_reviews}") + " " + c(_GRY, "fixed-destination sends (review)") + "  " +
      c(fdd_dot, "→ config/constant destination — tainted content, not exfil — review" if fixed_dest_reviews
        else "→ none reachable") + "\n")
    w("      " + c(_A + _B, f"▲ {install}") + " " + c(_GRY, "install-liability") + "  " +
      c(_A, "→ gate before you ship" if install else "→ none inherited") + "\n")
    w("      " + c(_GRY + _B, f"· {ai}") + " " + c(_GRY, "needs review (AI)") + "  " +
      c(_GRY, "→ human-verify — advisory, never a verdict" if ai else "→ none (AI tier off or nothing found)")
      + "\n\n")

    # ---- report path — orange, first ----
    try:
        rel = os.path.relpath(str(out_dir), os.getcwd())
    except Exception:
        rel = str(out_dir)
    html = os.path.join(rel, "shield_customer_report.html")
    md = os.path.join(rel, "hermes_shield_report.md")
    w(f"  {c(_O, '▸ REPORT')} {c(_O + _B, html)}  {c(_GRN, '← open this')}\n")
    w("      " + c(_DIM, md) + "\n\n")

    # ---- the honest Repairer hand-off ----
    w(f"  {c(_O, '▸ WHAT HAPPENS NEXT')}\n")
    w("      " + c(_GRY, "This free Scanner FINDS every action-surface and PLANS the fix — it never "
                        "touches your code.") + "\n")
    w("      " + c(_GRY, "The paid Hermes Shield Repairer (early access) turns each plan into a reviewed "
                        "diff:") + "\n")
    w("      " + c(_GRY, "proposed as a change, applied only when a human approves, then re-scanned — "
                        "never auto-fix.") + "\n\n")


def render_quiet(report: dict, scan: dict, out_dir, stream=None):
    """--live --quiet: exactly one honest verdict line + the report path. Nothing else."""
    stream = stream or sys.stdout
    colour = _use_colour(stream)
    sig = signal_tally(report, scan)
    vb = _IR.verdict_band(sig["reachable"], sig["proven"], sig["install"], sig["amber_actions"],
                          sig["fixed_dest_reviews"], sig["reachability_unknown"])
    band_c = {"red": _HEAT, "amber": _A, "blue": _BLU}[vb["code"]]
    try:
        rel = os.path.relpath(str(out_dir), os.getcwd())
    except Exception:
        rel = str(out_dir)
    html = os.path.join(rel, "shield_customer_report.html")
    head = vb["head"].upper()
    tag = f"{vb['icon']} {head} — {sig['reachable']} reachable & unguarded · report: {html}"
    stream.write((f"{band_c}{tag}{_R}\n") if colour else f"{tag}\n")
    stream.flush()
