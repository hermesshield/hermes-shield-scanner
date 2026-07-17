#!/usr/bin/env python3
"""Hermes Shield — live streaming scan renderer (S8.93).

Runs the scan in a worker thread and renders REAL progress in the main thread: a climbing file/surface
counter while files are mapped, RCE-class findings ticking off as their file is scanned, then a climbing
"traced X/total" reachability counter — each phase freezing into a green ✓ receipt with its real timing.
The spinner animates continuously so no phase ever looks frozen.

Honesty: every counter and every finding shown is emitted by the real scan as the work happens (see the
`progress` callbacks in repo_scanner.scan_repo and guard_attribution.apply). No fabricated progress, no
padding sleeps. Not a TTY / NO_COLOR / HERMES_SHIELD_NO_BANNER -> the scan runs plainly with no streaming,
so piped and CI output are unchanged.
"""
from __future__ import annotations
import itertools
import os
import queue
import sys
import threading
import time

_O = "\033[38;5;208m"
_A = "\033[38;5;215m"
_GRN = "\033[38;5;71m"
_RED = "\033[38;5;203m"
_GRY = "\033[38;5;245m"
_DIM = "\033[38;5;240m"
_B = "\033[1m"
_R = "\033[0m"
_SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_TICK_CAP = 6  # stream at most this many findings inline; the rest live in the report
_STEP = {"call-graph": "building the call graph", "cross-module": "cross-module guard-proof",
         "taint": "inter-procedural taint", "guards": "attributing guards"}


def _colour(stream) -> bool:
    if os.getenv("NO_COLOR") or os.getenv("HERMES_SHIELD_NO_BANNER"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def _short(cap: str) -> str:
    return {"code_exec": "exec()", "subprocess_exec": "subprocess/shell",
            "deserialize": "deserialize", "ssti": "template-injection"}.get(cap, cap)


def stream_scan(run_fn, stream=None):
    """run_fn(progress=cb) -> scan dict. Streams live on a TTY; otherwise runs plainly. Returns the scan."""
    stream = stream or sys.stdout
    if not _colour(stream):
        return run_fn(progress=None)

    q: "queue.Queue" = queue.Queue()
    box: dict = {}

    def worker():
        try:
            box["v"] = run_fn(progress=lambda ev: q.put(ev))
        except BaseException as e:
            box["e"] = e
        finally:
            q.put({"_end": True})

    t = threading.Thread(target=worker, daemon=True)
    t.start()

    spin = itertools.cycle(_SPIN)
    phase = None
    files = surfaces = traced = total = 0
    reach_step = ""
    reach_counter = False
    ticked: set = set()
    tick_count = 0
    pstart = time.time()
    pending: list = []   # permanent lines to print above the live line

    def w(s):
        stream.write(s)

    def clear():
        w("\r\033[K")

    def live_line() -> str:
        sp = next(spin)
        el = f"{time.time() - pstart:5.1f}s"
        if phase == "map":
            return (f"  {_O}{sp}{_R} {_A}Mapping action-surfaces{_R}   "
                    f"{_B}{files}{_R} {_GRY}files{_R} {_DIM}·{_R} {_B}{surfaces}{_R} {_GRY}surfaces{_R}"
                    f"   {_DIM}{el}{_R}")
        if phase == "reach":
            label = _STEP.get(reach_step, "tracing paths")
            cnt = f"   {_B}{traced:,}/{total:,}{_R}" if (reach_counter and total) else ""
            return (f"  {_O}{sp}{_R} {_A}Tracing reachability{_R} {_DIM}·{_R} {_A}{label}{_R}{cnt}"
                    f"   {_DIM}{el}{_R}")
        return f"  {_O}{sp}{_R} {_A}Scanning…{_R}   {_DIM}{el}{_R}"

    try:
        w("\033[?25l")  # hide cursor
        w(f"\n  {_DIM}▪ static analysis · no code executed · no network egress{_R}\n\n")
        while True:
            # drain everything currently queued
            drained = False
            try:
                while True:
                    ev = q.get_nowait()
                    drained = True
                    if ev.get("_end"):
                        raise StopIteration
                    ph = ev.get("phase")
                    if ev.get("start"):
                        phase = ph
                        pstart = time.time()
                        total = ev.get("total", 0) or total
                        pending.append(("hdr", ph))
                    elif ev.get("done"):
                        el = time.time() - pstart
                        if ph == "map":
                            pending.append(("done", f"  {_GRN}✓{_R} {_B}Mapped {ev.get('surfaces', surfaces):,} "
                                            f"action-surfaces{_R} across {ev.get('files', files):,} files"
                                            f"   {_DIM}{el:4.1f}s{_R}"))
                        else:
                            pending.append(("done", f"  {_GRN}✓{_R} {_B}Reachability traced{_R} across "
                                            f"{ev.get('total', total):,} surfaces   {_DIM}{el:4.1f}s{_R}"))
                    elif ph == "map":
                        files = ev.get("files", files)
                        surfaces = ev.get("surfaces", surfaces)
                        for cap, rel, line in ev.get("new", []):
                            key = (cap, rel, line)
                            if key in ticked or tick_count >= _TICK_CAP:
                                continue
                            ticked.add(key)
                            tick_count += 1
                            pending.append(("find", f"       {_RED}⚠{_R} {_GRY}{rel}:{line}{_R}"
                                            f"   {_A}{_short(cap)}{_R}"))
                    elif ph == "reach":
                        if "live" in ev:
                            cap, rel, line = ev["live"]
                            pending.append(("live", f"       {_RED}● live{_R}  {_GRY}{rel}:{line}{_R}"
                                            f"   {_A}{_short(cap)}{_R} {_DIM}reachable{_R}"))
                        else:
                            if "step" in ev:
                                reach_step = ev["step"]
                            if "traced" in ev:
                                traced = ev.get("traced", traced)
                                total = ev.get("total", total) or total
                                reach_counter = True
                            elif "step" in ev:
                                reach_counter = False   # a label-only sub-step (no per-item counter)
            except queue.Empty:
                pass
            except StopIteration:
                # flush any remaining permanent lines, then finish
                _flush(w, clear, pending)
                pending.clear()
                break

            # emit permanent lines (findings / phase headers / freezes) above the live line
            if pending:
                _flush(w, clear, pending)
                pending.clear()

            clear()
            w(live_line())
            stream.flush()
            time.sleep(0.08)
    finally:
        clear()
        w("\033[?25h")  # restore cursor
        w("\n")
        stream.flush()

    if "e" in box:
        raise box["e"]
    return box.get("v")


def _flush(w, clear, pending):
    clear()
    for kind, payload in pending:
        if kind == "hdr":
            label = {"map": "1/3  Mapping action-surfaces",
                     "reach": "2/3  Tracing reachability & attributing guards"}.get(payload, payload)
            w(f"  {_O}▸ {label}{_R}\n")
        else:
            w(payload + "\n")
