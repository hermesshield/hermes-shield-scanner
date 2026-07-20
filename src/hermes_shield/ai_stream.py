#!/usr/bin/env python3
"""ai_stream.py — DISPLAY-ONLY live feed for the AI phases (whole-repo finder + per-file tier).

WHY: the agentic finder and the per-file AI tier shell out to the local `claude` CLI, which — run with
`capture_output` and no streaming — can block for up to 600s emitting NOTHING until it exits. The banner
prints, then the scan looks HUNG. This module makes the AI phase watchable, exactly like the static scan:
activity you can see, then the report.

WHAT `run_claude()` gives the callers (ai_finder / ai_assist), with a signature that returns the SAME
`(stdout_text, returncode, stderr_text)` triple `subprocess.run` would, so every fail-loud guard downstream
is unchanged:

  1. STREAM (preferred, when the installed `claude` advertises `--output-format stream-json --verbose`):
     run via `subprocess.Popen`, read stdout line-by-line, parse the stream-json events, and surface a
     readable live feed on STDERR — "-> Read agent/runner.py", "-> Grep tool.invoke" — plus a spinner +
     elapsed-seconds clock that ticks even between events. The FINAL answer text is accumulated from the
     terminal `result` event and returned as `stdout_text`; that field is byte-identical to what
     `claude -p` (text mode) prints, so the JSON the caller parses is IDENTICAL to the blocking path.
  2. HEARTBEAT FALLBACK (stream-json unsupported, or callers that pass prefer_stream=False like the noisy
     per-file tier): the ORIGINAL blocking call, wrapped in a daemon-thread spinner + elapsed clock on
     STDERR so it never looks frozen.
  3. PLAIN (feed disabled): the byte-identical `subprocess.run` of today — no output at all.

HARD INVARIANTS:
  * BYTE-IDENTICAL RESULT: streaming is DISPLAY-ONLY. `run_claude` returns the same final answer text the
    blocking call would; the caller's JSON parse + fail-loud guards see identical input.
  * TTY-GATED, DEFAULT-ON: the feed is on by DEFAULT for AI phases, but ONLY when the target stream
    (stderr) `isatty()` and no NO_COLOR / HERMES_SHIELD_NO_BANNER / HERMES_SHIELD_AI_NO_STREAM opt-out is
    set. Piped / CI / non-TTY runs get NOTHING on stderr and stdout/the JSON artefacts are never touched.
"""
from __future__ import annotations
import itertools
import json
import os
import subprocess
import sys
import threading
import time

# palette (mirrors stream.py so the AI feed reads as the same product)
_O = "\033[38;5;208m"     # blaze
_A = "\033[38;5;215m"     # heat
_GRN = "\033[38;5;71m"
_GRY = "\033[38;5;245m"
_DIM = "\033[38;5;240m"
_B = "\033[1m"
_R = "\033[0m"
_SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def feed_enabled(stream=None) -> bool:
    """True iff a live feed may be drawn: the target stream is an interactive TTY and no opt-out is set.

    Gated identically to the static HUD (stream.py._colour) plus a dedicated HERMES_SHIELD_AI_NO_STREAM
    escape hatch (set by --quiet). Piped/CI/redirected stderr -> False -> the AI phase runs plainly."""
    stream = stream or sys.stderr
    if os.getenv("NO_COLOR") or os.getenv("HERMES_SHIELD_NO_BANNER") or os.getenv("HERMES_SHIELD_AI_NO_STREAM"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


_STREAM_SUPPORT: dict = {}


def supports_stream_json(exe: str) -> bool:
    """Probe (once, cached per exe) whether the installed `claude` advertises stream-json output. We ask
    `claude --help` and look for the flag rather than assume — an older CLI without it FALLS BACK to the
    heartbeat path. A failed/slow probe is treated as 'unsupported' (fail-safe to the blocking path)."""
    if exe in _STREAM_SUPPORT:
        return _STREAM_SUPPORT[exe]
    ok = False
    try:
        h = subprocess.run([exe, "--help"], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=10)
        ok = "stream-json" in ((h.stdout or "") + (h.stderr or ""))
    except Exception:
        ok = False
    _STREAM_SUPPORT[exe] = ok
    return ok


def _build_cmd(exe, prompt, model, allowed_tools, extra=()):
    """Build the claude argv. The PLAIN/heartbeat form is byte-identical to the historical callers:
    finder -> [exe, -p, prompt, --model, M, --allowedTools, T]; per-file -> [exe, -p, prompt, (--model M)?].
    The stream form appends `extra` (--output-format stream-json --verbose)."""
    cmd = [exe, "-p", prompt]
    if model:
        cmd += ["--model", model]
    if allowed_tools:
        cmd += ["--allowedTools", allowed_tools]
    cmd += list(extra)
    return cmd


# --------------------------------------------------------------------------------------------------------
# stream-json event -> human line  (pure; unit-tested against canned events)
# --------------------------------------------------------------------------------------------------------

def _short_arg(inp: dict) -> str:
    for k in ("file_path", "path", "pattern", "query", "prompt", "command"):
        v = inp.get(k)
        if v:
            v = str(v).replace("\n", " ")
            return v if len(v) <= 60 else "…" + v[-57:]
    return ""


def describe_event(ev: dict):
    """Fold ONE stream-json event into (permanent_lines, live_action, result_text).

    - permanent_lines: readable feed lines to print above the live status (tool uses).
    - live_action: short label for the spinner line ("Read runner.py", "writing findings…").
    - result_text: the FINAL answer text (only on the terminal `result` event); None otherwise. This is the
      byte-identical stand-in for `claude -p` stdout — the sole value the caller parses."""
    t = ev.get("type")
    if t == "assistant":
        msg = ev.get("message") or {}
        perm, action = [], None
        for block in (msg.get("content") or []):
            bt = block.get("type")
            if bt == "tool_use":
                name = block.get("name", "tool")
                arg = _short_arg(block.get("input") or {})
                perm.append(f"→ {name} {arg}".rstrip())
                action = f"{name} {arg}".strip()
            elif bt == "text":
                if (block.get("text") or "").strip():
                    action = "writing findings…"
        return perm, action, None
    if t == "user":
        # a tool_result flowing back — keep the spinner honest without spamming a line per result
        return [], "reading results…", None
    if t == "system" and ev.get("subtype") == "init":
        return [], "reading across the repo…", None
    if t == "result":
        # the definitive final answer; even "" is a real (empty) result and must be captured
        return [], None, (ev.get("result") or "")
    return [], None, None


def accumulate_result(lines) -> str:
    """Pure helper (used by tests): parse an iterable of stream-json text lines and return the final
    `result` text — the exact byte string the caller would have received from the blocking `claude -p`."""
    result = ""
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except Exception:
            continue
        _, _, res = describe_event(ev)
        if res is not None:
            result = res
    return result


# --------------------------------------------------------------------------------------------------------
# renderers (STDERR, TTY-only) — display-only, never touch stdout or the returned result
# --------------------------------------------------------------------------------------------------------

class _Renderer:
    """A single in-place live status line (spinner · elapsed · current action) with permanent feed lines
    printed above it. A daemon ticker redraws the live line every 0.25s so the elapsed clock keeps moving
    even while the model 'thinks' between events. All writes go to `st` (stderr); a lock serialises the
    ticker and the event thread so their writes never interleave."""

    def __init__(self, st, banner: str):
        self.st = st
        self.banner_text = banner
        self.start = time.time()
        self.action = "starting…"
        self.lock = threading.Lock()
        self.spin = itertools.cycle(_SPIN)
        self.stop_ev = threading.Event()
        self._t = None

    def _w(self, s):
        try:
            self.st.write(s)
            self.st.flush()
        except Exception:
            pass

    def banner(self):
        self._w(f"\n  {_O}{self.banner_text}{_R}\n")

    def start_ticker(self):
        self._w("\033[?25l")  # hide cursor
        self._t = threading.Thread(target=self._loop, daemon=True)
        self._t.start()

    def _loop(self):
        while not self.stop_ev.wait(0.25):
            with self.lock:
                self._draw_live()

    def _draw_live(self):
        el = time.time() - self.start
        try:
            self.st.write(f"\r\033[K  {_O}{next(self.spin)}{_R} {_DIM}{el:6.1f}s{_R}  {_GRY}{self.action}{_R}")
            self.st.flush()
        except Exception:
            pass

    def permanent(self, line: str):
        with self.lock:
            try:
                self.st.write("\r\033[K")
                self.st.write(f"       {_GRY}{line}{_R}\n")
                self.st.flush()
            except Exception:
                pass

    def set_action(self, action: str):
        self.action = action

    def finish(self, note: str):
        self.stop_ev.set()
        if self._t:
            self._t.join(timeout=1)
        el = time.time() - self.start
        colour = _GRN if note == "done" else _A
        glyph = "✓" if note == "done" else "…"
        with self.lock:
            self._w(f"\r\033[K  {colour}{glyph}{_R} {_GRY}AI phase {note}{_R}   {_DIM}{el:5.1f}s{_R}\n")
            self._w("\033[?25h")  # restore cursor


class _Heartbeat:
    """A self-clearing spinner + elapsed clock for the blocking fallback (and the per-file tier). Draws one
    in-place line on `st` and, on stop(), clears it — so a tier that calls this once per file leaves no
    residue. Purely cosmetic; the blocking subprocess result is untouched."""

    def __init__(self, st, label: str):
        self.st = st
        self.label = label
        self.start = time.time()
        self.spin = itertools.cycle(_SPIN)
        self.stop_ev = threading.Event()
        self._t = None

    def start_ticker(self):
        try:
            self.st.write("\033[?25l")
            self.st.flush()
        except Exception:
            pass
        self._t = threading.Thread(target=self._loop, daemon=True)
        self._t.start()

    def _loop(self):
        while not self.stop_ev.wait(0.2):
            el = time.time() - self.start
            try:
                self.st.write(f"\r\033[K  {_O}{next(self.spin)}{_R} {_GRY}{self.label}{_R} {_DIM}· {el:5.1f}s{_R}")
                self.st.flush()
            except Exception:
                pass

    def stop(self):
        self.stop_ev.set()
        if self._t:
            self._t.join(timeout=1)
        try:
            self.st.write("\r\033[K\033[?25h")  # clear line, restore cursor
            self.st.flush()
        except Exception:
            pass


# --------------------------------------------------------------------------------------------------------
# the three execution paths
# --------------------------------------------------------------------------------------------------------

def _run_plain(exe, prompt, model, cwd, timeout, allowed_tools):
    """Byte-identical to the historical blocking call: capture_output, utf-8/replace, returns
    (stdout, returncode, stderr). Raises subprocess.TimeoutExpired on timeout (caller translates)."""
    cmd = _build_cmd(exe, prompt, model, allowed_tools)
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=timeout, cwd=cwd)
    return (proc.stdout or ""), proc.returncode, (proc.stderr or "")


def _run_heartbeat(exe, prompt, model, cwd, timeout, allowed_tools, banner, label, st):
    """Blocking call + a spinner/elapsed heartbeat on stderr. communicate() captures stdout EXACTLY as
    subprocess.run would, so the returned result is byte-identical to the plain path."""
    cmd = _build_cmd(exe, prompt, model, allowed_tools)
    if banner:
        try:
            st.write(f"\n  {_O}{banner}{_R}\n")
            st.flush()
        except Exception:
            pass
    hb = _Heartbeat(st, label)
    hb.start_ticker()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            encoding="utf-8", errors="replace", cwd=cwd)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise
    finally:
        hb.stop()
    return (out or ""), proc.returncode, (err or "")


def _run_stream(exe, prompt, model, cwd, timeout, allowed_tools, banner, st):
    """Popen with --output-format stream-json --verbose; read stdout line-by-line, render a live feed on
    stderr, accumulate the final `result` text and return (result, returncode, stderr). The result field is
    byte-identical to `claude -p` text-mode stdout, so the caller's JSON parse is unchanged."""
    cmd = _build_cmd(exe, prompt, model, allowed_tools,
                     extra=["--output-format", "stream-json", "--verbose"])
    rend = _Renderer(st, banner)
    rend.banner()
    rend.start_ticker()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            encoding="utf-8", errors="replace", cwd=cwd, bufsize=1)

    # drain stderr concurrently so a chatty stderr can never dead-lock the stdout read (full-pipe deadlock)
    err_chunks: list = []

    def _drain_err():
        try:
            if proc.stderr:
                for l in proc.stderr:
                    err_chunks.append(l)
        except Exception:
            pass

    et = threading.Thread(target=_drain_err, daemon=True)
    et.start()

    timed_out = {"v": False}

    def _kill():
        timed_out["v"] = True
        try:
            proc.kill()
        except Exception:
            pass

    timer = threading.Timer(timeout, _kill)
    timer.daemon = True
    timer.start()

    result_text = ""
    try:
        if proc.stdout:
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                perm, action, res = describe_event(ev)
                for p in perm:
                    rend.permanent(p)
                if action:
                    rend.set_action(action)
                if res is not None:
                    result_text = res
    finally:
        timer.cancel()
        try:
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        et.join(timeout=2)

    err = "".join(err_chunks)
    if timed_out["v"]:
        rend.finish("timed out")
        raise subprocess.TimeoutExpired(cmd, timeout)
    rend.finish("done")
    return result_text, (proc.returncode or 0), err


def run_claude(exe, prompt, *, model=None, cwd=None, timeout=90, allowed_tools=None,
               banner=None, hb_label="AI", prefer_stream=True, stream=None):
    """Run the local `claude` CLI and return (stdout_text, returncode, stderr_text) — the SAME triple
    subprocess.run yields, so callers keep their exact fail-loud guards.

    Path selection:
      * feed disabled (non-TTY / opt-out)          -> _run_plain   (byte-identical to today, silent)
      * prefer_stream and stream-json supported     -> _run_stream  (rich live feed on stderr)
      * otherwise (feed on)                          -> _run_heartbeat (spinner + elapsed on stderr)

    Raises subprocess.TimeoutExpired on timeout and OSError/Exception on launch failure — exactly the
    exceptions the callers already translate into AIAgentError with their own wording."""
    st = stream or sys.stderr
    if not feed_enabled(st):
        return _run_plain(exe, prompt, model, cwd, timeout, allowed_tools)
    if prefer_stream and supports_stream_json(exe):
        return _run_stream(exe, prompt, model, cwd, timeout, allowed_tools,
                           banner or f"▶ {hb_label}", st)
    return _run_heartbeat(exe, prompt, model, cwd, timeout, allowed_tools, banner, hb_label, st)
