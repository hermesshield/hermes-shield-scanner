#!/usr/bin/env python3
"""open_report.py — reliable, cross-platform "open the HTML report" plumbing.

Two jobs, both display/UX only (they never touch the scan or its artefacts):

  1. open_command(abs_path)  -> a COPY-PASTE-RELIABLE shell command string that opens the report, built from
     the report's ABSOLUTE path. The historic bug this fixes: the CLI printed a RELATIVE path
     (`explorer.exe shield-report/outputs/…`), which Windows Explorer cannot resolve from a WSL shell — it
     silently opens Documents instead. On WSL we translate the Linux path to a Windows path via `wslpath -w`
     so `explorer.exe "<C:\\…>"` actually lands on the file.

  2. auto_open(abs_path)     -> fire-and-forget launch of the report in the OS default handler. Best-effort:
     EVERY error is swallowed, so a headless / no-DISPLAY box can never crash (or even slow) the scan. The
     CALLER decides whether it is appropriate to auto-open (interactive TTY only) — this function just does
     it without blocking.

Platform detection is robust: WSL is detected via WSL_DISTRO_NAME or `microsoft` in /proc/version (either
signal), macOS via sys.platform == "darwin", Windows via a "win" prefix, else generic Linux.

Pure stdlib. No import-time side effects.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

REPORT_NAME = "shield_customer_report.html"


def report_abspath(out_dir) -> str:
    """The ABSOLUTE path to the customer HTML report under `out_dir` (resolved even if it does not yet
    exist on disk, so this is safe to call before the report is written)."""
    return str((Path(out_dir) / REPORT_NAME).resolve())


def is_wsl() -> bool:
    """True on Windows Subsystem for Linux. Either signal is sufficient: the WSL_DISTRO_NAME env var (set in
    every WSL shell) or `microsoft` in /proc/version (the WSL kernel string)."""
    if os.getenv("WSL_DISTRO_NAME"):
        return True
    try:
        return "microsoft" in Path("/proc/version").read_text(encoding="utf-8", errors="ignore").lower()
    except Exception:
        return False


def _wsl_windows_path(abs_path: str) -> str | None:
    """Best-effort translate a WSL/Linux path to its Windows form via `wslpath -w`. Returns None if wslpath
    is unavailable or fails — the caller then falls back to an inline `$(wslpath -w …)` command."""
    wp = shutil.which("wslpath")
    if not wp:
        return None
    try:
        r = subprocess.run([wp, "-w", abs_path], capture_output=True, text=True, timeout=5)
    except Exception:
        return None
    if r.returncode == 0:
        win = (r.stdout or "").strip()
        return win or None
    return None


def open_command(abs_path: str):
    """Return (command_string, note) — a reliable copy-paste command that opens `abs_path` (which MUST be
    absolute). macOS -> `open`; Windows -> `Invoke-Item` (PowerShell-safe; `start` is a cmd-only builtin);
    WSL -> `explorer.exe "<translated windows path>"` (or an inline `$(wslpath -w …)` if translation is
    unavailable at print time); other Linux -> `xdg-open`."""
    plat = sys.platform
    if plat == "darwin":
        return f'open "{abs_path}"', ""
    if plat.startswith("win"):
        return f'Invoke-Item "{abs_path}"', ""
    # Linux family (WSL is a special case of Linux).
    if is_wsl():
        win = _wsl_windows_path(abs_path)
        if win:
            return f'explorer.exe "{win}"', "   (WSL → Windows)"
        # wslpath unavailable now, but it exists in every real WSL shell — defer the translation to paste time.
        return f'explorer.exe "$(wslpath -w "{abs_path}")"', "   (WSL → Windows)"
    if plat.startswith("linux"):
        return f'xdg-open "{abs_path}"', ""
    return abs_path, "   (open this in your browser)"


def auto_open(abs_path: str) -> bool:
    """Fire-and-forget open of `abs_path` in the OS default handler. Best-effort and NON-blocking: all
    errors are swallowed and it returns False rather than raising, so a headless box never breaks the scan.
    Returns True if a launcher was spawned (not that the file actually opened).

    The caller is responsible for deciding WHEN this is appropriate (interactive TTY, not CI). This function
    performs no TTY gating of its own."""
    try:
        plat = sys.platform
        if plat.startswith("win"):
            os.startfile(abs_path)  # type: ignore[attr-defined]  # Windows-only
            return True
        if plat == "darwin":
            argv = ["open", abs_path]
        elif is_wsl():
            argv = ["explorer.exe", _wsl_windows_path(abs_path) or abs_path]
        elif plat.startswith("linux"):
            if not shutil.which("xdg-open"):
                return False
            argv = ["xdg-open", abs_path]
        else:
            return False
        subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         stdin=subprocess.DEVNULL)
        return True
    except Exception:
        return False
