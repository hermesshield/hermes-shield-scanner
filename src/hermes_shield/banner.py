#!/usr/bin/env python3
"""Hermes Shield — CLI banner (S8.91). Prints a branded header at the start of a scan.

Pure stdlib. Two-tone orange (bright block bars + dim shadow) to match the product mark, with a clean
no-colour fallback. It writes only to the terminal — it changes nothing about the scan, and it is
suppressed by --quiet, NO_COLOR (colour only), or HERMES_SHIELD_NO_BANNER (whole banner).
"""
from __future__ import annotations
import os
import sys

# Block art (pyfiglet 'ANSI Shadow', generated once and embedded — no runtime font dependency).
_ART = r"""
░█░█░█▀▀░█▀▄░█▄█░█▀▀░█▀▀░░░█▀▀░█░█░▀█▀░█▀▀░█░░░█▀▄
░█▀█░█▀▀░█▀▄░█░█░█▀▀░▀▀█░░░▀▀█░█▀█░░█░░█▀▀░█░░░█░█
░▀░▀░▀▀▀░▀░▀░▀░▀░▀▀▀░▀▀▀░░░▀▀▀░▀░▀░▀▀▀░▀▀▀░▀▀▀░▀▀░
""".strip("\n").splitlines()

_ORANGE = "\033[38;5;208m"   # bright block bars
_DIM = "\033[38;5;130m"      # dim shadow (the ╗╝╚═║ chars)
_AMBER = "\033[38;5;215m"    # taglines (warm, softer than the wordmark)
_GREEN = "\033[38;5;71m"
_BLUE = "\033[38;5;74m"
_GREY = "\033[38;5;245m"
_BOLD = "\033[1m"
_RESET = "\033[0m"

# Pagga wordmark: the solid strokes (█▀▄) are the bright letter; the ░ light-shade is the dim LED texture.
_BRIGHT_CHARS = set("█▀▄▐▌")
_DIM_CHARS = set("░▒▓╗╝╚╔═║")

# --ai destination, per selected backend — the honest network-disclosure string. A cloud backend is REAL
# egress under the user's own key, so we must name where the code actually goes (never hard-code "claude").
_AI_DEST = {
    "claude":    "your local claude CLI (Anthropic, under your account)",
    "ollama":    "a local Ollama model (localhost, zero-egress)",
    "anthropic": "Anthropic's API (api.anthropic.com, under your key)",
    "openai":    "OpenAI's API (api.openai.com, under your key)",
    "venice":    "Venice's API (api.venice.ai, under your key)",
    "gemini":    "Google's Gemini API (under your key)",
}


def _ai_dest(backend: str | None) -> str:
    return _AI_DEST.get((backend or "claude").strip().lower(), f"the '{backend}' backend")


def _use_colour(stream) -> bool:
    if os.getenv("NO_COLOR"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def _paint_art_line(line: str, colour: bool) -> str:
    if not colour:
        return line
    out, cur = [], None
    for ch in line:
        want = _ORANGE if ch in _BRIGHT_CHARS else _DIM if ch in _DIM_CHARS else None
        if want != cur:
            out.append(want or _RESET)
            cur = want
        out.append(ch)
    out.append(_RESET)
    return "".join(out)


def _tier_line(tiers: dict) -> str:
    parts = ["Core"]
    if tiers.get("ai"):
        parts.append("+ AI")
    if tiers.get("semgrep"):
        parts.append("+ semgrep")
    if tiers.get("deps"):
        parts.append("+ deps")
    return "  ·  ".join(parts)


def render(version: str, tiers: dict | None = None, target: str | None = None, colour: bool = True) -> str:
    tiers = tiers or {}
    O = _ORANGE if colour else ""
    G = _GREY if colour else ""
    A = _AMBER if colour else ""
    GR = _GREEN if colour else ""
    B = _BOLD if colour else ""
    R = _RESET if colour else ""
    L = [""]
    L += [_paint_art_line(ln, colour) for ln in _ART]
    L.append("")
    L.append(f"  {O}│{R} {B}{O}excessive-agency scanner for AI-agent code{R} {G}·{R} {A}v{version}{R}")
    L.append(f"  {O}│{R} {A}maps + proves what a hijacked agent can do {G}·{A} static + AI-assisted{R}")
    # Honesty (audit #4): the deterministic CORE scan reaches no network and no source leaves the machine.
    # Optional tiers change that and must NOT be covered by the clean claim: --deps fetches the repo's own
    # pinned packages; --ai forwards selected in-root code TEXT to the SELECTED backend's destination (which
    # varies — local CLI, localhost model, or a cloud API under the user's own key). Name the ACTUAL
    # destination of the active backend instead of hard-coding "claude" — a cloud backend is real egress.
    if tiers.get("ai") or tiers.get("deps"):
        parts = []
        if tiers.get("deps"):
            parts.append("--deps fetches your pinned packages")
        if tiers.get("ai"):
            parts.append("--ai forwards selected in-root code to " + _ai_dest(tiers.get("ai_backend")))
        L.append(f"  {O}│{R} {A}network: " + f"{G} · {A}".join(parts) + f"{R}")
    else:
        L.append(f"  {O}│{R} {A}no network egress {G}·{A} source never leaves this machine{R}")
    L.append("")
    rule = "·" * 58
    L.append(f"  {O}+{rule}+{R}")
    status = f"{GR}▶{R} {_tier_line(tiers)}"
    if target:
        status += f"   {G}·{R}  scanning {O}{target}{R}"
    L.append(f"  {status}")
    L.append(f"  {O}+{rule}+{R}")
    L.append("")
    return "\n".join(L)


def print_banner(version: str, tiers: dict | None = None, target: str | None = None, stream=None) -> None:
    """Print the banner unless suppressed. Never raises — a cosmetic header must never break a scan."""
    stream = stream or sys.stdout
    if os.getenv("HERMES_SHIELD_NO_BANNER"):
        return
    try:
        colour = _use_colour(stream)
        # nice-to-have: set the terminal window title (ignored where unsupported)
        if colour and target:
            stream.write(f"\033]0;hermes-shield — scan {target}\007")
        stream.write(render(version, tiers, target, colour=colour) + "\n")
        stream.flush()
    except Exception:
        pass
