#!/usr/bin/env python3
"""
S9 — three CLI-UX upgrades, all guarded by the SAME invariant: a HUMAN on a terminal gets the rich
experience; a MACHINE (piped / redirected / CI / non-TTY) gets byte-clean output, no prompt, no auto-open,
and NO change to any JSON artefact.

  A. live-by-default    — the cinematic HUD is the default on an interactive stdout TTY; piped stays plain.
                          (`--live` is now a no-op alias; the TTY-flip is exercised in test_s8_94.)
  B. working open cmd    — the printed "open" command uses the report's ABSOLUTE path (a relative path is
                          unresolvable from a WSL shell), and is platform-correct; auto-open is TTY-only.
  C. offer the AI pass   — after a STATIC-only scan, an interactive run with the `claude` CLI present OFFERS
                          the deeper AI pass; a non-TTY / --quiet / no-claude run never prompts (never hangs).
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from hermes_shield import open_report as OR
from hermes_shield import scan_hermes as SH
from hermes_shield import shield_cli


# ---------------------------------------------------------------- fixtures / helpers

def _fixture(tmp_path: Path) -> Path:
    fx = tmp_path / "fx"
    fx.mkdir()
    (fx / "app.py").write_text("import os\ndef f(x):\n    os.system(x)\n", encoding="utf-8")
    return fx


class _TtyStdin(io.StringIO):
    """A stdin whose isatty() is True — a stand-in for a human at the keyboard."""
    def isatty(self):
        return True


# ================================================================ (A/B) MACHINE path: byte-clean

def test_non_tty_scan_zero_ansi_no_prompt_and_json_stable(tmp_path, capsys, monkeypatch):
    """capsys => stdout/stdin are NOT TTYs. The piped run must: emit ZERO HUD/ANSI escapes on stdout, never
    print the AI-pass prompt, and write a JSON artefact that is byte-identical across two runs (the UX layer
    never touches the artefacts). `claude` is forced present to prove the offer is gated on the TTY, not on
    tool availability."""
    monkeypatch.setattr(shield_cli.shutil, "which", lambda name: "/usr/bin/claude")
    fx = _fixture(tmp_path)
    out = tmp_path / "o"

    assert shield_cli.main(["scan", str(fx), "--out", str(out)]) == 0
    cap = capsys.readouterr()
    assert "\x1b[" not in cap.out, "piped stdout must carry no ANSI/cursor codes"
    assert "Run the deeper AI pass" not in cap.out and "Run the deeper AI pass" not in cap.err, \
        "a non-TTY run must NEVER prompt (it would hang a script)"

    json_path = out / "outputs" / "hermes_action_surface_scan.json"
    first = json_path.read_bytes()

    assert shield_cli.main(["scan", str(fx), "--out", str(out)]) == 0
    capsys.readouterr()
    assert json_path.read_bytes() == first, "the JSON artefact must be byte-identical (UX changes are inert)"


def test_non_tty_terse_output_prints_absolute_report_path_and_open_command(tmp_path, capsys):
    """MACHINE path: the terse (non-TTY) render prints the report's ABSOLUTE path + a copy-paste open command
    — never the old unresolvable relative path."""
    fx = _fixture(tmp_path)
    out = tmp_path / "o"
    assert SH.main(["--scan", "--root", str(fx), "--out", str(out)]) == 0
    text = capsys.readouterr().out

    abs_html = str((out / "outputs" / "shield_customer_report.html").resolve())
    assert abs_html in text, "the report path shown must be absolute"
    assert "shield-report/outputs/shield_customer_report.html" not in text, \
        "the old unresolvable RELATIVE path must not be printed"
    # an explicit, platform-correct open command line is present and targets the report by name (on WSL the
    # absolute Linux path is translated to its Windows form, so assert the filename, not the raw Linux path).
    open_lines = [ln for ln in text.splitlines() if ln.strip().startswith("open:")]
    assert open_lines, "a copy-paste open command must be printed"
    assert "shield_customer_report.html" in open_lines[0]
    assert "shield-report/outputs/" not in open_lines[0], "open command must not use the relative path"


# ================================================================ (A) --quiet forces plain + no prompt

def test_quiet_forces_plain_and_never_prompts(tmp_path, capsys, monkeypatch):
    """--quiet: stdout stays silent (no HUD, no panel) and no AI-pass prompt fires, even with `claude`
    present and stdin faked to a TTY."""
    monkeypatch.setattr(shield_cli.shutil, "which", lambda name: "/usr/bin/claude")
    monkeypatch.setattr(sys, "stdin", _TtyStdin("y\n"))   # even a 'yes' waiting on stdin must be ignored
    fx = _fixture(tmp_path)
    out = tmp_path / "o"
    assert shield_cli.main(["scan", str(fx), "--out", str(out), "--quiet"]) == 0
    cap = capsys.readouterr()
    assert cap.out == "", "--quiet must keep stdout silent (plain, no HUD)"
    assert "Run the deeper AI pass" not in cap.err, "--quiet must never prompt"


# ================================================================ (B) open_command: absolute + platform

def test_open_command_uses_absolute_path_per_platform(monkeypatch):
    abs_path = "/abs/dir/shield-report/outputs/shield_customer_report.html"

    monkeypatch.setattr(OR.sys, "platform", "darwin")
    cmd, _ = OR.open_command(abs_path)
    assert cmd == f'open "{abs_path}"'

    monkeypatch.setattr(OR.sys, "platform", "win32")
    cmd, _ = OR.open_command(abs_path)
    assert cmd == f'Invoke-Item "{abs_path}"'

    # generic Linux (force non-WSL) -> xdg-open with the ABSOLUTE path
    monkeypatch.setattr(OR.sys, "platform", "linux")
    monkeypatch.setattr(OR, "is_wsl", lambda: False)
    cmd, _ = OR.open_command(abs_path)
    assert cmd == f'xdg-open "{abs_path}"'
    assert "../" not in cmd and not cmd.endswith("shield_customer_report.html"[:-4])  # sanity: not relative


def test_open_command_wsl_translates_to_windows_path(monkeypatch):
    """On WSL the command must be `explorer.exe "<windows path>"` — a WSL/Linux path handed to explorer.exe
    is unresolvable (it opens Documents). When wslpath is unavailable we defer with an inline $(wslpath -w …),
    which is still driven by the ABSOLUTE path."""
    abs_path = "/home/u/proj/shield-report/outputs/shield_customer_report.html"
    monkeypatch.setattr(OR.sys, "platform", "linux")
    monkeypatch.setattr(OR, "is_wsl", lambda: True)

    monkeypatch.setattr(OR, "_wsl_windows_path", lambda p: r"\\wsl$\Ubuntu\home\u\proj\out\report.html")
    cmd, note = OR.open_command(abs_path)
    assert cmd == r'explorer.exe "\\wsl$\Ubuntu\home\u\proj\out\report.html"'
    assert "WSL" in note

    monkeypatch.setattr(OR, "_wsl_windows_path", lambda p: None)   # wslpath missing -> deferred, still absolute
    cmd, _ = OR.open_command(abs_path)
    assert cmd == f'explorer.exe "$(wslpath -w "{abs_path}")"'
    assert abs_path in cmd


def test_report_abspath_is_absolute(tmp_path):
    p = OR.report_abspath(tmp_path / "o" / "outputs")
    assert Path(p).is_absolute()
    assert p.endswith("shield_customer_report.html")


def test_auto_open_is_fire_and_forget_never_raises(monkeypatch):
    """auto_open must swallow EVERY error (a headless box has no launcher) and return False, never raise."""
    monkeypatch.setattr(OR.sys, "platform", "linux")
    monkeypatch.setattr(OR, "is_wsl", lambda: False)
    monkeypatch.setattr(OR.shutil, "which", lambda name: "/usr/bin/xdg-open")

    def boom(*a, **kw):
        raise OSError("no display")

    monkeypatch.setattr(OR.subprocess, "Popen", boom)
    assert OR.auto_open("/abs/report.html") is False   # did not raise


# ================================================================ (C) the AI-pass offer gate

def test_offer_gate_true_only_on_tty_with_claude(tmp_path, monkeypatch):
    """_should_offer_ai_pass is True ONLY for an interactive `scan` with `claude` present and no opt-out —
    and False on a non-TTY, under --quiet, when the deep pass already ran, or when claude is absent."""
    from types import SimpleNamespace
    base = dict(command="scan", ai=False, quiet=False)

    monkeypatch.setattr(shield_cli.shutil, "which", lambda name: "/usr/bin/claude")
    monkeypatch.setattr(sys, "stdin", _TtyStdin())
    monkeypatch.delenv("HERMES_SHIELD_NO_PROMPT", raising=False)
    assert shield_cli._should_offer_ai_pass(SimpleNamespace(**base), ai_deep_effective=False) is True

    # deep pass already requested -> no offer
    assert shield_cli._should_offer_ai_pass(SimpleNamespace(**base), ai_deep_effective=True) is False
    # --quiet -> no offer
    assert shield_cli._should_offer_ai_pass(SimpleNamespace(**{**base, "quiet": True}), False) is False
    # per-file --ai already on -> not static-only -> no offer
    assert shield_cli._should_offer_ai_pass(SimpleNamespace(**{**base, "ai": True}), False) is False
    # a non-scan command -> no offer
    assert shield_cli._should_offer_ai_pass(SimpleNamespace(**{**base, "command": "diff"}), False) is False
    # opt-out env -> no offer
    monkeypatch.setenv("HERMES_SHIELD_NO_PROMPT", "1")
    assert shield_cli._should_offer_ai_pass(SimpleNamespace(**base), False) is False
    monkeypatch.delenv("HERMES_SHIELD_NO_PROMPT")

    # claude absent -> no offer
    monkeypatch.setattr(shield_cli.shutil, "which", lambda name: None)
    assert shield_cli._should_offer_ai_pass(SimpleNamespace(**base), False) is False

    # non-TTY stdin -> no offer (this is what stops a piped run hanging)
    monkeypatch.setattr(shield_cli.shutil, "which", lambda name: "/usr/bin/claude")
    monkeypatch.setattr(sys, "stdin", io.StringIO())   # isatty() -> False
    assert shield_cli._should_offer_ai_pass(SimpleNamespace(**base), False) is False


def test_prompt_yes_no_only_true_for_yes():
    yes = shield_cli._prompt_yes_no("? ", stdin=io.StringIO("y\n"), stderr=io.StringIO())
    assert yes is True
    assert shield_cli._prompt_yes_no("? ", stdin=io.StringIO("yes\n"), stderr=io.StringIO()) is True
    for line in ("n\n", "\n", "", "maybe\n"):   # N / empty / EOF / garbage -> False
        assert shield_cli._prompt_yes_no("? ", stdin=io.StringIO(line), stderr=io.StringIO()) is False


def test_offer_yes_runs_ai_deep_second_pass(tmp_path, monkeypatch):
    """On 'y' the CLI re-runs the scan WITH --ai-deep (regenerating the report). Stub the engine so the test
    is fast + hermetic; assert it was called twice and the second call carried --ai-deep."""
    calls = []
    monkeypatch.setattr(shield_cli.scan_hermes, "main", lambda argv: calls.append(list(argv)) or 0)
    monkeypatch.setattr(shield_cli.shutil, "which", lambda name: "/usr/bin/claude")
    monkeypatch.setattr(sys, "stdin", _TtyStdin("y\n"))
    monkeypatch.delenv("HERMES_SHIELD_NO_PROMPT", raising=False)

    fx = _fixture(tmp_path)
    rc = shield_cli.main(["scan", str(fx), "--out", str(tmp_path / "o")])
    assert rc == 0
    assert len(calls) == 2, "a 'yes' answer must trigger a second (AI-deep) scan pass"
    assert "--ai-deep" not in calls[0] and "--ai-deep" in calls[1]


def test_offer_no_runs_single_pass(tmp_path, monkeypatch, capsys):
    """On 'n' (or EOF) the CLI skips cleanly — exactly one scan pass, no --ai-deep, no crash."""
    calls = []
    monkeypatch.setattr(shield_cli.scan_hermes, "main", lambda argv: calls.append(list(argv)) or 0)
    monkeypatch.setattr(shield_cli.shutil, "which", lambda name: "/usr/bin/claude")
    monkeypatch.setattr(sys, "stdin", _TtyStdin("n\n"))
    monkeypatch.delenv("HERMES_SHIELD_NO_PROMPT", raising=False)
    # stub auto_open so the 'declined' branch can't spawn a real launcher in the test
    import hermes_shield.open_report as _OR
    monkeypatch.setattr(_OR, "auto_open", lambda p: False)

    fx = _fixture(tmp_path)
    rc = shield_cli.main(["scan", str(fx), "--out", str(tmp_path / "o")])
    assert rc == 0
    assert len(calls) == 1, "a 'no' answer must NOT trigger a second pass"
    assert "--ai-deep" not in calls[0]
    assert "Run the deeper AI pass" in capsys.readouterr().err
