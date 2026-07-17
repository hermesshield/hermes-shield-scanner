#!/usr/bin/env python3
"""
CLI-ergonomics slice — `--version`, friendly bare command, and no-arg "detect & pick"
target resolution. All CLI-layer only (scan_hermes.current_repo_root is untouched).
Read-only; no live actions; the picker writes to STDERR so stdout stays script-clean
and it NEVER blocks on stdin in a pipe (it is only reached on an interactive TTY).
"""
from __future__ import annotations
import io
import json
import sys
from pathlib import Path

import pytest

from hermes_shield import shield_cli
from hermes_shield.models import SCANNER_VERSION


# ---- task 1: --version flag + friendly bare command ----

def test_version_flag_prints_and_exits_zero(capsys):
    with pytest.raises(SystemExit) as e:
        shield_cli.main(["--version"])
    assert e.value.code == 0
    assert SCANNER_VERSION in capsys.readouterr().out


def test_bare_command_prints_help_and_exits_zero(capsys):
    rc = shield_cli.main([])
    assert rc == 0
    out = capsys.readouterr().out
    assert "usage:" in out and "scan" in out


def test_version_subcommand_still_works(capsys):
    rc = shield_cli.main(["version"])
    assert rc == 0
    assert SCANNER_VERSION in capsys.readouterr().out


# ---- task 3: no-arg target resolution helpers ----

def test_enclosing_git_repo_found_from_subdir(tmp_path):
    (tmp_path / ".git").mkdir()
    sub = tmp_path / "a" / "b"
    sub.mkdir(parents=True)
    assert shield_cli._enclosing_git_repo(sub) == tmp_path.resolve()


def test_enclosing_git_repo_none_outside_repo(tmp_path):
    sub = tmp_path / "plain"
    sub.mkdir()
    assert shield_cli._enclosing_git_repo(sub) is None


def test_candidate_git_dirs_depth_capped_and_skips_junk(tmp_path):
    # depth-1 and depth-2 repos are found; hidden/node_modules/.venv/venv and depth-3 are not
    for d in ("one/.git", "nest/two/.git", "node_modules/x/.git", ".hidden/y/.git",
              ".venv/z/.git", "venv/w/.git", "deep/l2/l3/.git"):
        (tmp_path / d).mkdir(parents=True)
    found = shield_cli._candidate_git_dirs(tmp_path)
    names = sorted(p.relative_to(tmp_path).as_posix() for p in found)  # as_posix: OS-separator agnostic
    assert names == ["nest/two", "one"]


def test_candidate_git_dirs_respects_cap(tmp_path):
    for i in range(30):
        (tmp_path / f"r{i:02d}" / ".git").mkdir(parents=True)
    assert len(shield_cli._candidate_git_dirs(tmp_path, cap=20)) == 20


def test_candidate_git_dirs_does_not_descend_into_found_repo(tmp_path):
    (tmp_path / "outer" / ".git").mkdir(parents=True)
    (tmp_path / "outer" / "inner" / ".git").mkdir(parents=True)
    found = shield_cli._candidate_git_dirs(tmp_path)
    assert found == [tmp_path / "outer"]


def _pick(tmp_path, cands, line):
    err = io.StringIO()
    got = shield_cli._prompt_pick(tmp_path, cands, stdin=io.StringIO(line), stderr=err)
    return got, err.getvalue()


def test_prompt_pick_valid_choice(tmp_path):
    cands = [tmp_path / "a", tmp_path / "b"]
    got, err = _pick(tmp_path, cands, "2\n")
    assert got == cands[1]
    assert "0) scan this directory (default)" in err


def test_prompt_pick_zero_and_empty_and_garbage_default_to_cwd(tmp_path):
    cands = [tmp_path / "a"]
    for line in ("0\n", "\n", "banana\n", "9\n", ""):   # "" = EOF
        got, _ = _pick(tmp_path, cands, line)
        assert got == tmp_path, f"input {line!r} must fall back to the CWD default"


def test_prompt_pick_writes_picker_to_stderr_stream_only(tmp_path, capsys):
    _pick(tmp_path, [tmp_path / "a"], "1\n")
    assert capsys.readouterr().out == ""      # nothing leaked to stdout


class _Tty(io.StringIO):
    def isatty(self):
        return True


def test_interactive_false_under_ci_or_no_prompt(monkeypatch):
    monkeypatch.setattr(sys, "stdin", _Tty())
    monkeypatch.setattr(sys, "stderr", _Tty())
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("HERMES_SHIELD_NO_PROMPT", raising=False)
    assert shield_cli._interactive() is True
    monkeypatch.setenv("CI", "1")
    assert shield_cli._interactive() is False
    monkeypatch.delenv("CI")
    monkeypatch.setenv("HERMES_SHIELD_NO_PROMPT", "1")
    assert shield_cli._interactive() is False


def test_interactive_false_when_piped(monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO())     # isatty() -> False
    assert shield_cli._interactive() is False


# ---- task 3: end-to-end resolution through `scan` with no target ----

def _scan_root(out_dir: Path) -> str:
    data = json.loads((out_dir / "outputs" / "hermes_action_surface_scan.json").read_text())
    return data["root"]


def test_scan_no_target_uses_enclosing_git_repo(tmp_path, monkeypatch, capsys):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "f.py").write_text("x = 1\n")
    sub = repo / "sub"
    sub.mkdir()
    monkeypatch.chdir(sub)
    out = tmp_path / "out"
    rc = shield_cli.main(["scan", "--quiet", "--out", str(out)])
    assert rc == 0
    err = capsys.readouterr().err
    assert "enclosing git repo of the current directory" in err
    assert "pass a path to choose another" in err
    assert _scan_root(out) == str(repo.resolve())


def test_scan_no_target_non_tty_scans_cwd_with_message(tmp_path, monkeypatch, capsys):
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "f.py").write_text("x = 1\n")
    monkeypatch.chdir(plain)
    monkeypatch.setattr(sys, "stdin", io.StringIO())     # piped: must not prompt or block
    out = tmp_path / "out"
    rc = shield_cli.main(["scan", "--quiet", "--out", str(out)])
    assert rc == 0
    err = capsys.readouterr().err
    assert "scanning the current directory" in err
    assert _scan_root(out) == str(plain.resolve())


def test_scan_explicit_target_prints_no_resolution_message(tmp_path, monkeypatch, capsys):
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "f.py").write_text("x = 1\n")
    monkeypatch.chdir(tmp_path)
    rc = shield_cli.main(["scan", str(plain), "--quiet", "--out", str(tmp_path / "out")])
    assert rc == 0
    err = capsys.readouterr().err
    assert "enclosing git repo" not in err and "scanning the current directory" not in err
