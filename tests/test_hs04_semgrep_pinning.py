"""
test_hs04_semgrep_pinning — HS-04: the semgrep comparator runs a PINNED image and every comparator
result is attributed to a concrete semgrep version.

Locks:
  - SEMGREP_IMAGE is a concrete pinned ref (version tag or @sha256 digest), never a floating bare name,
  - build_cmd (docker) uses the pinned ref; HERMES_SHIELD_SEMGREP_IMAGE overrides it,
  - run() returns a non-empty `comparator_version` in ALL modes, on success AND on every error path
    (docker -> the pinned image ref; venv/uvx -> the binary's own --version),
  - all of this stays inside the flag-gated comparator tier — the default scan is untouched.
"""
from __future__ import annotations
import json
import re
from pathlib import Path

from hermes_shield import semgrep_runner as SG  # noqa: E402

# a concrete pin: a version tag or a sha256 digest — NOT a floating bare image name
_PINNED_RE = re.compile(r"^semgrep/semgrep(:[\w.-]+|@sha256:[a-f0-9]{64})$")

_MOCK = json.dumps({"results": [
    {"path": "pkg/x.py", "start": {"line": 10},
     "check_id": "python.lang.security.eval", "extra": {"severity": "ERROR",
      "metadata": {"cwe": ["CWE-94: Code Injection"], "confidence": "HIGH"}}},
]})


def test_semgrep_image_is_pinned(monkeypatch):
    monkeypatch.delenv("HERMES_SHIELD_SEMGREP_IMAGE", raising=False)
    assert _PINNED_RE.match(SG.SEMGREP_IMAGE), "SEMGREP_IMAGE must be a pinned ref"
    cmd = SG.build_cmd(Path("/tmp/repo"), Path("/tmp/out/semgrep.json"), mode="docker")
    assert SG.SEMGREP_IMAGE in cmd
    assert "semgrep/semgrep" not in cmd, "bare (floating :latest) image ref must be gone"


def test_semgrep_image_operator_override(monkeypatch):
    ref = "semgrep/semgrep@sha256:" + "ab" * 32
    monkeypatch.setenv("HERMES_SHIELD_SEMGREP_IMAGE", ref)
    cmd = SG.build_cmd(Path("/tmp/repo"), Path("/tmp/out/semgrep.json"), mode="docker")
    assert ref in cmd and SG.SEMGREP_IMAGE not in cmd


def test_run_docker_reports_pinned_image_as_comparator_version(tmp_path, monkeypatch):
    monkeypatch.delenv("HERMES_SHIELD_SEMGREP_IMAGE", raising=False)

    def fake_run(cmd, **kw):
        (tmp_path / "out" / "semgrep.json").write_text(_MOCK)

        class _R:
            returncode = 0
            stdout, stderr = "", ""
        return _R()

    monkeypatch.setattr(SG.subprocess, "run", fake_run)
    res = SG.run(tmp_path, tmp_path / "out", mode="docker")
    assert res["comparator_version"] == SG.SEMGREP_IMAGE
    assert res["count"] == 1


def test_run_venv_captures_semgrep_version(tmp_path, monkeypatch):
    def fake_run(cmd, **kw):
        class _R:
            returncode = 0
            stderr = ""
            stdout = "1.86.0\n" if "--version" in cmd else ""
        if "--version" not in cmd:
            (tmp_path / "out" / "semgrep.json").write_text(_MOCK)
        return _R()

    monkeypatch.setattr(SG.subprocess, "run", fake_run)
    res = SG.run(tmp_path, tmp_path / "out", mode="venv")
    assert res["comparator_version"] == "semgrep 1.86.0 (venv)"


def test_run_error_paths_still_carry_comparator_version(tmp_path, monkeypatch):
    # error path 1: the semgrep process itself blows up
    def boom(cmd, **kw):
        raise OSError("docker missing")

    monkeypatch.setattr(SG.subprocess, "run", boom)
    res = SG.run(tmp_path, tmp_path / "out1", mode="docker")
    assert res["error"].startswith("semgrep run failed")
    assert res["comparator_version"] == SG.SEMGREP_IMAGE  # docker mode never needs a subprocess

    # error path 2: semgrep runs but produces no output file
    def silent(cmd, **kw):
        class _R:
            returncode = 0
            stdout, stderr = "", ""
        return _R()

    monkeypatch.setattr(SG.subprocess, "run", silent)
    res = SG.run(tmp_path, tmp_path / "out2", mode="docker")
    assert res["error"] == "semgrep produced no output"
    assert res["comparator_version"] == SG.SEMGREP_IMAGE


def test_version_capture_fail_open(monkeypatch):
    # venv mode with no semgrep binary at all -> 'unknown', never an exception
    def boom(cmd, **kw):
        raise FileNotFoundError("semgrep")

    monkeypatch.setattr(SG.subprocess, "run", boom)
    assert SG._comparator_version("venv") == "unknown"
