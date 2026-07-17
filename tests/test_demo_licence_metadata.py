#!/usr/bin/env python3
"""
Demo subcommand + licence + packaging-metadata slice.

`hermes-shield demo` = a real red report in ~10 seconds: inert bundled fixtures
(_demo/*.py.txt — never importable, never executed) are copied to a temp dir under
real .py names and scanned via the NORMAL scan path, guaranteeing one
UNGUARDED_CRITICAL_LIVE_SINK (the eval() in app.py) plus the full HTML report.

Also pins the licence decision (full Apache-2.0, no stub wording anywhere) and the
PyPI-facing metadata (authors, urls, classifiers, dual console scripts).
"""
from __future__ import annotations
import json
from importlib import resources
from pathlib import Path

from hermes_shield import shield_cli

_PKG_ROOT = Path(__file__).resolve().parents[1]


# ---- task 2: demo fixtures ship as inert package data ----

def test_demo_package_data_present_and_labelled_inert():
    pkg = resources.files("hermes_shield") / "_demo"
    for name in ("app.py.txt", "tools.py.txt"):
        text = (pkg / name).read_text(encoding="utf-8")
        assert "illustrative fixture — not executed" in text, f"{name} must carry the inert header"
    assert "eval(task)" in (pkg / "app.py.txt").read_text(encoding="utf-8")
    assert "subprocess.run" in (pkg / "tools.py.txt").read_text(encoding="utf-8")


def test_demo_package_data_wired_in_pyproject():
    toml = (_PKG_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "_demo/*.txt" in toml, "wheel package-data must ship the demo fixtures"


def test_no_importable_py_ships_under_demo_dir():
    demo_dir = _PKG_ROOT / "src" / "hermes_shield" / "_demo"
    assert not list(demo_dir.glob("*.py")), \
        "_demo must contain only .txt fixtures — a .py would ship importable vulnerable code"


def test_materialise_demo_target_writes_real_py_names():
    tmp = shield_cli._materialise_demo_target()
    assert sorted(p.name for p in tmp.iterdir()) == ["app.py", "tools.py"]
    assert "eval(task)" in (tmp / "app.py").read_text(encoding="utf-8")


# ---- task 2: demo end-to-end — guaranteed red finding + full HTML report ----

def test_demo_yields_unguarded_critical_live_sink_and_html(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    rc = shield_cli.main(["demo", "--quiet", "--out", str(tmp_path / "out")])
    assert rc == 0
    out = capsys.readouterr().out
    assert "demo target — a deliberately vulnerable toy agent" in out
    scan = json.loads((tmp_path / "out" / "outputs" /
                       "hermes_action_surface_scan.json").read_text())
    crit = [s for s in scan["surfaces"] if s["verdict"] == "UNGUARDED_CRITICAL_LIVE_SINK"]
    assert crit, "demo must guarantee an UNGUARDED_CRITICAL_LIVE_SINK"
    assert any(s["file_path"] == "app.py" and s["sink_name"] == "eval" for s in crit)
    html = tmp_path / "out" / "outputs" / "shield_customer_report.html"
    assert html.exists() and html.stat().st_size > 0, "demo must produce the full HTML report"


# ---- task 4: full Apache-2.0 licence, stub gone everywhere ----

def test_licence_is_complete_apache_2_0():
    text = (_PKG_ROOT / "LICENSE").read_text(encoding="utf-8")
    for marker in (
        "Apache License",
        "Version 2.0, January 2004",
        "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION",
        "1. Definitions.",
        "9. Accepting Warranty or Additional Liability.",
        "END OF TERMS AND CONDITIONS",
        "APPENDIX: How to apply the Apache License to your work.",
        "Copyright 2026 Hermes Shield",
    ):
        assert marker in text, f"LICENSE is missing required Apache-2.0 text: {marker!r}"
    assert len(text) > 10_000, "LICENSE looks truncated — the full Apache-2.0 text is ~11 kB"
    assert "stub" not in text and "replace this" not in text


def test_readme_licence_line_is_clean():
    readme = (_PKG_ROOT / "README.md").read_text(encoding="utf-8")
    # markdown-link agnostic: "Licensed under [Apache-2.0](LICENSE)" is clean
    assert "Licensed under" in readme and "Apache-2.0" in readme
    for stale in ("placeholder pending", "evaluation use only", "Audit and evaluation use only"):
        assert stale not in readme, f"stale licence wording still in README: {stale!r}"


# ---- task 5: PyPI-facing metadata ----

def test_pyproject_pypi_metadata_complete():
    toml = (_PKG_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "authors" in toml and "hello@hermesshield.ai" in toml
    assert "[project.urls]" in toml
    for url_key in ("Homepage", "Repository", "Changelog"):
        assert url_key in toml
    for classifier in (
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.13",
    ):
        assert classifier in toml
    # dual console scripts: `uvx hermes-shield-scanner scan .` needs the package-named entry
    assert 'hermes-shield = "hermes_shield.shield_cli:main"' in toml
    assert 'hermes-shield-scanner = "hermes_shield.shield_cli:main"' in toml
    # the core stays stdlib-only
    assert "dependencies = []" in toml
