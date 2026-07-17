"""
test_s8_87_out_dir — scan artefacts must NOT be written into the scanner package (S8.87, product shape).

The historical bug wrote every scan into the scanner's own package dir regardless of target. This locks:
  - `--out DIR` writes artefacts under DIR/outputs, never into the installed package,
  - env HERMES_SHIELD_OUT does the same,
  - no override defaults to ./shield-report/ in CWD (never the package, never the target repo).
"""
from __future__ import annotations
from pathlib import Path

from hermes_shield import scan_hermes as SH

_PKG = Path(SH.__file__).resolve().parent


def _outside_package(p: Path) -> bool:
    return _PKG not in (p, *p.parents) and p not in (_PKG, *_PKG.parents)


def test_explicit_out_arg(tmp_path):
    out, base = SH.resolve_out_paths(tmp_path, out_arg=str(tmp_path / "custom"))
    assert out == (tmp_path / "custom" / "outputs").resolve()
    assert base == (tmp_path / "custom" / "baseline" / "scan_baseline.json").resolve()
    assert _outside_package(out)


def test_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_SHIELD_OUT", str(tmp_path / "envout"))
    out, base = SH.resolve_out_paths(tmp_path)
    assert out == (tmp_path / "envout" / "outputs").resolve()
    assert _outside_package(out)


def test_default_out_is_cwd_never_package(tmp_path, monkeypatch):
    monkeypatch.delenv("HERMES_SHIELD_OUT", raising=False)
    monkeypatch.chdir(tmp_path)
    foreign = tmp_path / "some_other_repo"
    foreign.mkdir()
    out, base = SH.resolve_out_paths(foreign)
    assert out == (tmp_path / "shield-report" / "outputs").resolve()
    assert _outside_package(out)
    assert _outside_package(base)


def test_default_out_never_inside_target(tmp_path, monkeypatch):
    # the target repo stays strictly read-only: default out dir is CWD, not the target
    monkeypatch.delenv("HERMES_SHIELD_OUT", raising=False)
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "victim_repo"
    target.mkdir()
    out, _ = SH.resolve_out_paths(target)
    assert target not in (out, *out.parents)


def test_end_to_end_writes_to_out_dir(tmp_path, monkeypatch):
    # scan a tiny repo with --out; artefacts land under the out dir, package untouched.
    monkeypatch.delenv("HERMES_SHIELD_OUT", raising=False)
    target = tmp_path / "mini_repo"
    target.mkdir()
    (target / "app.py").write_text("import os\ndef f(x):\n    os.system(x)\n")
    outdir = tmp_path / "report_here"
    rc = SH.main(["--scan", "--root", str(target), "--out", str(outdir), "--quiet"])
    assert rc == 0
    produced = list((outdir / "outputs").glob("*.json"))
    assert produced, "expected scan artefacts under the --out dir"
    assert (outdir / "outputs" / "hermes_action_surface_scan.json").exists()
    assert not list(_PKG.rglob("shield-report")), "package dir must stay clean"
