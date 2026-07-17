"""
test_s8_89_semgrep_comparator — semgrep as an ISOLATED, ATTRIBUTED comparator (Gate #4 / ITEM 4 / S8.89).

Locks:
  - semgrep json parses into our capability vocab, attributed source="semgrep-classic",
  - merge_attribute never merges into our headline (separate both / semgrep_only sets),
  - the head-to-head note is attributed and keeps semgrep in its own tier,
  - the default offline scan is UNCHANGED (flag off -> no semgrep artefacts, run() never called),
  - flag on (mocked semgrep) -> the comparator artefacts are written.
"""
from __future__ import annotations
import json
import sys
from pathlib import Path
from types import SimpleNamespace


from hermes_shield import semgrep_runner as SG  # noqa: E402
from hermes_shield import scan_hermes as SH  # noqa: E402

_MOCK = json.dumps({"results": [
    {"path": "pkg/x.py", "start": {"line": 10},
     "check_id": "python.lang.security.eval", "extra": {"severity": "ERROR",
      "metadata": {"cwe": ["CWE-94: Code Injection"], "confidence": "HIGH"}}},
    {"path": "web/t.html", "start": {"line": 3},
     "check_id": "generic.xss", "extra": {"severity": "WARNING",
      "metadata": {"cwe": ["CWE-79: XSS"], "confidence": "LOW"}}},
]})


def test_parse_maps_and_attributes():
    r = SG.parse(_MOCK)
    assert r["count"] == 2
    caps = {f["capability"] for f in r["findings"]}
    assert "code_exec" in caps                       # CWE-94 -> code_exec (in-domain)
    assert "classic_web" in caps                     # CWE-79 -> out-of-domain noise
    assert all(f["source"] == "semgrep-classic" for f in r["findings"])


def test_merge_attribute_never_merges_headline():
    findings = SG.parse(_MOCK)["findings"]
    hermes = [SimpleNamespace(file_path="pkg/x.py", line_start=10, sink_line=10, capability="code_exec")]
    m = SG.merge_attribute(hermes, findings)
    assert m["counts"]["both"] == 1                  # the code_exec overlaps
    assert m["counts"]["semgrep_only"] == 1          # the XSS is semgrep-only
    assert m["counts"]["hermes_total"] == 1


def test_head_to_head_is_attributed():
    findings = SG.parse(_MOCK)["findings"]
    hermes = [SimpleNamespace(file_path="pkg/x.py", line_start=10, sink_line=10, capability="code_exec")]
    note = SG.head_to_head(hermes, findings, hermes_proven=0, hermes_non_gated=1)
    assert "semgrep-classic" in note
    assert "Hermes engine" in note
    assert "never" in note.lower()                   # explicit "never merged into headline" framing


def test_default_scan_unchanged_no_semgrep(tmp_path, monkeypatch):
    monkeypatch.delenv("HERMES_SHIELD_SEMGREP", raising=False)
    called = {"n": 0}
    monkeypatch.setattr(SG, "run", lambda *a, **k: called.__setitem__("n", called["n"] + 1) or {})
    target = tmp_path / "mini"
    target.mkdir()
    (target / "app.py").write_text("import os\ndef f(x):\n    os.system(x)\n")
    outdir = tmp_path / "out"
    SH.main(["--scan", "--root", str(target), "--out", str(outdir), "--quiet"])
    assert called["n"] == 0, "semgrep must NOT run unless the flag is set"
    assert not (outdir / "outputs" / "semgrep").exists()


def test_flag_on_emits_comparator(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_SHIELD_SEMGREP", "1")
    monkeypatch.setattr(SG, "run", lambda *a, **k: SG.parse(_MOCK))
    target = tmp_path / "mini"
    target.mkdir()
    (target / "app.py").write_text("import os\ndef f(x):\n    os.system(x)\n")
    outdir = tmp_path / "out"
    SH.main(["--scan", "--root", str(target), "--out", str(outdir), "--quiet"])
    note = outdir / "outputs" / "semgrep" / "semgrep_head_to_head.md"
    comp = outdir / "outputs" / "semgrep" / "semgrep_comparator.json"
    assert note.exists() and comp.exists(), "flag-on must emit the attributed comparator"
    assert "semgrep-classic" in note.read_text()
