"""S7.4 — wiring the whole-repo AGENTIC AI finder (ai_finder + ai_verify) into the real scan.

Locks the four contract points from the wiring task:

  (1) OFF by default is BYTE-IDENTICAL — with HERMES_SHIELD_AI_FINDER unset the finder is never invoked and
      the scan/report is unchanged (even if ai_finder.find WOULD have injected surfaces).
  (2) A finder surface is ALWAYS advisory — detection_source == "ai_suspected", verdict AI_SUSPECTED_REVIEW,
      and it can NEVER drive the RED/AMBER/BLUE band or the deterministic block count.
  (3) A broken/absent finder backend FAILS LOUD — _finder_agent (and find) raise AIAgentError instead of the
      old silent "", and the wiring records a VISIBLE failed status while the deterministic scan still
      completes (fail-loud tier, fail-open scan).
  (4) Dedup — a finder finding that coincides with an existing surface is not double-reported.
"""
from __future__ import annotations

import pytest

from hermes_shield import scan_hermes as SH
from hermes_shield import ai_finder
from hermes_shield import ai_verify
from hermes_shield import install_report as IR
from hermes_shield import shield_report as SR
from hermes_shield.ai_assist import AIAgentError


# --- fixtures --------------------------------------------------------------------------------------

def _repo(tmp_path):
    """A repo with one static-visible sink and one file holding a cross-file delegation gateway that the
    static engine has no signature for — the exact 'agent plumbing' the finder is meant to surface."""
    (tmp_path / "poster.py").write_text(
        "import subprocess\n"
        "def post(item):\n"
        "    subprocess.run(['post', item])\n")
    (tmp_path / "agent.py").write_text(
        "def run_agent(orchestrator, task):\n"
        "    return orchestrator.delegate(task)\n")
    return tmp_path


# a finder agent stub: returns canned STRICT-JSON referencing a REAL call in agent.py, so find() runs the
# real repo_map + the real ai_verify AST gate (AI proposes, deterministic disposes) — no live claude CLI.
_FAKE_FINDING = ('[{"file": "agent.py", "line": 2, "call": "orchestrator.delegate(task)", '
                 '"capability": "cross-file-delegation", "why": "LLM-chosen delegate", '
                 '"evidence_path": ["agent.py:2"], "confidence": 0.8}]')


def _stub_agent(*_a, **_k):
    def run(_prompt, _cwd):
        return _FAKE_FINDING
    return run


def _out(tmp_path):
    d = tmp_path / "out"
    d.mkdir(exist_ok=True)
    return d


# --- (1) OFF is byte-identical ---------------------------------------------------------------------

def test_ai_deep_off_is_byte_identical(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    monkeypatch.delenv("HERMES_SHIELD_AI_FINDER", raising=False)

    # baseline: finder OFF, find() untouched
    base = SH.run_scan(root, out_dir=_out(tmp_path))
    base_html = SR.build_html(base, "demo", root=str(root))
    base_md = SR.build_report(base, "demo", root=str(root))
    base_static = sorted(s.stable_id for s in base["surfaces"])

    # OFF again, but now ai_finder.find is booby-trapped: if the gate ever calls it, the surfaces change.
    called = {"n": 0}

    def _boom(*_a, **_k):
        called["n"] += 1
        return {"model": "x", "verified": [{"file": "agent.py", "line": 2,
                "call": "orchestrator.delegate(task)", "capability": "x"}],
                "n_proposed": 1, "n_verified": 1, "fabrication_rate": 0.0}

    monkeypatch.setattr(ai_finder, "find", _boom)
    off = SH.run_scan(root, out_dir=_out(tmp_path))

    assert called["n"] == 0, "finder must NOT run when HERMES_SHIELD_AI_FINDER is unset"
    assert off["ai_finder"] == {}
    assert not any(getattr(s, "detection_source", "static") == "ai_suspected" for s in off["surfaces"])
    assert sorted(s.stable_id for s in off["surfaces"]) == base_static
    assert SR.build_html(off, "demo", root=str(root)) == base_html
    assert SR.build_report(off, "demo", root=str(root)) == base_md


# --- (2) a finder surface is advisory-only and never drives the band -------------------------------

def test_finder_surface_is_advisory_and_never_drives_band(tmp_path, monkeypatch):
    root = _repo(tmp_path)

    # band + headline with finder OFF
    monkeypatch.delenv("HERMES_SHIELD_AI_FINDER", raising=False)
    off = SH.run_scan(root, out_dir=_out(tmp_path))
    off_html = SR.build_html(off, "demo", root=str(root))
    off_band = off_html.split('<div class="banner ', 1)[1][:5]
    off_ir = IR.build_report(root, off)

    # band + headline with finder ON (real AST gate, stubbed agent)
    monkeypatch.setenv("HERMES_SHIELD_AI_FINDER", "1")
    monkeypatch.setattr(ai_finder, "_finder_agent", _stub_agent)
    on = SH.run_scan(root, out_dir=_out(tmp_path))

    # the finder actually appended a verified advisory surface
    fs = [s for s in on["surfaces"]
          if getattr(s, "detection_source", "static") == "ai_suspected" and s.file_path == "agent.py"]
    assert fs, "finder should append its AST-verified delegation surface"
    finder = fs[0]
    assert finder.verdict == "AI_SUSPECTED_REVIEW"
    assert finder.live_promotion_verdict == "REVIEW"
    assert on["ai_finder"]["ai_finder_status"] == "ok"
    assert on["ai_finder"]["ai_finder_added"] >= 1

    # it can NEVER hold a deterministic band-driving verdict...
    assert finder.verdict not in ("BLOCK_LIVE_PROMOTION", "GUARD_LOST", "UNGUARDED_CRITICAL_LIVE_SINK")

    # ...and the band + deterministic headline are IDENTICAL to the finder-OFF run
    on_html = SR.build_html(on, "demo", root=str(root))
    on_band = on_html.split('<div class="banner ', 1)[1][:5]
    assert on_band == off_band, "an advisory finder surface must not flip RED/AMBER/BLUE"
    on_ir = IR.build_report(root, on)
    assert on_ir["non_gated_vulnerable"] == off_ir["non_gated_vulnerable"]
    assert on_ir["total_action_surfaces"] == off_ir["total_action_surfaces"]
    assert on_ir["overall_rating"] == off_ir["overall_rating"]

    # the finder file stays out of the deterministic 'Reachable in-repo' table but appears in its own section
    reachable = on_html.split("Reachable in-repo", 1)[1].split("Fix plan", 1)[0]
    assert "agent.py" not in reachable
    md = SR.build_report(on, "demo", root=str(root))
    assert "agent.py" in md.split("AI-suspected surfaces", 1)[1]


# --- (3) a broken finder backend fails LOUD, not silent-empty --------------------------------------

def test_finder_agent_missing_cli_raises(monkeypatch):
    monkeypatch.setattr(ai_finder.shutil, "which", lambda _n: None)
    run = ai_finder._finder_agent("claude-fable-5", 5)
    with pytest.raises(AIAgentError):
        run("prompt", "/tmp")


def test_find_propagates_backend_failure(tmp_path):
    """find() must NOT swallow a backend failure into an empty result — a broken backend is not 'nothing
    found'. A custom agent that raises AIAgentError propagates out of find()."""
    def _broken(_model, _timeout):
        def run(_p, _c):
            raise AIAgentError("claude finder CLI not found on PATH")
        return run

    with pytest.raises(AIAgentError):
        ai_finder.find(tmp_path, static_surfaces=[], agent=_broken("m", 1))


def test_wiring_records_failed_status_and_scan_completes(tmp_path, monkeypatch):
    """Wiring: a broken finder backend surfaces a VISIBLE failed status (fail-loud tier) while the
    deterministic scan still completes with its static surfaces intact (fail-open scan)."""
    root = _repo(tmp_path)
    monkeypatch.setenv("HERMES_SHIELD_AI_FINDER", "1")

    def _broken_agent(*_a, **_k):
        def run(_p, _c):
            raise AIAgentError("claude finder CLI not found on PATH — install it")
        return run

    monkeypatch.setattr(ai_finder, "_finder_agent", _broken_agent)
    scan = SH.run_scan(root, out_dir=_out(tmp_path))

    assert scan["ai_finder"]["ai_finder_status"] == "failed"
    assert "ai_finder_error" in scan["ai_finder"]
    # deterministic scan still produced its static surfaces; no silent finder surface leaked in
    assert any(getattr(s, "detection_source", "static") == "static" for s in scan["surfaces"])
    assert not any(getattr(s, "detection_source", "static") == "ai_suspected" for s in scan["surfaces"])


# --- (4) dedup: never double-report a sink another tier already has --------------------------------

def test_finder_dedups_against_existing_surface(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    monkeypatch.setenv("HERMES_SHIELD_AI_FINDER", "1")

    # stub the finder to 'discover' the SAME static subprocess.run sink in poster.py (line 3)
    dup = ('[{"file": "poster.py", "line": 3, "call": "subprocess.run([\'post\', item])", '
           '"capability": "code-exec", "why": "dup", "evidence_path": ["poster.py:3"], '
           '"confidence": 0.9}]')

    def _dup_agent(*_a, **_k):
        return lambda _p, _c: dup

    monkeypatch.setattr(ai_finder, "_finder_agent", _dup_agent)
    scan = SH.run_scan(root, out_dir=_out(tmp_path))

    poster_ai = [s for s in scan["surfaces"]
                 if s.file_path == "poster.py" and getattr(s, "detection_source", "static") == "ai_suspected"]
    assert poster_ai == [], "the finder must not double-report a sink static already covers"
    assert scan["ai_finder"]["ai_finder_deduped"] >= 1
