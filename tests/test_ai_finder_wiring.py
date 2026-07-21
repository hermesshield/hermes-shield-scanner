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

import json
import os

import pytest

from hermes_shield import scan_hermes as SH
from hermes_shield import shield_cli as CLI
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


# --- (5) DE-MOCKED TRIGGER: the real --ai-deep flag path fires the finder end-to-end -----------------
# These drive the ACTUAL trigger (env/flag -> finder block ENTERS -> ai_finder.find runs for real -> a
# verified ai_suspected surface appears). Only the leaf claude-CLI subprocess is stubbed via _finder_agent;
# ai_finder.find itself is NEVER monkeypatched — so these prove the trigger wiring, not just the append.

def _spy_run_scan(monkeypatch):
    """Wrap the REAL run_scan so a test can inspect the scan dict produced by an argv-driven main()."""
    real = SH.run_scan
    box = {}

    def _spy(*a, **k):
        r = real(*a, **k)
        box["scan"] = r
        return r

    monkeypatch.setattr(SH, "run_scan", _spy)
    return box


def test_scan_hermes_ai_deep_flag_fires_finder(tmp_path, monkeypatch):
    """`scan_hermes.main([... , '--ai-deep'])` must set the env gate BEFORE run_scan and drive the finder
    block to append a verified advisory surface — without HERMES_SHIELD_AI_FINDER pre-set in the env."""
    root = _repo(tmp_path)
    monkeypatch.delenv("HERMES_SHIELD_AI_FINDER", raising=False)
    monkeypatch.setattr(ai_finder, "_finder_agent", _stub_agent)   # stub only the leaf CLI, NOT find()
    box = _spy_run_scan(monkeypatch)

    rc = SH.main(["--scan", "--root", str(root), "--ai-deep",
                  "--out", str(_out(tmp_path)), "--quiet"])
    assert rc == 0
    scan = box["scan"]
    assert scan["ai_finder"]["ai_finder_status"] == "ok"
    assert scan["ai_finder"]["ai_finder_added"] >= 1
    assert any(getattr(s, "detection_source", "static") == "ai_suspected"
               and s.file_path == "agent.py" for s in scan["surfaces"])


def test_shield_cli_scan_ai_deep_fires_finder(tmp_path, monkeypatch):
    """The SHIPPED CLI: `hermes-shield scan <repo> --ai-deep` must set the env gate and fire the finder
    through the in-process scan_hermes call. `claude` availability is stubbed present."""
    root = _repo(tmp_path)
    monkeypatch.delenv("HERMES_SHIELD_AI_FINDER", raising=False)
    monkeypatch.setattr(CLI, "_tool_available", lambda n: True)     # pretend claude is on PATH
    monkeypatch.setattr(ai_finder, "_finder_agent", _stub_agent)    # stub only the leaf CLI, NOT find()
    box = _spy_run_scan(monkeypatch)

    rc = CLI.main(["scan", str(root), "--ai-deep", "--out", str(_out(tmp_path)), "--quiet"])
    assert rc == 0
    assert os.environ.get("HERMES_SHIELD_AI_FINDER") == "1"
    scan = box["scan"]
    assert scan["ai_finder"]["ai_finder_status"] == "ok"
    assert scan["ai_finder"]["ai_finder_added"] >= 1
    assert any(getattr(s, "detection_source", "static") == "ai_suspected"
               and s.file_path == "agent.py" for s in scan["surfaces"])


def test_shield_cli_ai_deep_graceful_degrade_without_claude(tmp_path, monkeypatch, capsys):
    """No `claude` on PATH: --ai-deep must NOT set the finder gate and must NOT fire the finder; the core
    deterministic scan still completes (fail-open, graceful degrade — mirrors --ai)."""
    root = _repo(tmp_path)
    monkeypatch.delenv("HERMES_SHIELD_AI_FINDER", raising=False)
    monkeypatch.setattr(CLI, "_tool_available", lambda n: False)    # claude absent

    def _must_not_run(*_a, **_k):
        raise AssertionError("finder backend must not be invoked when claude is absent")

    monkeypatch.setattr(ai_finder, "_finder_agent", _must_not_run)
    box = _spy_run_scan(monkeypatch)

    rc = CLI.main(["scan", str(root), "--ai-deep", "--out", str(_out(tmp_path)), "--quiet"])
    assert rc == 0
    assert os.environ.get("HERMES_SHIELD_AI_FINDER") != "1"
    assert box["scan"]["ai_finder"] == {}
    assert "--ai-deep not available" in capsys.readouterr().err


# --- (6) exit-0 content-refusal is fail-loud, not a silent zero ------------------------------------

def test_exit0_content_refusal_raises(monkeypatch):
    """A backend that AUP-refuses on STDOUT with exit code 0 (the observed claude-fable-5 behaviour) must
    raise AIAgentError — NOT return '' that _parse turns into a silent []/status=ok."""
    refusal = ("API Error: Fable 5's safeguards flagged this message as violating our usage policies. "
               "Claude Code can't respond to this request with Fable 5. "
               "https://www.anthropic.com/legal/aup")

    class _Proc:
        returncode = 0
        stdout = refusal
        stderr = ""

    monkeypatch.setattr(ai_finder.shutil, "which", lambda _n: "/usr/bin/claude")
    monkeypatch.setattr(ai_finder.subprocess, "run", lambda *a, **k: _Proc())
    run = ai_finder._finder_agent("claude-fable-5", 5)
    with pytest.raises(AIAgentError):
        run("prompt", "/tmp")


def test_wiring_records_failed_status_on_refusal(tmp_path, monkeypatch):
    """End-to-end: an exit-0 refusal from the real _finder_agent surfaces a VISIBLE failed status via the
    wiring (fail-loud tier) while the deterministic scan still completes (fail-open)."""
    root = _repo(tmp_path)
    monkeypatch.setenv("HERMES_SHIELD_AI_FINDER", "1")
    refusal = "I can't respond to this request. https://www.anthropic.com/legal/aup"

    class _Proc:
        returncode = 0
        stdout = refusal
        stderr = ""

    monkeypatch.setattr(ai_finder.shutil, "which", lambda _n: "/usr/bin/claude")
    monkeypatch.setattr(ai_finder.subprocess, "run", lambda *a, **k: _Proc())
    scan = SH.run_scan(root, out_dir=_out(tmp_path))

    assert scan["ai_finder"]["ai_finder_status"] == "failed"
    assert "refused" in scan["ai_finder"]["ai_finder_error"].lower()
    assert not any(getattr(s, "detection_source", "static") == "ai_suspected" for s in scan["surfaces"])


# --- (7) FAIL-LOUD SURFACE: the finder tier status reaches the JSON artefact + the console -----------
# HIGH gap closed: ai_finder_status="failed" used to live ONLY in the in-memory scan dict, so in the
# shipped CLI a broken/refusing AI backend was operator-indistinguishable from "ran, found nothing".

_EXPECTED_DEFAULT_JSON_KEYS = {
    "root", "head", "scan_time", "files_scanned", "scanner_version", "surfaces", "ingresses"}


def test_json_artefact_omits_ai_finder_key_by_default(tmp_path, monkeypatch):
    """Default scan (no --ai-deep): the JSON artefact must NOT carry an `ai_finder` key — the top-level
    key set is byte-identical to the pre-change shape."""
    root = _repo(tmp_path)
    monkeypatch.delenv("HERMES_SHIELD_AI_FINDER", raising=False)
    out = _out(tmp_path)
    rc = SH.main(["--scan", "--root", str(root), "--out", str(out), "--quiet"])
    assert rc == 0
    doc = json.loads((out / "outputs" / "hermes_action_surface_scan.json").read_text(encoding="utf-8"))
    assert "ai_finder" not in doc
    assert set(doc) == _EXPECTED_DEFAULT_JSON_KEYS


def test_failed_finder_status_in_json_artefact_and_console(tmp_path, monkeypatch, capsys):
    """A broken backend under --ai-deep: the FAILED status + reason must appear IN the JSON artefact and
    on ONE console line (not just the in-memory scan dict)."""
    root = _repo(tmp_path)
    monkeypatch.delenv("HERMES_SHIELD_AI_FINDER", raising=False)

    def _broken_agent(*_a, **_k):
        def run(_p, _c):
            raise AIAgentError("claude finder CLI not found on PATH — install it")
        return run

    monkeypatch.setattr(ai_finder, "_finder_agent", _broken_agent)
    out = _out(tmp_path)
    # NB: no --quiet, so the console summary (and the new finder line) actually renders.
    rc = SH.main(["--scan", "--root", str(root), "--ai-deep", "--out", str(out)])
    assert rc == 0

    doc = json.loads((out / "outputs" / "hermes_action_surface_scan.json").read_text(encoding="utf-8"))
    assert doc["ai_finder"]["ai_finder_status"] == "failed"
    assert "ai_finder_error" in doc["ai_finder"]

    printed = capsys.readouterr().out
    assert "AI finder: FAILED" in printed


def test_ok_finder_status_in_json_artefact_and_console(tmp_path, monkeypatch, capsys):
    """A finder that runs OK under --ai-deep: the ok status + counts appear in the JSON artefact and the
    console line names the model + proposed/verified/added counts."""
    root = _repo(tmp_path)
    monkeypatch.delenv("HERMES_SHIELD_AI_FINDER", raising=False)
    monkeypatch.setattr(ai_finder, "_finder_agent", _stub_agent)
    out = _out(tmp_path)
    rc = SH.main(["--scan", "--root", str(root), "--ai-deep", "--out", str(out)])
    assert rc == 0

    doc = json.loads((out / "outputs" / "hermes_action_surface_scan.json").read_text(encoding="utf-8"))
    assert doc["ai_finder"]["ai_finder_status"] == "ok"
    assert doc["ai_finder"]["ai_finder_added"] >= 1

    printed = capsys.readouterr().out
    assert "AI finder:" in printed and "FAILED" not in printed


# --- (8) FIX 2: nonzero exit is a failure UNLESS a JSON array actually parsed ------------------------

def _proc(returncode, stdout, stderr=""):
    class _P:
        pass
    _P.returncode = returncode
    _P.stdout = stdout
    _P.stderr = stderr
    return _P()


def test_nonzero_exit_with_nonjson_stdout_raises(monkeypatch):
    """FIX 2: a nonzero exit carrying NON-empty, non-JSON, non-refusal stdout must raise AIAgentError —
    previously it fell through _parse -> [] -> status 'ok' (a silent zero)."""
    monkeypatch.setattr(ai_finder.shutil, "which", lambda _n: "/usr/bin/claude")
    monkeypatch.setattr(ai_finder.subprocess, "run",
                        lambda *a, **k: _proc(1, "diagnostic chatter, no findings array here", "boom"))
    run = ai_finder._finder_agent("sonnet", 5)
    with pytest.raises(AIAgentError):
        run("prompt", "/tmp")


def test_nonzero_exit_with_valid_json_array_is_kept(monkeypatch):
    """FIX 2: a nonzero exit that DID emit a valid JSON findings array is NOT a failure — it returns and
    the findings parse (the one carve-out to the nonzero-exit rule)."""
    monkeypatch.setattr(ai_finder.shutil, "which", lambda _n: "/usr/bin/claude")
    monkeypatch.setattr(ai_finder.subprocess, "run", lambda *a, **k: _proc(2, _FAKE_FINDING, ""))
    run = ai_finder._finder_agent("sonnet", 5)
    out = run("prompt", "/tmp")
    assert ai_finder._parse(out), "valid findings JSON on a nonzero exit must survive"


def test_nonzero_exit_with_empty_stdout_still_raises(monkeypatch):
    """FIX 2 regression: the original behaviour (nonzero exit + empty stdout -> raise) is preserved."""
    monkeypatch.setattr(ai_finder.shutil, "which", lambda _n: "/usr/bin/claude")
    monkeypatch.setattr(ai_finder.subprocess, "run", lambda *a, **k: _proc(3, "", "fatal: crashed"))
    run = ai_finder._finder_agent("sonnet", 5)
    with pytest.raises(AIAgentError):
        run("prompt", "/tmp")


def test_nonzero_exit_with_json_error_payload_raises(monkeypatch):
    """FIX 2 hardening: a nonzero exit whose stdout is a JSON ERROR OBJECT carrying an embedded array span
    (e.g. an overload / rate-limit error) must FAIL LOUD, not masquerade as an empty result. The guard now
    requires a TOP-LEVEL JSON array, so the embedded `[]` in `{"...":[]}` no longer defeats it."""
    monkeypatch.setattr(ai_finder.shutil, "which", lambda _n: "/usr/bin/claude")
    overload = '{"type":"error","errors":[],"message":"overloaded_error: server overloaded"}'
    assert ai_finder._is_toplevel_json_array(overload) is None       # object, not a top-level array
    assert ai_finder._json_array(overload) == []                     # the embedded span DID parse (the old hole)
    assert ai_finder._is_toplevel_json_array(_FAKE_FINDING) is not None  # a genuine array still trusted
    monkeypatch.setattr(ai_finder.subprocess, "run", lambda *a, **k: _proc(1, overload, ""))
    run = ai_finder._finder_agent("sonnet", 5)
    with pytest.raises(AIAgentError):
        run("prompt", "/tmp")


# --- (9) FIX 3: a refusal with a stray bracket pair is still detected --------------------------------

def test_is_refusal_truth_table():
    """_is_refusal is now ENRICHMENT-ONLY — the STRUCTURAL guard (exit 0 + no parseable JSON array) decides
    pass/fail; _is_refusal only picks the friendlier reason text. It keeps the existing true-negatives AND
    detects a refusal that merely contains a non-parsing '[x]'."""
    # legitimate empty result — NOT a refusal
    assert ai_finder._is_refusal("[]") is False
    # a real findings array — NOT a refusal
    assert ai_finder._is_refusal(_FAKE_FINDING) is False
    # terse 'nothing' prose without a signature — NOT a refusal (yet FAILS structurally at the agent; see
    # test_finder_exit0_arbitrary_prose_without_json_raises)
    assert ai_finder._is_refusal("found nothing") is False
    # a real AUP refusal — IS a refusal
    real = ("API Error: safeguards flagged this message as violating our usage policies. "
            "Claude Code can't respond to this request. https://www.anthropic.com/legal/aup")
    assert ai_finder._is_refusal(real) is True
    # newly-added markers enrich the reason for the common phrasings
    assert ai_finder._is_refusal("I can't help with this. Acceptable Use Policy.") is True
    # a refusal carrying a stray, non-parsing bracket pair is STILL detected
    assert ai_finder._is_refusal(
        "I can't respond to this request [x] — usage policies. https://www.anthropic.com/legal/aup") is True


# --- (10) SHIP-BLOCKER (structural): exit-0 with no parseable JSON array = protocol violation -----------
# The finder's STRICT-JSON contract: on exit 0 the ONLY honest reply is a parseable JSON array (empty [] =
# nothing-found, or findings). Anything else on exit 0 — a non-marker refusal, arbitrary prose, truncation —
# is a protocol violation the agent must FAIL LOUD on, never fall through _parse -> [] -> status "ok".

_NON_MARKER_REFUSAL = "I'm sorry, but I won't be able to analyse this repository for you."
_PROSE_NO_JSON = "Here is a prose summary of the repo, but I have produced no structured findings array."


def test_finder_exit0_non_marker_refusal_raises(monkeypatch):
    """A refusal phrased ENTIRELY OUTSIDE the marker set (exit 0, no JSON array) must raise on STRUCTURE —
    the core silent-clean SHIP-BLOCKER. Marker matching alone would have parsed it to [] (a silent zero)."""
    monkeypatch.setattr(ai_finder.shutil, "which", lambda _n: "/usr/bin/claude")
    monkeypatch.setattr(ai_finder.subprocess, "run",
                        lambda *a, **k: _proc(0, _NON_MARKER_REFUSAL, ""))
    run = ai_finder._finder_agent("sonnet", 5)
    with pytest.raises(AIAgentError) as ei:
        run("prompt", "/tmp")
    assert "parseable json array" in str(ei.value).lower()


def test_finder_exit0_arbitrary_prose_without_json_raises(monkeypatch):
    """Arbitrary exit-0 prose carrying no JSON array must raise (protocol violation), not fall through to []."""
    monkeypatch.setattr(ai_finder.shutil, "which", lambda _n: "/usr/bin/claude")
    monkeypatch.setattr(ai_finder.subprocess, "run",
                        lambda *a, **k: _proc(0, _PROSE_NO_JSON, ""))
    run = ai_finder._finder_agent("sonnet", 5)
    with pytest.raises(AIAgentError) as ei:
        run("prompt", "/tmp")
    assert "parseable json array" in str(ei.value).lower()


def test_finder_exit0_genuine_empty_array_is_nothing_found_not_raised(monkeypatch):
    """MUST-NOT-OVER-CORRECT: a genuine `[]` (valid JSON array) on exit 0 is a real nothing-found — it
    returns and parses to no findings, it does NOT raise."""
    monkeypatch.setattr(ai_finder.shutil, "which", lambda _n: "/usr/bin/claude")
    monkeypatch.setattr(ai_finder.subprocess, "run", lambda *a, **k: _proc(0, "[]", ""))
    run = ai_finder._finder_agent("sonnet", 5)
    out = run("prompt", "/tmp")
    assert ai_finder._parse(out) == []                      # genuine empty result, no exception


def test_finder_exit0_genuine_finding_is_returned(monkeypatch):
    """A genuine findings array on exit 0 returns and parses to the real finding (the happy path)."""
    monkeypatch.setattr(ai_finder.shutil, "which", lambda _n: "/usr/bin/claude")
    monkeypatch.setattr(ai_finder.subprocess, "run", lambda *a, **k: _proc(0, _FAKE_FINDING, ""))
    run = ai_finder._finder_agent("sonnet", 5)
    out = run("prompt", "/tmp")
    parsed = ai_finder._parse(out)
    assert parsed and parsed[0]["file"] == "agent.py"


# --- (11) SHIP-BLOCKER END-TO-END: the EXACT embedded-`[]` silent-cleans through _finder_agent ----------
# The live hole the previous green suite MISSED: an exit-0 reply that CONTAINS a parseable `[]` defeated the
# lenient `_json_array` guard, so an overload error / refusal / chatty prose was read as "ok/nothing found".
# The strict `_is_toplevel_json_array` gate now fails each loud. Driven through the REAL _finder_agent leaf
# (only the claude subprocess is mocked), then end-to-end through the wiring so a green here means a real hole
# closed, not just a passing unit.

_OVERLOAD_ERR = '{"type":"error","errors":[],"message":"overloaded"}'          # (1) rate-limit/overload OBJECT
_REFUSAL_EMPTY = "I can't help with that. Here is an empty result: []"          # (2) refusal + trailing []
_CHATTY_EMPTY = "Sure, here is my analysis. I found no dangerous surfaces: []"  # (3) chatty prose + trailing []
_NONDICT_LIST = "[1]"                                                            # (4) a non-findings array

_FINDER_SILENT_CLEANS = [
    pytest.param(_OVERLOAD_ERR, id="overload_error_object"),
    pytest.param(_REFUSAL_EMPTY, id="refusal_with_trailing_empty"),
    pytest.param(_CHATTY_EMPTY, id="chatty_prose_with_trailing_empty"),
    pytest.param(_NONDICT_LIST, id="nondict_list_[1]"),
]


@pytest.mark.parametrize("reply", _FINDER_SILENT_CLEANS)
def test_finder_exit0_embedded_empty_silent_clean_raises(reply, monkeypatch):
    """Each exit-0 reply carrying an embedded/ill-typed bracket span must raise AIAgentError on STRUCTURE —
    the lenient `_json_array` guard passed all of these (they CONTAIN a parseable `[]`); the strict top-level
    arbiter fails them loud."""
    monkeypatch.setattr(ai_finder.shutil, "which", lambda _n: "/usr/bin/claude")
    monkeypatch.setattr(ai_finder.subprocess, "run", lambda *a, **k: _proc(0, reply, ""))
    run = ai_finder._finder_agent("sonnet", 5)
    with pytest.raises(AIAgentError):
        run("prompt", "/tmp")


@pytest.mark.parametrize("reply", _FINDER_SILENT_CLEANS)
def test_wiring_records_failed_status_on_embedded_empty_silent_clean(reply, tmp_path, monkeypatch):
    """End-to-end: each exit-0 silent-clean from the REAL _finder_agent surfaces a VISIBLE failed status via
    the wiring (fail-loud tier) while the deterministic scan still completes and no advisory surface leaks."""
    root = _repo(tmp_path)
    monkeypatch.setenv("HERMES_SHIELD_AI_FINDER", "1")

    monkeypatch.setattr(ai_finder.shutil, "which", lambda _n: "/usr/bin/claude")
    monkeypatch.setattr(ai_finder.subprocess, "run", lambda *a, **k: _proc(0, reply, ""))
    scan = SH.run_scan(root, out_dir=_out(tmp_path))

    assert scan["ai_finder"]["ai_finder_status"] == "failed", f"{reply!r} must fail the finder tier loud"
    assert "ai_finder_error" in scan["ai_finder"]
    assert not any(getattr(s, "detection_source", "static") == "ai_suspected" for s in scan["surfaces"])
    # the deterministic scan still stands
    assert any(getattr(s, "detection_source", "static") == "static" for s in scan["surfaces"])


def test_finder_exit0_fenced_genuine_finding_is_returned(monkeypatch):
    """MUST-NOT-OVER-CORRECT: a genuine findings array wrapped in a ```json fence still parses to the real
    finding (the strict arbiter strips the fence) — a well-behaved fenced reply is not mis-failed."""
    monkeypatch.setattr(ai_finder.shutil, "which", lambda _n: "/usr/bin/claude")
    fenced = "```json\n" + _FAKE_FINDING + "\n```"
    monkeypatch.setattr(ai_finder.subprocess, "run", lambda *a, **k: _proc(0, fenced, ""))
    run = ai_finder._finder_agent("sonnet", 5)
    parsed = ai_finder._parse(run("prompt", "/tmp"))
    assert parsed and parsed[0]["file"] == "agent.py"


def test_finder_toplevel_arbiter_rejects_nondict_and_error_object():
    assert ai_finder._is_toplevel_json_array(_OVERLOAD_ERR) is None     # error OBJECT
    assert ai_finder._is_toplevel_json_array("[1]") is None            # non-findings array
    assert ai_finder._is_toplevel_json_array('["x"]') is None          # non-findings array
    assert ai_finder._is_toplevel_json_array("[]") == []              # genuine empty -> passes
    assert ai_finder._is_toplevel_json_array(_FAKE_FINDING) is not None  # genuine findings -> passes
    assert ai_finder._is_toplevel_json_array("```json\n[]\n```") == []  # fenced empty -> passes
    assert ai_finder._json_array(_OVERLOAD_ERR) == []                  # OLD lenient arbiter still accepts it


def test_default_finder_model_is_not_fable(monkeypatch):
    """Regression guard for B1: the default finder model must not be the AUP-refusing claude-fable-5.
    find() must invoke the agent with the non-refusing default when no model/env override is given."""
    monkeypatch.delenv("HERMES_SHIELD_FINDER_MODEL", raising=False)
    seen = {}

    def _capture_agent(model, timeout):
        seen["model"] = model
        return lambda _p, _c: "[]"

    # drive find() with the default model resolution but a capturing agent factory
    monkeypatch.setattr(ai_finder, "_finder_agent", _capture_agent)
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        ai_finder.find(d, static_surfaces=[])
    assert seen["model"] != "claude-fable-5"
    assert seen["model"] == "sonnet"
