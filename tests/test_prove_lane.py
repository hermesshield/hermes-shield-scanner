"""
test_prove_lane — the PROVEN-LIVE self-attack lane (Phase 0).

Locks the safety-critical contract:
  * a directly-drivable code_exec fixture is PROVEN (nonce fired via the sink, negative control clean,
    reproduced) -> proven_live_poc >= 1;
  * the demo Flask route (untrusted input from the `request` global) is REFUSED -> recipe (needs app
    bootstrap), never promoted;
  * the demo shell tool (subprocess_exec, no entrypoint) is REFUSED -> recipe (outside the Phase-0
    provable set), never promoted;
  * the promotion decision rejects a fired negative control and a non-reproduced proof (promote-only);
  * run_lane never downgrades / removes a finding;
  * the consent gate blocks all execution by default and leaves the default demo scan byte-identical;
  * (bwrap present) network is denied inside the cell.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from hermes_shield import prove
from hermes_shield import shield_cli
from hermes_shield import scan_hermes

_HAS_BWRAP = shutil.which("bwrap") is not None

# The --prove self-attack lane needs Linux + bubblewrap + unprivileged user namespaces (a network-
# isolated sandbox). Hosted CI runners (e.g. GitHub Ubuntu 24.04) restrict user namespaces, so the cell
# can't be built and the lane fails SAFE (inconclusive, never a false proof) — so these proof-exercising
# tests are skipped in CI and where no sandbox exists (macOS/Windows/bwrap-less Linux). They run on any
# real dev machine with a working sandbox. The off-sandbox "refuse cleanly" contract stays covered in CI
# by test_prove_platform_guard.py.
pytestmark = pytest.mark.skipif(
    bool(os.getenv("CI")) or not (sys.platform.startswith("linux") and _HAS_BWRAP),
    reason="--prove needs Linux + bubblewrap + user namespaces (unavailable in CI / off-Linux)")


# --------------------------------------------------------------------------- proofs

def test_prove_demo_promotes_drivable_eval(tmp_path):
    res = prove.prove_demo(out_dir=tmp_path / "out")
    rep = res["report"]
    assert rep["proven_live_poc"] >= 1, "the directly-drivable eval fixture must be PROVEN"
    assert ("eval_tool.py", 14) in set(map(tuple, res["validated"]))
    proven = [r for r in res["records"] if r["verdict"] == "proven"]
    assert proven and proven[0]["file"] == "eval_tool.py"
    r = proven[0]
    # the honest proof shape: nonce fired via the sink, reproduced, negative control clean
    assert r["nonce_effect"]["fired_via_sink"] is True
    assert r["reproduced"] is True
    assert r["negative_control"]["clean"] is True
    assert r["promoted"] is True
    # evidence bundle written to the operator out dir
    ev = tmp_path / "out" / "prove" / "prove_summary.json"
    assert ev.exists()
    summary = json.loads(ev.read_text())
    assert summary["proven"] >= 1


def test_flask_route_needs_app_bootstrap_refused(tmp_path):
    res = prove.prove_demo(out_dir=tmp_path / "out")
    app = [r for r in res["records"] if r["file"] == "app.py"]
    assert app, "the demo Flask route must appear as an attempted surface"
    r = app[0]
    assert r["verdict"] == "refused-recipe" and r["promoted"] is False
    assert "bootstrap" in r["reason"]
    # the recipe still carries the entrypoint evidence (http route) for a human PoC
    assert r["recipe"]["manual_only"] is True
    assert (r["recipe"].get("entrypoint") or {}).get("type") == "http_route"


def test_shell_tool_param_derived_is_proven(tmp_path):
    # Phase-2a: the demo shell tool `run_shell(cmd): subprocess.run(cmd, shell=True)` is param-derived and
    # shell-interpreted -> the prove lane now PROVES it live via the shell canary (was refused pre-2a).
    res = prove.prove_demo(out_dir=tmp_path / "out")
    tools = [r for r in res["records"] if r["file"] == "tools.py"]
    assert tools, "the demo shell tool must appear as an attempted surface"
    r = tools[0]
    assert r["capability"] == "subprocess_exec"
    assert r["verdict"] == "proven" and r["promoted"] is True
    assert r["nonce_effect"]["fired_via_sink"] is True
    assert r["reproduced"] is True and r["negative_control"]["clean"] is True
    # the added /bin/sh execution surface is recorded in the isolation config
    assert "/bin/sh" in r["isolation"].get("added_execution_surface", "")


# --------------------------------------------------------------------------- promote-only logic

def test_decide_promotes_only_reproduced_clean_negative():
    # PROVEN: both positives fired, negative clean
    assert prove.decide(True, True, False) == ("proven", True)
    # negative control fired -> NOT promoted (the canary fired without the payload = inconclusive)
    assert prove.decide(True, True, True) == ("inconclusive", False)
    # not reproduced -> NOT promoted
    assert prove.decide(True, False, False) == ("inconclusive", False)
    # never fired -> NOT promoted
    assert prove.decide(False, False, False) == ("inconclusive", False)


def _fake_scan_one_candidate(root: Path):
    """Build a scan with one candidate-critical code_exec surface whose enclosing callable is NOT
    directly drivable (module-level sink) — the prove lane must refuse it and leave it untouched."""
    (root / "m.py").write_text("import os\neval(os.environ['X'])\n")   # module scope, not drivable
    scan = scan_hermes.run_scan(root)
    return scan


def test_run_lane_is_promote_only_never_downgrades(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    scan = _fake_scan_one_candidate(target)
    before = [(s.file_path, s.capability, s.verdict, s.tainted_reachable) for s in scan["surfaces"]]
    validated, records = prove.run_lane(target, scan, out_dir=tmp_path / "out")
    after = [(s.file_path, s.capability, s.verdict, s.tainted_reachable) for s in scan["surfaces"]]
    assert before == after, "run_lane must NEVER mutate/downgrade a surface"
    assert validated == set(), "a non-drivable candidate must not be promoted"
    assert all(r["promoted"] is False for r in records)


# --------------------------------------------------------------------------- consent gate + byte-identical

def _read_surfaces(out_root: Path):
    # compare the deterministic surface data only (top-level root/head/scan_time carry the incidental
    # temp path + git stamps, which are not part of the core result).
    d = json.loads((out_root / "outputs" / "hermes_action_surface_scan.json").read_text())
    return json.dumps(d["surfaces"], sort_keys=True)


def test_consent_gate_blocks_execution_by_default(tmp_path, monkeypatch, capsys):
    # non-interactive, no consent env, no --yes flag -> must NOT execute, must return non-zero, no report
    monkeypatch.delenv("HERMES_SHIELD_PROVE_CONSENT", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    rc = shield_cli.main(["demo", "--prove", "--quiet", "--out", str(tmp_path / "out")])
    assert rc == 2, "without consent the prove lane must refuse"
    err = capsys.readouterr().err
    assert "NOT confirmed" in err
    assert not (tmp_path / "out" / "prove").exists(), "no evidence dir when consent is refused"


def test_default_demo_scan_byte_identical_with_prove_off(tmp_path, monkeypatch):
    # the deterministic core is unchanged when --prove is OFF (the default): two plain demo runs match,
    # and no proof was ever run (proven_live_poc == 0).
    monkeypatch.chdir(tmp_path)
    a = tmp_path / "a"
    b = tmp_path / "b"
    assert shield_cli.main(["demo", "--quiet", "--out", str(a)]) == 0
    assert shield_cli.main(["demo", "--quiet", "--out", str(b)]) == 0
    assert _read_surfaces(a) == _read_surfaces(b), "default demo scan must be byte-identical"
    rep = json.loads((a / "outputs" / "hermes_shield_report.json").read_text())
    assert rep["proven_live_poc"] == 0, "the default scan proves nothing (no execution)"


def test_consent_env_allows_non_interactive_run(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HERMES_SHIELD_PROVE_CONSENT", "1")
    rc = shield_cli.main(["demo", "--prove", "--out", str(tmp_path / "out")])
    assert rc == 0
    out = capsys.readouterr().out
    assert "PROVEN-LIVE" in out
    # the CLI resolves artefacts under <out>/outputs/ (the standard scan artefact convention)
    assert (tmp_path / "out" / "outputs" / "prove" / "prove_summary.json").exists()


# --------------------------------------------------------------------------- isolation

def test_isolation_config_reports_network_posture():
    cfg = prove.isolation_config(prove.isolation_backend())
    if prove.isolation_backend() == "bwrap":
        assert cfg["network"].startswith("denied")
    else:
        assert "NOT blocked" in cfg["network"]


# --------------------------------------------------------------------------- Phase 1: scan --prove

def _throwaway_target(tmp_path):
    """A real (non-fixture) repo: one directly-drivable code_exec sink, one param-derived shell-injection
    sink (Phase-2a PROVEN), and one list-argv subprocess sink that must be REFUSED (not shell-interpreted)."""
    target = tmp_path / "repo"
    target.mkdir()
    (target / "drive.py").write_text(
        "def run_task(payload):\n"
        "    return eval(payload)   # directly-drivable code_exec sink\n")
    (target / "shell.py").write_text(
        "import subprocess\n"
        "def run_cmd(cmd):\n"
        "    return subprocess.run(cmd, shell=True)   # subprocess_exec — Phase-2a provable (param IS command)\n")
    (target / "listargv.py").write_text(
        "import subprocess\n"
        "def run_argv(cmd):\n"
        "    return subprocess.run(['echo', cmd])   # list-argv, not shell-interpreted -> REFUSED (recipe)\n")
    return target


def test_scan_prove_promotes_drivable_and_refuses_rest(tmp_path, monkeypatch):
    """`scan --prove` on a REAL repo: the drivable code_exec sink is PROVEN-LIVE and rebuilds the report so
    proven_live_poc reflects it; the subprocess_exec sink is REFUSED-RECIPE (never promoted); an evidence
    bundle lands under the operator out dir."""
    target = _throwaway_target(tmp_path)
    out = tmp_path / "out"
    monkeypatch.setenv("HERMES_SHIELD_PROVE_CONSENT", "1")
    rc = scan_hermes.main(["--scan", "--root", str(target), "--out", str(out), "--quiet", "--prove"])
    assert rc == 0
    rep = json.loads((out / "outputs" / "hermes_shield_report.json").read_text())
    assert rep["proven_live_poc"] >= 1, "the drivable code_exec sink must be PROVEN-LIVE via scan --prove"
    assert any(it["file"] == "drive.py" for it in rep["proven_live"]["items"])
    # evidence bundle under the operator out dir (never the target), with the refused subprocess sink
    summ = json.loads((out / "outputs" / "prove" / "prove_summary.json").read_text())
    assert summ["proven"] >= 1 and summ["refused_recipe"] >= 1
    assert not (target / "prove").exists(), "evidence must NEVER be written into the target repo"


def test_scan_prove_off_is_byte_identical_and_proves_nothing(tmp_path, monkeypatch):
    """The deterministic core is byte-identical with --prove OFF (the default), even when consent is granted
    in the environment: the base report matches a plain scan and proves nothing."""
    target = _throwaway_target(tmp_path)
    monkeypatch.setenv("HERMES_SHIELD_PROVE_CONSENT", "1")   # granted, but --prove is NOT passed
    a, b = tmp_path / "a", tmp_path / "b"
    assert scan_hermes.main(["--scan", "--root", str(target), "--out", str(a), "--quiet"]) == 0
    assert scan_hermes.main(["--scan", "--root", str(target), "--out", str(b), "--quiet"]) == 0
    ra = (a / "outputs" / "hermes_shield_report.json").read_text()
    rb = (b / "outputs" / "hermes_shield_report.json").read_text()
    assert ra == rb, "the base report must be byte-identical with --prove off"
    assert json.loads(ra)["proven_live_poc"] == 0, "a plain scan proves nothing"
    assert not (a / "outputs" / "prove").exists(), "no prove evidence when --prove is off"


# --------------------------------------------------------------------------- interpreter-masking bug

def test_bwrap_rebinds_interpreter_under_tmp_and_never_binds_mount_roots(monkeypatch):
    """Regression: when the interpreter's real binary lives under a cell-masked path (e.g. directly under
    /tmp), the cell must STILL re-expose it — precisely (the interpreter's own path), AFTER the --tmpfs
    mask, and WITHOUT binding a mount-point root (/ or /tmp). The old `.resolve().parent.parent` heuristic
    resolved a bare /tmp/python to `/`, tried to --ro-bind / read-only, and made the cell root read-only so
    /hs_cell could not be created -> every proof went inconclusive. This locks the fix statically (no bwrap
    needed)."""
    monkeypatch.setattr(sys, "executable", "/tmp/hs_direct_python3_regress")
    cmd = prove._bwrap_cmd("/target", "/tmp/hs-prove-x/cell", "/hs_cell", "/hs_cell/spec.json")
    binds = {b for a, b in zip(cmd, cmd[1:]) if a in ("--ro-bind", "--ro-bind-try")}
    # never a mount-point root — those would defeat the tmpfs or break the writable cell
    assert "/" not in binds and "/tmp" not in binds, "must never bind a mount-point root"
    # the interpreter's own path IS re-exposed, AFTER the --tmpfs /tmp mask
    assert "/tmp/hs_direct_python3_regress" in cmd, "interpreter under /tmp must be re-bound"
    tmpfs_pos = cmd.index("--tmpfs")
    assert cmd.index("/tmp/hs_direct_python3_regress") > tmpfs_pos, "interp bind must come after the tmpfs mask"


@pytest.mark.skipif(not _HAS_BWRAP, reason="bwrap not present — cell masking is a bwrap guarantee")
def test_proof_promotes_when_interpreter_realpath_is_under_tmp(tmp_path, monkeypatch):
    """End-to-end: drive the same drivable code_exec sink but with the LAUNCH interpreter being a real
    binary that sits DIRECTLY under /tmp (grandparent == /). Under the old bind logic this returned
    inconclusive (the cell could not be built); with the fix the canary fires and the sink is promoted.
    Network stays denied throughout."""
    interp = Path("/tmp") / f"hs_prove_regress_{os.getpid()}_python3"
    try:
        shutil.copy2(os.path.realpath(sys.executable), interp)
        interp.chmod(0o755)
    except Exception as e:                                    # pragma: no cover - env without a copyable interp
        pytest.skip(f"could not stage a /tmp interpreter: {e}")
    target = tmp_path / "repo"
    target.mkdir()
    (target / "drive.py").write_text(
        "def run_task(payload):\n"
        "    return eval(payload)   # directly-drivable code_exec sink\n")
    cell = tmp_path / "cell"
    cell.mkdir()
    nonce = "beadfeed00c0ffee"
    try:
        monkeypatch.setattr(sys, "executable", str(interp))   # _bwrap_cmd launches the /tmp interpreter
        run = prove._run_in_cell(
            "bwrap", str(target.resolve()), str((target / "drive.py").resolve()),
            "run_task", "payload", lambda cdir: prove._payload_code_exec(nonce, cdir),
            "code_exec", "", nonce, cell, "pos")
    finally:
        try:
            interp.unlink()
        except OSError:
            pass
    assert run.get("error") is None, f"cell must build + launch under a /tmp interpreter: {run.get('error')}"
    assert run["canary_file"] is True, "the nonce must fire via the sink even with the interpreter under /tmp"


@pytest.mark.skipif(not _HAS_BWRAP, reason="bwrap not present — network-deny is a bwrap guarantee")
def test_bwrap_denies_network_in_cell(tmp_path):
    # a fixture that only writes the canary AFTER a successful outbound socket connect. With the network
    # namespace unshared, the connect must fail, so the canary must NOT fire.
    target = tmp_path / "netrepo"
    target.mkdir()
    (target / "net_writer.py").write_text(
        "import socket\n"
        "def run_task(payload):\n"
        "    socket.create_connection(('1.1.1.1', 53), timeout=3)   # raises when net is denied\n"
        "    return eval(payload)                                   # only reached if connected\n")
    cell = tmp_path / "cell"
    cell.mkdir()
    nonce = "abc123deadbeef00"
    run = prove._run_in_cell(
        "bwrap", str(target.resolve()), str((target / "net_writer.py").resolve()),
        "run_task", "payload", lambda cdir: prove._payload_code_exec(nonce, cdir),
        "code_exec", "", nonce, cell, "net")
    assert run["canary_file"] is False, "network was NOT denied — the sink was reached over the net"
    assert run["error"], "the outbound connect should have raised inside the cell"


# --------------------------------------------------------------------------- FIX 1: dataflow-based drivability

def _prove_file(tmp_path, name, source):
    """Write a one-file repo, run the normal static scan + the prove lane, return the record for `name`."""
    target = tmp_path / "repo"
    target.mkdir(exist_ok=True)
    (target / name).write_text(source)
    scan = scan_hermes.run_scan(target)
    _validated, records = prove.run_lane(target, scan)
    recs = [r for r in records if r["file"] == name]
    assert recs, f"{name} must appear as an attempted surface"
    return recs[0]


def test_eval_expr_param_is_proven_regardless_of_name(tmp_path):
    # ROOT-CAUSE FIX: drivability is DATAFLOW-gated, not param-NAME-gated. `expr` is not in _UNTRUSTED_PARAMS,
    # yet the sink is directly driven from it -> PROVEN.
    r = _prove_file(tmp_path, "e.py", "def run(expr):\n    return eval(expr)\n")
    assert r["capability"] == "code_exec"
    assert r["verdict"] == "proven" and r["promoted"] is True
    assert r["trigger"]["tainted_param"] == "expr"
    assert r["nonce_effect"]["fired_via_sink"] is True and r["reproduced"] is True
    assert r["negative_control"]["clean"] is True


def test_constant_code_arg_is_not_a_promotable_surface(tmp_path):
    # v0.8.1 PRECISION: a compile-time-constant code/module target (`__import__('re')`) is a STATIC import,
    # not a dynamic code-exec injection point. It is now removed at DETECTION (ast_sinks constant-target
    # guard), so it never becomes a code_exec surface and can NEVER be promoted to proven-live — a strictly
    # stronger guarantee than the prior refuse-at-prove. (The prove lane's own constant-refusal remains for
    # sinks that DO still surface, e.g. the constant SHELL command in test_constant_shell_command_refused.)
    target = tmp_path / "repo"
    target.mkdir(exist_ok=True)
    (target / "c.py").write_text("def run(x):\n    return __import__('re')\n")
    scan = scan_hermes.run_scan(target)
    code_exec = [s for s in scan["surfaces"] if s.file_path == "c.py" and s.capability == "code_exec"]
    assert not code_exec, "constant-literal __import__ must not be a code_exec surface (removed at detection)"
    _validated, records = prove.run_lane(target, scan)
    assert not [r for r in records if r["file"] == "c.py"], "constant code target must never reach the prove lane"


def test_driver_fills_other_required_params(tmp_path):
    # multi-param callable: the driver fills the non-injected required param so there is no missing-arg TypeError.
    r = _prove_file(tmp_path, "m.py", "def run(expr, url):\n    return eval(expr)\n")
    assert r["verdict"] == "proven" and r["promoted"] is True
    assert r["trigger"]["fill"] == {"url": ""}
    assert r["nonce_effect"]["fired_via_sink"] is True


def test_positional_only_param_binds(tmp_path):
    # a positional-only injectable param must be bound positionally by the driver, not by keyword.
    r = _prove_file(tmp_path, "p.py", "def run(expr, /):\n    return eval(expr)\n")
    assert r["verdict"] == "proven" and r["promoted"] is True
    assert r["trigger"]["tainted_param"] == "expr"


# --------------------------------------------------------------------------- FIX 2: Phase-2a shell injection

def test_shell_injection_param_derived_is_proven(tmp_path):
    r = _prove_file(tmp_path, "s.py",
                    "import subprocess\n"
                    "def run(cmd):\n"
                    "    return subprocess.run(cmd, shell=True)\n")
    assert r["capability"] == "subprocess_exec"
    assert r["verdict"] == "proven" and r["promoted"] is True
    assert r["nonce_effect"]["mechanism"] == "shell-canary-file-write"
    assert r["nonce_effect"]["fired_via_sink"] is True and r["reproduced"] is True
    assert "/bin/sh" in r["isolation"].get("added_execution_surface", "")


def test_constant_shell_command_refused(tmp_path):
    r = _prove_file(tmp_path, "sc.py",
                    "import subprocess\n"
                    "def run(x):\n"
                    "    return subprocess.run('echo hi', shell=True)\n")
    assert r["capability"] == "subprocess_exec"
    assert r["verdict"] == "refused-recipe" and r["promoted"] is False
    assert "constant" in r["reason"]


def test_list_argv_subprocess_refused(tmp_path):
    # a list-argv subprocess is not shell-interpreted -> a data arg is not command-injectable -> recipe only.
    r = _prove_file(tmp_path, "la.py",
                    "import subprocess\n"
                    "def run(cmd):\n"
                    "    return subprocess.run(['echo', cmd])\n")
    assert r["capability"] == "subprocess_exec"
    assert r["verdict"] == "refused-recipe" and r["promoted"] is False
    assert "list-argv" in r["reason"]
    assert r["recipe"]["capability"] == "subprocess_exec"


def test_shell_negative_control_clean(tmp_path):
    # the MANDATORY negative control runs the SAME shell sink with a benign no-op command and must NOT fire.
    r = _prove_file(tmp_path, "sn.py",
                    "import subprocess\n"
                    "def run(cmd):\n"
                    "    return subprocess.run(cmd, shell=True)\n")
    assert r["negative_control"]["fired"] is False and r["negative_control"]["clean"] is True
    neg = [run for run in r["runs"] if run["tag"] == "neg"][0]
    assert neg["canary_file"] is False


# --------------------------------------------------------------------------- byte-identical scanner default path

def test_scanner_analyze_byte_identical():
    # the DEFAULT (name-gated) taint path — analyze() with seed_params=None — is unchanged by the prove-lane
    # dataflow work: an arbitrarily-named param does NOT taint the sink, a conventionally-untrusted name does.
    import ast as _ast
    from hermes_shield import taint
    assert taint.analyze(_ast.parse("def run(expr):\n    return eval(expr)\n")) == {}, \
        "default analyze() must stay name-gated — an 'expr' param must not taint the sink"
    assert taint.analyze(_ast.parse("def run(text):\n    return eval(text)\n")) == {2: "untrusted param 'text'"}
