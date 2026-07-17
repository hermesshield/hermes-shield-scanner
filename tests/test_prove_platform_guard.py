"""--prove must refuse cleanly off Linux+bwrap (never crash on Windows, never run a network-exposed
sandbox on macOS). The deterministic scan is unaffected."""
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from hermes_shield import prove


def test_prove_supported_true_on_linux_with_bwrap():
    # This suite runs on Linux+bwrap; the lane's own tests already exercise the happy path.
    if sys.platform.startswith("linux") and __import__("shutil").which("bwrap"):
        assert prove.prove_supported() == (True, "")


def test_prove_refused_off_linux_no_crash():
    with mock.patch.object(sys, "platform", "win32"):
        ok, why = prove.prove_supported()
        assert ok is False
        assert "Linux" in why and "ran fully" in why
        # run_lane must degrade to a clean no-op, never raise (e.g. no `import resource`).
        validated, records = prove.run_lane(".", {"surfaces": []})
        assert validated == set() and records == []


def test_prove_refused_without_bwrap():
    with mock.patch.object(sys, "platform", "linux"), \
         mock.patch("hermes_shield.prove.shutil.which", return_value=None):
        ok, why = prove.prove_supported()
        assert ok is False
        assert "bwrap" in why.lower()


# --- structural isolation: the subprocess (rlimit-only) backend NEVER executes target code ----------

def test_run_in_cell_subprocess_backend_refuses(tmp_path):
    """The low-level cell runner must refuse the unsandboxed subprocess backend before executing
    anything — a hard structural wall, not just a run_lane gate."""
    target = tmp_path / "t.py"
    target.write_text("def run(expr):\n    eval(expr)\n", encoding="utf-8")
    out = prove._run_in_cell("subprocess", str(tmp_path), str(target), "run", "expr",
                             "open('x','w')", "code_exec", "", "deadbeef", tmp_path, "pos1")
    assert out["ran"] is False
    assert out["canary_file"] is False
    assert out.get("refused_no_sandbox") is True
    assert "no bwrap sandbox" in (out["error"] or "")


def test_prove_surface_subprocess_backend_refuses_and_recipes(tmp_path):
    """A directly-drivable code_exec surface, proven under the subprocess backend, must be REFUSED
    (verdict 'refused-no-sandbox', not promoted) and fall back to a manual recipe — no target code runs,
    no canary is ever written."""
    target = tmp_path / "t.py"
    target.write_text("def run(expr):\n    eval(expr)\n", encoding="utf-8")
    surface = SimpleNamespace(id="t1", file_path="t.py", sink_line=2, line_start=2,
                              capability="code_exec", sink_name="eval", context="prod", shell_form=True)
    rec = prove.prove_surface(surface, str(tmp_path), tmp_path / "cell", backend="subprocess")
    assert rec["trigger"]["drivable"] is True, "fixture must be drivable so we exercise the refusal, not a skip"
    assert rec["verdict"] == "refused-no-sandbox"
    assert rec["promoted"] is False
    assert "no bwrap sandbox" in rec["reason"]
    assert rec["recipe"] is not None
    # the isolation record for the subprocess backend must not claim the target is 'not executed'
    iso = rec["isolation"]
    assert "REFUSED" in iso.get("status", "")
    assert "not executed" not in iso.get("target_root", "").lower()
