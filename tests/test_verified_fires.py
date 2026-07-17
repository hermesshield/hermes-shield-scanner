"""
S8.75 VERIFIED-FIRES probe (consensus Q3 addition). The wiring check proves a module is IMPORTED; it does NOT
prove it FIRES and changes output on a real scan. This runs scan_hermes against a fixture repo with one known
eval-on-LLM-output, one known secret-exfil, and one benign file, and asserts each wired detector actually emits
its finding and the benign file emits none. If a wired detector produces nothing on its own positive fixture,
that is the silent regression import-reachability is blind to. This turns WIRED into VERIFIED-FIRES, and runs
in CI so drift fails the build.
"""
import sys
import tempfile
from pathlib import Path


from hermes_shield import scan_hermes


def _scan_fixture(files):
    tmp = Path(tempfile.mkdtemp())
    for name, src in files.items():
        (tmp / name).write_text(src)
    return scan_hermes.run_scan(tmp)


def test_eval_on_llm_output_detector_FIRES():
    scan = _scan_fixture({"a.py": "def h(self, assistant_reply):\n    tasks = eval(assistant_reply)\n"})
    tagged = [s for s in scan["surfaces"] if s.capability == "code_exec" and s.guard_proof.get("llm_output_eval")]
    assert tagged, "eval-on-LLM-output detector is WIRED but did not FIRE on its positive fixture"


def test_secret_exfil_detector_FIRES():
    scan = _scan_fixture({"b.py": "import os, pickle, requests\ndef f(self):\n    tok = os.environ['API_KEY']\n"
                                   "    blob = pickle.dumps({'k': tok})\n    requests.post(url, data=blob)\n"})
    assert any(s.capability == "secret_exfil" for s in scan["surfaces"]), \
        "secret_exfil detector is WIRED but did not FIRE on its positive fixture (secret->serialise->egress)"


def test_ssti_sink_FIRES():
    scan = _scan_fixture({"c.py": "from flask import render_template_string\n"
                                   "def view(self, body):\n    render_template_string(body)\n"})
    assert any(s.capability == "ssti" for s in scan["surfaces"]), "SSTI sink WIRED but did not FIRE"


def test_benign_file_stays_CLEAN():
    scan = _scan_fixture({"d.py": "def add(a, b):\n    return a + b\n"})
    noisy = [s for s in scan["surfaces"] if s.capability in ("code_exec", "secret_exfil", "ssti", "subprocess_exec")
             and s.context == "prod"]
    assert not noisy, f"benign file produced dangerous findings (false positive): {[s.capability for s in noisy]}"
