"""S8.19 false-positive suppression — each FP must stop firing AND a paired real threat must still fire."""
import sys
from pathlib import Path


from hermes_shield import ast_sinks as A


def _ce(src):
    ok, sinks = A.detect(src)
    return [s for s in sinks if s["capability"] == "code_exec"]


# FP1 — dead code after an unconditional raise/return
def test_deadcode_suppressed():
    assert not _ce("def f():\n    raise HTTPException(400)\n    exec(code)\n")


def test_deadcode_live_exec_still_fires():
    assert _ce("def f():\n    exec(code)\n")


def test_deadcode_conditional_raise_still_fires():
    # the raise is CONDITIONAL, so the exec is live and must still fire (anti-over-suppression anchor)
    assert _ce("def f():\n    if bad:\n        raise X()\n    exec(code)\n")


# FP2 — page.evaluate with a CONSTANT JS body + untrusted argument (scoped to evaluate, never to eval/exec)
def test_evaluate_constant_body_suppressed():
    assert not _ce('def f(text):\n    page.evaluate("(t)=>navigator.clipboard.writeText(t)", text)\n')


def test_evaluate_fstring_body_fires():
    assert _ce('def f(text, fn):\n    page.evaluate(f"(t)=>{fn}(t)", text)\n')


def test_evaluate_constant_body_that_evals_arg_fires():
    assert _ce('def f(text):\n    page.evaluate("(t)=>eval(t)", text)\n')


# THE CRITICAL PROTECTION: a real eval() inside a display/print method must STILL fire (interface.py:199).
def test_print_display_proximity_does_not_suppress_real_eval():
    src = "def display(self, m):\n    print('msg')\n    msg_dict = eval(function_args)\n    print(msg_dict)\n"
    assert _ce(src), "a real eval() was wrongly suppressed because print() sits nearby"


# FP3 + FP4 run through the full pipeline (guard_attribution demotes). Helper:
from hermes_shield import scan_hermes


def _verdicts(tmp_path, fname, src, cap="external_write"):
    (tmp_path / fname).write_text(src)
    scan = scan_hermes.run_scan(tmp_path)
    return [s.verdict for s in scan["surfaces"] if s.file_path == fname and s.capability == cap]


def test_config_destination_demoted(tmp_path):
    v = _verdicts(tmp_path, "a.py", "import requests\nclass A:\n    def p(self):\n        requests.post(self.config.webhook_url, json={})\n")
    assert v and all(x == "CONFIG_DESTINATION_WRITE_REVIEW" for x in v)


def test_unknown_destination_stays_critical(tmp_path):
    v = _verdicts(tmp_path, "b.py", "import requests\ndef p(dest):\n    requests.post(dest, json={})\n")
    assert v and all(x != "CONFIG_DESTINATION_WRITE_REVIEW" for x in v)


def test_auth_gated_route_demoted(tmp_path):
    v = _verdicts(tmp_path, "c.py", "import requests\nfrom fastapi import Depends\ndef get_current_org(): pass\n@router.post('/wh')\ndef wh(org=Depends(get_current_org)):\n    requests.post(org.callback_url, json={})\n")
    assert v and all(x == "AUTH_GATED_REVIEW" for x in v)


def test_non_auth_depends_not_demoted(tmp_path):
    v = _verdicts(tmp_path, "d.py", "import requests\ndef get_db(): pass\n@router.post('/x')\ndef x(db=Depends(get_db)):\n    requests.post(some_url, json={})\n")
    assert v and all(x not in ("AUTH_GATED_REVIEW", "CONFIG_DESTINATION_WRITE_REVIEW") for x in v)


def test_system_method_not_subprocess_fp():
    """S8.58: a .system() METHOD on a non-os object (self.prompt.system(), logger.system()) must NOT be
    flagged as os.system - it false-fired on notte. Real os.system + resolved 'from os import system' stay."""
    from hermes_shield import ast_sinks
    def caps(code):
        _, sinks = ast_sinks.detect(code)
        return [s['capability'] for s in sinks]
    assert caps('x = self.prompt.system()') == []          # FP fixed
    assert caps('logger.system(msg)') == []                # FP fixed
    assert 'subprocess_exec' in caps('import os\nos.system(cmd)')             # real os.system kept
    assert 'subprocess_exec' in caps('from os import system\nsystem(cmd)')   # resolved import kept
