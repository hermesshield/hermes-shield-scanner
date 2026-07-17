"""S8.60 focused eval-on-LLM-output detector — precise on the proven class, rejects the config-eval FPs."""
import sys
from pathlib import Path
from hermes_shield import llm_eval_detector as D


def _confs(code):
    return [f["confidence"] for f in D.detect(code)]


def test_finds_superagi_archetype_cleaner_wrapped():
    # eval(clean(assistant_reply <- response['content'])) — the one the general scanner BURIED
    code = "def h(self, reply):\n    assistant_reply = response['content']\n    tasks = eval(clean(assistant_reply))\n"
    assert "high" in _confs(code)


def test_finds_code_as_action():
    code = "def x(self, msg):\n    code = msg.content\n    r = eval(code, g)\n"
    assert D.detect(code), "code-as-action eval(msg.content) missed"


def test_strong_param_name_stays_medium():
    # assistant_reply is a param (LLM call is in the caller) — a definitive name, must not drop to low
    code = "def handle(self, assistant_reply):\n    tasks = eval(assistant_reply)\n"
    assert "medium" in _confs(code)


def test_rejects_typed_config_eval_fp():
    # the FPs the general scanner TOP-RANKED — must be clean
    assert _confs("def a(self):\n    ids = eval(config.value)\n") == []
    assert _confs("def b(self, vector_ids):\n    x = eval(vector_ids)\n") == []
    assert _confs("def c(self):\n    eval('1+1')\n") == []
