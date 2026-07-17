"""S8.83 — AI-surface reachability (inter_taint extra_targets) + capability normalisation.

Covers the three required fixtures: an AI-asserted action line that IS reachable from a real entrypoint
is marked; one that is NOT is left unmarked; a benign target yields nothing. Plus conservative-map unit
tests (clear caps mapped, ambiguous caps left non-canonical)."""
import sys
from pathlib import Path


from hermes_shield import inter_taint as IT
from hermes_shield import cross_module as XM
from hermes_shield import cap_normalise as CN
from hermes_shield.models import ActionSurface


def _compute(tmp, files, extra):
    for name, src in files.items():
        (tmp / name).write_text(src)
    graphs = XM.build_graphs(tmp, list(files))
    return IT.compute(tmp, graphs, XM.build_mod2files(graphs), extra_targets=extra)


# ---------------- Build B: reachability of AI-asserted action lines ----------------

def test_ai_line_reachable_via_arg_is_marked(tmp_path):
    """Untrusted entrypoint param flows as an ARG into the AI-asserted action line -> marked reachable."""
    src = ("import os\n"
           "@app.post('/h')\n"
           "def handler(message):\n"
           "    do_action(message)\n")     # line 4 = AI target, arg tainted
    res = _compute(tmp_path, {"a.py": src}, {"a.py": {4}})
    assert 4 in res.get("a.py", {}), "arg-tainted AI target not marked reachable"


def test_ai_line_reachable_via_receiver_is_marked(tmp_path):
    """RECEIVER-taint (the new AI-target extension): obj holding untrusted data performs the action."""
    src = ("@app.post('/h')\n"
           "def handler(message):\n"
           "    sink_obj = message\n"
           "    sink_obj.upload()\n")       # line 4 = AI target, receiver tainted
    res = _compute(tmp_path, {"b.py": src}, {"b.py": {4}})
    assert 4 in res.get("b.py", {}), "receiver-tainted AI target not marked reachable"


def test_ai_line_not_reachable_is_not_marked(tmp_path):
    """A real entrypoint but the action line touches only a CONSTANT -> NOT reachable (sound under-mark)."""
    src = ("@app.post('/h')\n"
           "def handler(message):\n"
           "    safe = 'constant'\n"
           "    safe.upload()\n")           # line 4 = AI target, no taint
    res = _compute(tmp_path, {"c.py": src}, {"c.py": {4}})
    assert 4 not in res.get("c.py", {}), "clean AI target over-marked as reachable"


def test_ai_line_no_entrypoint_not_marked(tmp_path):
    """No entrypoint grounds the param -> the AI target must NOT be reachable (the over-mark we must avoid)."""
    src = ("def handler(message):\n"
           "    do_action(message)\n")       # line 2 = AI target, but message ungrounded
    res = _compute(tmp_path, {"d.py": src}, {"d.py": {2}})
    assert not res.get("d.py"), "ungrounded param over-marked as reachable"


def test_benign_target_yields_nothing(tmp_path):
    """Benign file, no untrusted source anywhere -> no sink marked (extra target inert)."""
    src = ("def add(a, b):\n"
           "    return a + b\n"
           "add(1, 2)\n")
    res = _compute(tmp_path, {"e.py": src}, {"e.py": {2, 3}})
    assert not res.get("e.py"), "benign target produced a reachable mark"


def test_extra_targets_empty_is_byte_identical(tmp_path):
    """Off-path guarantee: no extra_targets -> identical to the pre-S8.83 compute output."""
    files = {"f.py": ("import os\ndef sink_fn(data):\n    os.system(data)\n"
                      "@app.post('/e')\ndef entry(payload):\n    sink_fn(payload)\n")}
    for n, s in files.items():
        (tmp_path / n).write_text(s)
    graphs = XM.build_graphs(tmp_path, list(files))
    m2f = XM.build_mod2files(graphs)
    a = IT.compute(tmp_path, graphs, m2f)                       # default
    b = IT.compute(tmp_path, graphs, m2f, extra_targets={})     # explicit empty
    assert a == b


# ---------------- Build A: conservative capability normalisation ----------------

def test_clear_caps_map_to_canonical():
    cases = {
        "code-execution": "code_exec", "exec": "code_exec", "execute-code": "code_exec",
        "subprocess": "subprocess_exec", "shell-exec": "subprocess_exec",
        "tool-invoke": "tool_invoke", "llm-tool-invoke": "tool_invoke",
        "agent-delegation": "tool_invoke", "agent-execution": "tool_invoke",
        "file-write": "file_write", "file-delete": "file_delete",
        "network-send": "external_write", "cloud-write": "external_write", "upload": "external_write",
        "deserialize/eval": "deserialize", "send/exfiltrate": "secret_exfil",
    }
    for raw, want in cases.items():
        got, mapped = CN.normalise_capability(raw)
        assert mapped and got == want, f"{raw!r} -> {got!r} (want {want})"


def test_ambiguous_caps_left_non_canonical():
    """No force-fit: caps with no clear canonical meaning are returned UNCHANGED (under-mark, never inflate)."""
    for raw in ("db-write", "network-fetch", "network-fetch (SSRF)", "dynamic-dispatch",
                "dynamic-import", "sql-execution", "approval-grant", "money-transfer", "state-write"):
        got, mapped = CN.normalise_capability(raw)
        assert not mapped and got == raw, f"{raw!r} was force-fit to {got!r}"


def test_apply_only_touches_ai_surfaces():
    static_s = ActionSurface(id="s", file_path="x.py", capability="code-execution", detection_source="static")
    ai_s = ActionSurface(id="a", file_path="x.py", capability="code-execution", detection_source="ai_suspected")
    stats = CN.apply_to_surfaces([static_s, ai_s])
    assert static_s.capability == "code-execution"      # static untouched
    assert ai_s.capability == "code_exec"               # AI normalised
    assert stats["ai_caps_mapped"] == 1
