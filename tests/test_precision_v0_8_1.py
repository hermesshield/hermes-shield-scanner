#!/usr/bin/env python3
"""v0.8.1 PRECISION — three provably-inert false-positive classes removed WITHOUT dropping recall.

Each class has a FP-GONE test (the inert form is no longer flagged) AND a RECALL-PRESERVED / adversarial
test (the dynamic, injection-prone form STILL fires). The line the whole product holds: we only ever
downgrade a PROVABLY-inert case — a non-constant / attacker-controlled form is never silenced.

  1. Constant-literal dynamic-exec: eval/exec/compile/__import__/import_module with a CONSTANT STRING
     target is developer-authored static code, not dynamic code-exec. A Name / f-string / expression
     target stays RED code_exec.
  2. Constant page.evaluate: a fixed JS body (inline OR a module-level string constant) is Playwright DATA,
     not injectable. An interpolated (f-string) JS body stays RED code_exec.
  3. Fixed-destination outbound write: a send whose scheme://HOST authority is a CONSTANT (only a secret
     token / path interpolates AFTER the host) lands in the AMBER fixed-dest review band, not RED exfil.
     A tainted / interpolated / non-delimited host stays RED.
"""
from __future__ import annotations

from hermes_shield import ast_sinks as A
from hermes_shield import scan_hermes, install_report as IR


def _caps(src):
    ok, sinks = A.detect(src)
    assert ok, "AST parse failed"
    return [s["capability"] for s in sinks]


# ─────────────────────────── Class 1: constant-literal dynamic-exec ───────────────────────────

def test_c1_fp_gone_constant_builtin_targets_not_codeexec():
    assert "code_exec" not in _caps('__import__("re")\n')
    assert "code_exec" not in _caps('__import__("datetime")\n')
    assert "code_exec" not in _caps('eval("1 + 1")\n')
    assert "code_exec" not in _caps('exec("x = 2")\n')
    assert "code_exec" not in _caps('compile("z", "<s>", "eval")\n')
    # importlib.import_module with a constant was already inert on main — assert it stays that way.
    assert "code_exec" not in _caps('import importlib\nimportlib.import_module("pkg.mod")\n')
    assert "dynamic_dispatch" not in _caps('import importlib\nimportlib.import_module("pkg.mod")\n')


def test_c1_fp_gone_alias_bound_builtin_constant_target():
    # `_imp = __import__; _imp("re")` — a name bound to a builtin code-exec called with a constant is inert.
    assert "code_exec" not in _caps('_imp = __import__\ndef f():\n    return _imp("re")\n')


def test_c1_recall_nonconstant_builtin_targets_stay_red():
    assert "code_exec" in _caps('def f(x):\n    __import__(x)\n')
    assert "code_exec" in _caps('import flask\ndef f():\n    return eval(flask.request.json["x"])\n')
    assert "code_exec" in _caps('def f(code):\n    exec(code)\n')
    assert "code_exec" in _caps('def f(src, ns):\n    exec(compile(src, "<s>", "exec"), ns)\n')
    # f-string / concatenation target is dynamic
    assert "code_exec" in _caps('def f(u):\n    eval(f"{u} + 1")\n')
    # NON-constant importlib.import_module stays dynamic-dispatch
    assert "dynamic_dispatch" in _caps('import importlib\ndef f(name):\n    importlib.import_module(name)\n')


def test_c1_recall_alias_bound_builtin_nonconstant_stays_red():
    # webhook_ops compute.py:12 shape — `_calc = eval; _calc(expr)` with a non-constant arg stays RED.
    assert "code_exec" in _caps('_calc = eval\ndef f(expr):\n    return _calc(expr)\n')


# ─────────────────────────── Class 2: constant page.evaluate ───────────────────────────

def test_c2_fp_gone_constant_js_body():
    # inline constant JS body
    assert "code_exec" not in _caps('def f(page, d):\n    return page.evaluate("(x) => x.length", d)\n')
    # module-level STRING CONSTANT bound to a Name, passed as the JS body (the _HARVEST_JS shape)
    src = ('_HARVEST_JS = "(contracts) => { return contracts.map(c => c.id); }"\n'
           'def f(page, contracts):\n'
           '    return page.evaluate(_HARVEST_JS, contracts)\n')
    assert "code_exec" not in _caps(src)


def test_c2_recall_interpolated_js_body_stays_red():
    # f-string JS body with untrusted interpolation — injectable, stays RED
    assert "code_exec" in _caps('def f(page, untrusted):\n    return page.evaluate(f"() => {{ {untrusted} }}")\n')
    # a Name bound to an f-string is NOT a literal constant -> not resolved -> stays RED
    src = ('def f(page, untrusted):\n'
           '    js = f"() => {{ {untrusted} }}"\n'
           '    return page.evaluate(js, [])\n')
    assert "code_exec" in _caps(src)
    # a constant body that itself evals its argument is still code-exec
    assert "code_exec" in _caps('def f(page, d):\n    return page.evaluate("(x) => eval(x)", d)\n')


# ─────────────────────────── Class 3: fixed-destination constant host ───────────────────────────

def test_c3_unit_classify_dest_const_host():
    import ast
    def prov(expr):
        node = ast.parse(expr, mode="eval").body
        return A._classify_dest(node)
    # f-string with constant host + interpolated token AFTER the host -> constant (fixed destination)
    assert prov('f"https://api.telegram.org/bot{tok}/sendMessage"') == "constant"
    assert prov('f"https://api.example.com/v1/{tok}/send"') == "constant"
    # concatenation with a leading constant host is also fixed
    assert prov('"https://api.host.com/x/" + tok') == "constant"
    # plain constant URL stays constant (unchanged)
    assert prov('"https://api.telegram.org/x"') == "constant"
    # ADVERSARIAL: an interpolated HOST is attacker-controllable -> unknown (stays RED)
    assert prov('f"https://{host}/send"') == "unknown"
    assert prov('f"{base}/sendMessage"') == "unknown"
    # ADVERSARIAL: host not closed by a constant delimiter could be EXTENDED by the interpolation -> unknown
    assert prov('f"https://evil.co{suffix}"') == "unknown"
    # a bare variable destination stays unknown
    assert prov('url') == "unknown"


def _scan(tmp_path, files):
    for name, src in files.items():
        (tmp_path / name).write_text(src)
    return scan_hermes.run_scan(tmp_path)


def _band(tmp_path, scan):
    rep = IR.build_report(tmp_path, scan)
    vb = IR.verdict_band(rep["non_gated_vulnerable"], rep["proven_live_poc"],
                         rep["install_liability_rce"], rep["reachable_amber_actions"],
                         rep["reachable_fixed_dest_review"])
    return rep, vb


def test_c3_fp_gone_const_host_secret_token_is_amber_not_red(tmp_path):
    """The prompt's telegram/api-host shape: fixed HOST, only a SECRET token interpolates (not tainted),
    tainted CONTENT -> AMBER fixed-dest review, never RED exfil."""
    scan = _scan(tmp_path, {"ship.py":
        "import os, requests\n"
        "def ship(text):\n"                              # 'text' is untrusted content
        "    tok = os.getenv('API_TOKEN')\n"             # secret, not attacker-controlled
        "    requests.post(f'https://api.example.com/v1/{tok}/send', json={'text': text})\n"})
    v = [s for s in scan["surfaces"] if s.file_path == "ship.py" and s.capability == "external_write"]
    assert v, "external_write sink not detected"
    assert all(s.dest_provenance == "constant" for s in v)
    assert all(s.tainted_reachable and not s.tainted_destination for s in v)
    assert all(s.verdict == "CONFIG_DESTINATION_WRITE_REVIEW" for s in v)
    assert all(s.verdict != "UNGUARDED_CRITICAL_LIVE_SINK" for s in v)
    rep, vb = _band(tmp_path, scan)
    assert rep["non_gated_vulnerable"] == 0                     # not red
    assert rep["reachable_fixed_dest_review"] >= 1
    assert vb["code"] == "amber"


def test_c3_recall_attacker_controlled_url_stays_red(tmp_path):
    """A whole-URL variable destination is a genuine exfil channel -> STILL RED."""
    scan = _scan(tmp_path, {"relay.py":
        "import requests\n"
        "def relay(url, text):\n"
        "    requests.post(url, json={'text': text})\n"})
    v = [s for s in scan["surfaces"] if s.file_path == "relay.py" and s.capability == "external_write"]
    assert v
    assert all(s.dest_provenance == "unknown" for s in v)
    assert any(s.verdict == "UNGUARDED_CRITICAL_LIVE_SINK" for s in v)
    rep, vb = _band(tmp_path, scan)
    assert rep["non_gated_vulnerable"] >= 1 and vb["code"] == "red"


def test_c3_recall_interpolated_host_stays_red(tmp_path):
    """An interpolated HOST (attacker could redirect the destination) -> STILL RED, never demoted."""
    scan = _scan(tmp_path, {"h.py":
        "import requests\n"
        "def relay(host, text):\n"
        "    requests.post(f'https://{host}/send', json={'text': text})\n"})
    v = [s for s in scan["surfaces"] if s.file_path == "h.py" and s.capability == "external_write"]
    assert v
    assert all(s.dest_provenance == "unknown" for s in v)
    assert all(s.verdict != "CONFIG_DESTINATION_WRITE_REVIEW" for s in v)
    rep, vb = _band(tmp_path, scan)
    assert rep["non_gated_vulnerable"] >= 1 and vb["code"] == "red"
