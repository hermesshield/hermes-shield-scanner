#!/usr/bin/env python3
"""S9 DET-RECALL — deterministic alias/binding tracking of KNOWN dangerous callables.

Regression tests for the intra-function / module-level binding forms the static engine now resolves:
a dangerous primitive bound to a local/module name (or a getattr on a known-dangerous receiver) and then
invoked through that name — no literal sink token at the call site. Mirrors the planted sinks in
tests/recall_corpus/ (S02/S03/S06/S08/S11/S14/S17/S19/S22).

CONSERVATIVE by design: a generic name bound to an UNKNOWN/BENIGN callable must NOT fire (that is the AI
finder's job and flagging the shape alone over-fires). The negative tests below pin that discipline —
especially the D08 decoy shape `getattr(_TEXT, verb)` and scope-isolation of a reused local name.

Read-only; drives ast_sinks.detect() directly on source snippets."""
from __future__ import annotations

from hermes_shield import ast_sinks  # noqa: E402


def _caps_at(src, line):
    ok, sinks = ast_sinks.detect(src)
    assert ok, "AST parse failed"
    return {s["capability"] for s in sinks if s["line"] == line}


def _all_caps(src):
    ok, sinks = ast_sinks.detect(src)
    assert ok, "AST parse failed"
    return {s["capability"] for s in sinks}


# ---- POSITIVE: alias of a builtin code-exec primitive (compute.py S06) -----------------------------
def test_module_name_alias_of_eval():
    src = "_calc = eval\n\n\ndef run(expr, ctx):\n    return _calc(expr, {}, dict(ctx))\n"
    assert "code_exec" in _caps_at(src, 5)


def test_module_name_alias_of_exec():
    src = "_ex = exec\n\n\ndef run(code):\n    return _ex(code)\n"
    assert "code_exec" in _caps_at(src, 5)


# ---- POSITIVE: dotted attribute-ref alias of a known dotted sink (shell_plugin.py S14) -------------
def test_module_dotted_alias_subprocess_getoutput():
    src = "import subprocess\n_run = subprocess.getoutput\n\n\ndef execute(cmd):\n    return _run(cmd)\n"
    assert "subprocess_exec" in _caps_at(src, 6)


# ---- POSITIVE: aliased requests.post -> exfil ship (exfil.py S22) ----------------------------------
def test_module_dotted_alias_requests_post():
    src = ("import os\nimport requests\n_ship = requests.post\n\n\n"
           "def collect_and_send(dest):\n    secret = os.environ.get('API_TOKEN', '')\n"
           "    return _ship(dest, json={'token': secret})\n")
    assert "external_write" in _caps_at(src, 8)


# ---- POSITIVE: attribute-reference alias of a distinctive name-sink (senders.py S11) ---------------
def test_attr_ref_alias_of_name_sink():
    src = ("def broadcast(api, user_ids, text):\n"
           "    _sender = api.send_direct_message\n"
           "    return [_sender(uid, text) for uid in user_ids]\n")
    assert "dm" in _caps_at(src, 3)


# ---- POSITIVE: getattr-assigned dynamic dispatch on the os module (tools.py S03) -------------------
def test_getattr_assigned_on_os():
    src = ("import os\n\n\ndef raw_tool(arg):\n    verb, _, rest = arg.partition(' ')\n"
           "    fn = getattr(os, verb)\n    return fn(rest)\n")
    assert "dynamic_dispatch" in _caps_at(src, 7)


# ---- POSITIVE: string-registry + getattr-assigned on os (admin.py S17) -----------------------------
def test_getattr_assigned_string_registry_on_os():
    src = ("import os\n_OS_OPS = {'purge': 'system'}\n\n\ndef do_op(verb, arg):\n"
           "    method = _OS_OPS[verb]\n    fn = getattr(os, method)\n    return fn(arg)\n")
    assert "dynamic_dispatch" in _caps_at(src, 8)


# ---- POSITIVE: transitive getattr chain via a self-attr danger-lib (gateways.py S08) ---------------
def test_getattr_chain_via_self_attr_danger_lib():
    src = ("import stripe\n\n\nclass DynamicGateway:\n    def __init__(self):\n        self.client = stripe\n\n"
           "    def charge(self, amount, token, action='Charge'):\n"
           "        resource = getattr(self.client, action)\n"
           "        creator = getattr(resource, 'create')\n"
           "        return creator(amount=amount, source=token)\n")
    assert "dynamic_dispatch" in _caps_at(src, 11)


# ---- POSITIVE: self-attr danger-lib instance -> generic-verb library-aware call (channels.py S19) --
def test_self_attr_danger_lib_generic_verb():
    src = ("import sendgrid\n\n\nclass EmailChannel:\n    def __init__(self, api_key):\n"
           "        self.sg = sendgrid.SendGridAPIClient(api_key)\n\n"
           "    def send(self, message):\n        return self.sg.send(message)\n")
    assert "email_send" in _caps_at(src, 9)


# ---- PRECISION: the D08 decoy shape — getattr on a BENIGN local must NOT fire ----------------------
def test_getattr_assigned_on_benign_receiver_not_flagged():
    src = ("class TextOps:\n    def upper(self, s):\n        return s.upper()\n\n\n_TEXT = TextOps()\n\n\n"
           "def text_tool(arg):\n    verb, _, rest = arg.partition(' ')\n"
           "    fn = getattr(_TEXT, verb)\n    return fn(rest)\n")
    assert "dynamic_dispatch" not in _caps_at(src, 12)
    assert _all_caps(src) == set()


# ---- PRECISION: scope isolation — a benign `fn` in one function must not inherit a sibling's RED `fn`
def test_scope_isolation_reused_local_name():
    src = ("import os\n\n\nclass T:\n    pass\n\n\n_T = T()\n\n\n"
           "def danger(arg):\n    fn = getattr(os, arg)\n    return fn(arg)\n\n\n"
           "def benign(arg):\n    fn = getattr(_T, arg)\n    return fn(arg)\n")
    assert "dynamic_dispatch" in _caps_at(src, 13)   # danger()'s fn -> flagged
    assert "dynamic_dispatch" not in _caps_at(src, 18)  # benign()'s fn -> clean


# ---- PRECISION: a generic name bound to an UNKNOWN/benign callable must NOT fire -------------------
def test_generic_binding_of_unknown_callable_not_flagged():
    # `handler` is bound to an attribute whose name is NOT in the sink vocabulary, on an unresolved
    # receiver — exactly the generic-dispatch case the AI finder must resolve, not static.
    src = ("def run(obj, data):\n    handler = obj.process\n    return handler(data)\n")
    assert _all_caps(src) == set()


def test_getattr_on_unresolved_param_not_flagged():
    # loader.py S13: getattr on a bare function parameter `mod` (an untrusted dynamic import upstream) is
    # NOT provably dangerous within this file -> left to the finder. Pins the honest residual.
    src = ("def run_hook(mod, hook_name, data):\n    handler = getattr(mod, hook_name)\n"
           "    return handler(data)\n")
    assert "dynamic_dispatch" not in _caps_at(src, 3)


# ---- RESIDUAL (documents a known gap): cross-file exec re-export is NOT resolved by the single-file
# engine. `_ex` is imported from another module where `_ex = exec` lives; without cross-file alias
# resolution the binding is invisible to this pass. HONEST LABEL: this is CROSS-FILE-DETERMINISTIC-PENDING,
# not an AI-only case — it is deterministically resolvable with cross-module alias resolution (the repo
# already ships cross_module.py / module_index.py); it is a scope limit of the per-file detect() pass.
# The scorer counts it as a genuine MISS at tol 0 (no locality bleed onto the neighbouring surface).
def test_cross_file_import_alias_is_residual_not_resolved():
    src = ("from _aliases import _ex\n\n\ndef py_tool(code):\n    return _ex(code)\n")
    assert "code_exec" not in _caps_at(src, 5)
