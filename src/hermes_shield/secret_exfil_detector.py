"""
secret_exfil_detector.py (S8.64) — FP-SAFE focused detector for secret exfiltration. Ships ONLY the two
sub-patterns that are high-precision statically (a general "secret reaches an egress" rule is a false-positive
cannon — every authenticated API call sends a token — so it is deliberately NOT shipped):

  (A) secret -> SERIALISER (pickle/json/yaml dumps) -> egress / agent-visible channel  (the LangGrinch
      CVE-2025-68664 shape; normal auth puts the RAW token in a header, it never pickles it into a body)
  (B) secret -> LLM prompt / tool-result  (you never legitimately put an API key in prompt text)

MANDATORY exclusion: a secret in a headers=/auth=/cookies= kwarg of an HTTP call is normal auth, never flagged.
Confidentiality-OUT is the dual of taint (untrustedness-IN), so this is a standalone detector, NOT merged into
taint.py (which deliberately dropped os.environ as a source). Under-claims: cross-function secret flow, secrets
in generic-named vars, and file/DB-read secrets are all missed by design.
"""
from __future__ import annotations
import ast
import re

_SECRET_KEY_RE = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_KEY|CREDENTIAL|BEARER|APIKEY)", re.I)
# STRONG compound names — unambiguous secrets (bare token/key/secret are EXCLUDED: pagination/CSRF/dict-key FPs)
_SECRET_NAMES = ("api_key", "apikey", "secret_key", "access_token", "private_key", "client_secret",
                 "password", "passwd", "bearer_token", "secret_token", "auth_token", "aws_secret")
_SERIALISER_ATTRS = {"dumps", "dump", "encode"}
_SERIALISER_MODS = ("pickle", "json", "yaml", "jsonpickle", "cloudpickle", "marshal", "dill")
_EGRESS_NAMES = {"post", "put", "patch", "send", "request", "sendall", "publish", "upload",
                 "send_direct_message", "send_message", "sendMessage", "write", "emit"}
_LLM_CALLS = {"invoke", "chat", "complete", "completion", "generate", "predict", "create", "acreate", "ask", "run"}
_AUTH_KWARGS = {"headers", "auth", "cookies", "params"}


def _is_secret_source(node):
    """os.environ[SECRET_KEY] / os.getenv('SECRET') / keyring.get_password / *.get_secret_value with a secret key."""
    if isinstance(node, ast.Subscript):                      # os.environ['API_KEY']
        base = node.value
        if isinstance(base, ast.Attribute) and base.attr == "environ":
            k = node.slice
            return isinstance(k, ast.Constant) and isinstance(k.value, str) and bool(_SECRET_KEY_RE.search(k.value))
    if isinstance(node, ast.Call):
        fn = node.func
        name = fn.attr if isinstance(fn, ast.Attribute) else (fn.id if isinstance(fn, ast.Name) else "")
        if name in ("getenv",) and node.args and isinstance(node.args[0], ast.Constant):
            return bool(_SECRET_KEY_RE.search(str(node.args[0].value)))
        if name in ("get_password", "get_secret_value", "get_secret"):
            return True
    return False


def _is_secret_name(name):
    n = (name or "").lower()
    return any(s == n or s in n for s in _SECRET_NAMES)


def _serialiser_receiver(call):
    """If `call` is a serialiser (pickle.dumps/json.dumps/yaml.dump/...), return True."""
    if not isinstance(call, ast.Call):
        return False
    fn = call.func
    if isinstance(fn, ast.Attribute) and fn.attr in _SERIALISER_ATTRS:
        recv = fn.value
        rname = recv.id if isinstance(recv, ast.Name) else (recv.attr if isinstance(recv, ast.Attribute) else "")
        return rname.lower() in _SERIALISER_MODS
    return False


def _refs_secret(node, secret_vars):
    """Does this expression reference a secret var / a secret source / a secret-named f-string field?"""
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and n.id in secret_vars:
            return True
        if _is_secret_source(n):
            return True
    return False


def _is_egress_call(call):
    if not isinstance(call, ast.Call):
        return False
    fn = call.func
    name = fn.attr if isinstance(fn, ast.Attribute) else (fn.id if isinstance(fn, ast.Name) else "")
    return name in _EGRESS_NAMES


def _is_llm_call(call):
    if not isinstance(call, ast.Call):
        return False
    fn = call.func
    name = fn.attr if isinstance(fn, ast.Attribute) else (fn.id if isinstance(fn, ast.Name) else "")
    return name in _LLM_CALLS


def _positional_and_data_args(call):
    """Args that are a payload BODY (positional + data=/json=/body=) — NOT the auth kwargs (excluded)."""
    out = list(call.args)
    for kw in call.keywords:
        if kw.arg in ("data", "json", "body", "content", "payload", "message", "text"):
            out.append(kw.value)
        # headers=/auth=/cookies=/params= are the normal-auth channel -> EXCLUDED (not added)
    return out


def _detect_in_function(fn):
    assigns = {}
    for n in ast.walk(fn):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    assigns[t.id] = n.value
    # secret vars: assigned from a secret source, or a strong secret name assigned from *something*
    secret_vars = set()
    for name, rhs in assigns.items():
        if _is_secret_source(rhs) or _is_secret_name(name):
            secret_vars.add(name)
    # serialised-secret vars: assigned from a serialiser whose args reference a secret
    serialised_secret = set()
    for name, rhs in assigns.items():
        if _serialiser_receiver(rhs) and any(_refs_secret(a, secret_vars) for a in getattr(rhs, "args", [])):
            serialised_secret.add(name)

    findings = []
    for n in ast.walk(fn):
        if not isinstance(n, ast.Call):
            continue
        # Pattern A: egress whose BODY arg is a serialised-secret (or serialises a secret inline)
        if _is_egress_call(n):
            for a in _positional_and_data_args(n):
                inline_ser = _serialiser_receiver(a) and any(_refs_secret(x, secret_vars) for x in a.args)
                if (isinstance(a, ast.Name) and a.id in serialised_secret) or inline_ser:
                    findings.append({"line": n.lineno, "pattern": "serialise->egress", "confidence": "high"})
                    break
        # Pattern B: LLM call whose prompt references a secret
        if _is_llm_call(n):
            if any(_refs_secret(a, secret_vars) for a in n.args):
                findings.append({"line": n.lineno, "pattern": "secret->llm", "confidence": "high"})
    return findings


def detect(text: str):
    """Return [{line, pattern, confidence}] for the two shippable secret-exfil sub-patterns."""
    try:
        tree = ast.parse(text)
    except Exception:
        return []
    out = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.extend(_detect_in_function(node))
    return out
