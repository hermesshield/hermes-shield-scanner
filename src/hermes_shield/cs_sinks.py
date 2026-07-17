"""
cs_sinks.py (S8.25) — C#/.NET sink front-end via tree-sitter. v1 sinks-only (blast-radius), same honesty
posture as ts_sinks: no taint/guard -> never UNGUARDED_CRITICAL. Tagged language='csharp'.

Maps .NET + Semantic Kernel surfaces to our capability vocabulary. C# ambiguities handled like JS: a method
name alone is not enough where the type disambiguates (Process.Start vs a local .Start()).
"""
from __future__ import annotations

try:
    import tree_sitter_c_sharp as _tscs
    from tree_sitter import Language, Parser
    _LANG = Language(_tscs.language())
    _OK = True
except Exception:
    _OK = False

# (object-hint, method) -> capability. object hint matched case-insensitively as a substring of the receiver.
_OBJ_METHOD = {
    ("process", "Start"): "subprocess_exec",
    ("file", "WriteAllText"): "file_write", ("file", "WriteAllBytes"): "file_write",
    ("file", "AppendAllText"): "file_write", ("file", "WriteAllLines"): "file_write",
    ("file", "AppendAllLines"): "file_write", ("file", "Create"): "file_write", ("file", "Copy"): "file_write",
    ("file", "Delete"): "file_delete", ("directory", "Delete"): "file_delete",
    ("csharpscript", "EvaluateAsync"): "code_exec", ("csharpscript", "RunAsync"): "code_exec",
    ("assembly", "Load"): "code_exec", ("assembly", "LoadFrom"): "code_exec", ("assembly", "LoadFile"): "code_exec",
    ("binaryformatter", "Deserialize"): "deserialize", ("formatter", "Deserialize"): "deserialize",
}
# method + a set of receiver hints (any) -> capability
_METHOD_HINT = {
    "PostAsync": ("external_write", ("client", "http", "web", "api", "rest")),
    "PutAsync": ("external_write", ("client", "http", "web", "api", "rest")),
    "PatchAsync": ("external_write", ("client", "http", "web", "api", "rest")),
    "DeleteAsync": ("external_write", ("client", "http", "web", "api", "rest")),
    "SendAsync": ("external_write", ("client", "http", "web", "api")),
    "UploadString": ("external_write", ("client", "web")), "UploadData": ("external_write", ("client", "web")),
    "InvokeAsync": ("tool_invoke", ("kernel", "function", "plugin", "skill", "tool", "agent")),
    "Invoke": ("tool_invoke", ("kernel", "function", "plugin", "skill", "tool", "agent")),
    "ExecuteNonQuery": ("db_mutation", ("command", "cmd", "sql")),
    "ExecuteReader": ("db_mutation", ("command", "cmd", "sql")),
    "ExecuteScalar": ("db_mutation", ("command", "cmd", "sql")),
}


def _text(node, src):
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _callee(node, src):
    fn = node.child_by_field_name("function")
    if fn is None:
        return None, ""
    if fn.type == "member_access_expression":
        name = fn.child_by_field_name("name")
        obj = fn.child_by_field_name("expression")
        return (_text(name, src) if name else None), (_text(obj, src) if obj else "")
    if fn.type == "identifier":
        return _text(fn, src), ""
    return None, ""


def _capability(method, objstr):
    ol = objstr.lower()
    if method:
        for (objhint, m), cap in _OBJ_METHOD.items():
            if m == method and objhint in ol:
                return cap
        if method in _METHOD_HINT:
            cap, hints = _METHOD_HINT[method]
            if any(h in ol for h in hints):
                return cap
        # S8.35 cross-language absorb: a learned rule (from any lane) fires in C# too.
        lc = _learned().get(method)
        if lc:
            return lc
    return None


def _learned():
    try:
        from . import learned_sinks
        return learned_sinks.learned_name_sinks()
    except Exception:
        return {}


def detect(text: str):
    if not _OK:
        return False, []
    try:
        parser = Parser(_LANG)
        src = text.encode("utf-8")
        tree = parser.parse(src)
    except Exception:
        return False, []
    sinks, stack = [], [tree.root_node]
    while stack:
        n = stack.pop()
        if n.type == "invocation_expression":
            method, objstr = _callee(n, src)
            cap = _capability(method, objstr)
            if cap:
                sinks.append({
                    "line": n.start_point[0] + 1, "capability": cap, "mutating": "yes",
                    "sink_kind": "cs_call", "enclosing_symbol": "", "module_scope": False,
                    "call_expr": (objstr + "." if objstr else "") + str(method),
                    "auth_gated": False, "dest_provenance": "unknown", "language": "csharp"})
        for c in n.children:
            stack.append(c)
    return True, sinks
