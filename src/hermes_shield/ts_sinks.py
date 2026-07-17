"""
ts_sinks.py (S8.24) — TypeScript/JavaScript sink front-end via tree-sitter.

v1 = SINKS-ONLY (blast-radius). Finds dangerous action-surfaces mapped to our shared capability vocabulary,
using tree-sitter (one universal parser, no Node runtime). NO taint or guard analysis yet, so every TS
surface is emitted with tainted_reachable=False -> guard-attribution reads guard as "unknown" ->
NEEDS_CALL_GRAPH / REVIEW. It NEVER claims UNGUARDED_CRITICAL_LIVE_SINK (that needs taint+guard, v2/v3). This
is the same honest "surfaces found" signal we already report, just extended to a new language. Every finding
is tagged language='typescript' so the census never double-counts or misattributes.

JS truth (do NOT blindly port Python): JSON.parse is NOT deserialize; process.argv/env are operator-controlled.
"""
from __future__ import annotations

try:
    import tree_sitter_typescript as _tsts
    from tree_sitter import Language, Parser
    _LANG_TS = Language(_tsts.language_typescript())
    _LANG_TSX = Language(_tsts.language_tsx())
    _OK = True
except Exception:
    _OK = False

# bare-name calls (high confidence): the danger is the function itself.
_BARE_CAP = {
    "eval": "code_exec", "Function": "code_exec",
}
# method names (danger is the method); some need an object hint (below).
_METHOD_CAP = {
    "spawn": "subprocess_exec", "spawnSync": "subprocess_exec",
    "runInNewContext": "code_exec", "runInThisContext": "code_exec", "compileFunction": "code_exec",
    "writeFile": "file_write", "writeFileSync": "file_write", "appendFile": "file_write",
    "appendFileSync": "file_write", "createWriteStream": "file_write",
    "unlink": "file_delete", "unlinkSync": "file_delete", "rm": "file_delete", "rmSync": "file_delete",
    "rmdir": "file_delete", "rmdirSync": "file_delete",
    "callTool": "tool_invoke",                       # MCP client.callTool — distinctive
    "sendMail": "email_send",
}
_HTTP_WRITE = {"post", "put", "patch", "delete"}     # axios.post / client.post / http.request
_HTTP_HINTS = ("axios", "http", "https", "fetch", "client", "request", "got", "api")
_TOOL_HINTS = ("tool", "agent", "chain", "executor", "crew")
_BROWSER_METHODS = {"goto", "click", "fill", "type", "press", "selectOption", "setInputFiles"}


def _text(node, src):
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _callee(node, src):
    fn = node.child_by_field_name("function")
    if fn is None:
        return None, ""
    if fn.type == "identifier":
        return _text(fn, src), ""
    if fn.type == "member_expression":
        prop = fn.child_by_field_name("property")
        obj = fn.child_by_field_name("object")
        method = _text(prop, src) if prop else None
        objstr = _text(obj, src) if obj else ""
        return method, objstr
    return None, ""


# exec/execSync/execFile are AMBIGUOUS in JS: child_process.exec (dangerous) vs regex.exec (harmless).
# Fire only when bare (imported from child_process) or the object clearly hints child_process; NEVER on a
# regex/pattern/matcher receiver. This is the JS analogue of the Python precision gates.
_EXEC_METHODS = {"exec", "execSync", "execFile", "execFileSync", "fork"}
_CP_HINTS = ("cp", "child", "process", "shell", "execa", "sh", "proc", "spawn")
_REGEX_HINTS = ("regex", "regexp", "pattern", "matcher", "\brx", "re.", "expr")


def _capability(method, objstr):
    if method in _BARE_CAP and not objstr:
        return _BARE_CAP[method]
    ol = objstr.lower()
    if method in _EXEC_METHODS:
        if any(r in ol for r in _REGEX_HINTS):
            return None                               # regex.exec / pattern.exec -> not a subprocess
        if not objstr or any(h in ol for h in _CP_HINTS):
            return "subprocess_exec"
        return None                                   # exec on an unknown object -> under-claim (safe)
    if method in _METHOD_CAP:
        return _METHOD_CAP[method]
    if method in _HTTP_WRITE and any(h in ol for h in _HTTP_HINTS):
        return "external_write"
    if method == "evaluate" and "page" in ol:
        return "code_exec"                            # page.evaluate (const-body refinement is v2)
    if method in _BROWSER_METHODS and "page" in ol:
        return "browser_submit"
    if method in ("invoke", "run", "call") and any(t in ol for t in _TOOL_HINTS):
        return "tool_invoke"
    # S8.35 cross-language absorb: a rule the loop LEARNED (any language) fires here too — the compounding
    # now spans all lanes, not just Python. Distinctive learned names only (guarded at absorb time).
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


def detect(text: str, tsx: bool = False):
    """Return (ok, sinks). Each sink is the same dict shape ast_sinks emits, tagged language='typescript'."""
    if not _OK:
        return False, []
    try:
        parser = Parser(_LANG_TSX if tsx else _LANG_TS)
        src = text.encode("utf-8")
        tree = parser.parse(src)
    except Exception:
        return False, []
    sinks, stack = [], [tree.root_node]
    while stack:
        n = stack.pop()
        if n.type == "call_expression":
            method, objstr = _callee(n, src)
            if method:
                cap = _capability(method, objstr)
                if cap:
                    sinks.append({
                        "line": n.start_point[0] + 1, "capability": cap, "mutating": "yes",
                        "sink_kind": "ts_call", "enclosing_symbol": "", "module_scope": False,
                        "call_expr": (objstr + "." if objstr else "") + str(method),
                        "auth_gated": False, "dest_provenance": "unknown", "language": "typescript"})
        for c in n.children:
            stack.append(c)
    return True, sinks
