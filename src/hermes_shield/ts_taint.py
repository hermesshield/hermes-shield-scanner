"""
ts_taint.py (S8.27) — TypeScript intra-function + intra-file field-cell taint via tree-sitter.

A 1:1 port of taint.py's _FnTaint to TypeScript nodes: tracks untrusted input through variables, this.<field>
(across methods of the same class), and containers, then reports sinks whose args carry taint. Makes TS
surfaces tainted_reachable=True.

HONESTY CEILING (do not exceed): this proves REACHABILITY only. It does NOT prove "unguarded" — a third-party
TS repo uses its own guard idioms, so guard stays "unknown" and the verdict tops out at REVIEW, never the
UNGUARDED_CRITICAL headline (that needs a per-repo guard vocabulary, v3). Sources exclude process.argv/env
(operator-controlled). Under-claims aliasing / renamed-destructuring / for-in / cross-file (safe direction).
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

_UNTRUSTED_PARAMS = {"message", "msg", "body", "payload", "prompt", "content", "req", "request",
                     "webhook", "event", "comment", "reply", "text", "html", "user_input", "input_text"}
_SOURCE_PROPS = {"body", "query", "params", "headers", "cookies", "data", "content"}
_SOURCE_ROOTS = {"req", "request", "ctx", "event", "message", "msg", "res", "response"}
_SOURCE_CALLS = {"json", "text", "formData", "recv", "receive", "readResource"}
_CONTAINER_MUTATORS = {"push", "unshift", "add", "set"}


def _txt(n, src):
    return src[n.start_byte:n.end_byte].decode("utf-8", "replace")


def _ap(node, src):
    """Access path: name -> 'buf'; this -> 'this'; member a.b -> 'a.b'; else None. Case-preserving."""
    if node is None:
        return None
    if node.type == "identifier":
        return _txt(node, src)
    if node.type == "this":
        return "this"
    if node.type in ("member_expression", "optional_member_expression"):
        base = _ap(node.child_by_field_name("object"), src)
        prop = node.child_by_field_name("property")
        return f"{base}.{_txt(prop, src)}" if (base and prop) else None
    return None


def _is_source(node, src):
    """Untrusted-source expression: req.body-style property read, res.json()-style call. Excludes process.*"""
    if node is None:
        return False
    if node.type in ("member_expression", "optional_member_expression"):
        obj = node.child_by_field_name("object")
        prop = node.child_by_field_name("property")
        if prop is None:
            return False
        # exclude operator-controlled process.env / process.argv anywhere in the chain
        root = obj
        while root is not None and root.type in ("member_expression", "optional_member_expression"):
            root = root.child_by_field_name("object")
        if root is not None and root.type == "identifier" and _txt(root, src) == "process":
            return False
        prop_t = _txt(prop, src)
        obj_root = _ap(obj, src) or ""
        obj_first = obj_root.split(".")[0]
        if prop_t in _SOURCE_PROPS and obj_first in _SOURCE_ROOTS:
            return True
    if node.type == "call_expression":
        fn = node.child_by_field_name("function")
        if fn is not None and fn.type in ("member_expression", "optional_member_expression"):
            prop = fn.child_by_field_name("property")
            obj = fn.child_by_field_name("object")
            if prop is not None and _txt(prop, src) in _SOURCE_CALLS:
                or_ = (_ap(obj, src) or "").lower()
                if any(h in or_ for h in ("res", "response", "fetch", "client", "mcp")):
                    return True
    return False


class _TsFn:
    def __init__(self, body_node, src, params=None, field_seed=None):
        self.src = src
        self.body = body_node
        self.tainted = set()
        self.source = {}
        for p in (params or []):
            if p in _UNTRUSTED_PARAMS:
                self.tainted.add(p)
                self.source[p] = f"untrusted param '{p}'"
        if field_seed:
            for ap in field_seed:
                self.tainted.add(ap)
                self.source[ap] = f"tainted field '{ap}'"
        for _ in range(5):
            if not self._round():
                break

    def _round(self):
        changed = False
        for n in _walk(self.body):
            tainted, src, targets = False, "", []
            if n.type == "variable_declarator":
                tainted, src = self._expr_taint(n.child_by_field_name("value"))
                targets = [n.child_by_field_name("name")]
            elif n.type == "assignment_expression":
                tainted, src = self._expr_taint(n.child_by_field_name("right"))
                targets = [n.child_by_field_name("left")]
            elif n.type == "augmented_assignment_expression":
                tainted, src = self._expr_taint(n.child_by_field_name("right"))
                targets = [n.child_by_field_name("left")]
            elif n.type == "for_in_statement":
                op = n.child_by_field_name("operator")
                if op is not None and _txt(op, self.src) == "of":   # for-of = values; skip for-in (keys)
                    tainted, src = self._expr_taint(n.child_by_field_name("right"))
                    targets = [n.child_by_field_name("left")]
            elif n.type == "call_expression":
                fn = n.child_by_field_name("function")
                if fn is not None and fn.type == "member_expression":
                    prop = fn.child_by_field_name("property")
                    if prop is not None and _txt(prop, self.src) in _CONTAINER_MUTATORS:
                        recv = _ap(fn.child_by_field_name("object"), self.src)
                        args = n.child_by_field_name("arguments")
                        if recv and args and any(self._expr_taint(a)[0] for a in args.named_children):
                            if recv not in self.tainted:
                                self.tainted.add(recv); self.source[recv] = "tainted container"; changed = True
            if tainted:
                for tg in targets:
                    for name in _bound_names(tg, self.src):
                        if name not in self.tainted:
                            self.tainted.add(name); self.source[name] = src; changed = True
                    if tg is not None and tg.type in ("member_expression", "optional_member_expression"):
                        ap = _ap(tg, self.src)
                        if ap and ap not in self.tainted:
                            self.tainted.add(ap); self.source[ap] = src; changed = True
                    if tg is not None and tg.type == "subscript_expression":
                        ap = _ap(tg.child_by_field_name("object"), self.src)
                        if ap and ap not in self.tainted:
                            self.tainted.add(ap); self.source[ap] = src; changed = True
        return changed

    def _expr_taint(self, node):
        if node is None:
            return False, ""
        if _is_source(node, self.src):
            return True, "untrusted source"
        for x in _walk(node):
            if x.type == "identifier" and _txt(x, self.src) in self.tainted:
                nm = _txt(x, self.src)
                return True, self.source.get(nm, f"tainted var '{nm}'")
            if x.type in ("member_expression", "optional_member_expression"):
                ap = _ap(x, self.src)
                if ap and ap in self.tainted:
                    return True, self.source.get(ap, f"tainted field '{ap}'")
            if x.type == "subscript_expression":
                ap = _ap(x.child_by_field_name("object"), self.src)
                if ap and ap in self.tainted:
                    return True, self.source.get(ap, f"tainted container '{ap}'")
            if _is_source(x, self.src):
                return True, "untrusted source"
        return False, ""

    def tainted_sinks(self):
        out = {}
        for n in _walk(self.body):
            if n.type == "call_expression":
                args = n.child_by_field_name("arguments")
                if args:
                    for a in args.named_children:
                        t, src = self._expr_taint(a)
                        if t:
                            out[n.start_point[0] + 1] = src
                            break
        return out

    def field_writes(self):
        return {ap for ap in self.tainted if ap.startswith("this.")}


def _walk(node):
    if node is None:
        return
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        for c in n.children:
            stack.append(c)


def _bound_names(tg, src):
    """Bare names bound by a target: identifier, and shorthand object/array patterns (not renamed/computed)."""
    if tg is None:
        return
    if tg.type == "identifier":
        yield _txt(tg, src)
    elif tg.type in ("object_pattern", "array_pattern"):
        for c in tg.named_children:
            if c.type == "shorthand_property_identifier_pattern":
                yield _txt(c, src)
            elif c.type == "identifier":
                yield _txt(c, src)


def _params_of(fn_node, src):
    ps = fn_node.child_by_field_name("parameters")
    out = []
    if ps:
        for p in ps.named_children:
            pat = p.child_by_field_name("pattern") if p.type in ("required_parameter", "optional_parameter") else p
            if pat is not None and pat.type == "identifier":
                out.append(_txt(pat, src))
    return out


_FN_TYPES = {"function_declaration", "method_definition", "arrow_function", "function_expression"}


def analyze(text: str, tsx: bool = False) -> dict:
    """Return {sink_line: source_desc} for TS calls whose args carry untrusted taint (intra-fn + this-field)."""
    if not _OK:
        return {}
    try:
        parser = Parser(_LANG_TSX if tsx else _LANG_TS)
        src = text.encode("utf-8")
        tree = parser.parse(src)
    except Exception:
        return {}
    out = {}
    # per-class field-cell: this.<field> tainted in any method -> seed all methods of that class
    for cls in _walk(tree.root_node):
        if cls.type != "class_declaration":
            continue
        body = cls.child_by_field_name("body")
        methods = [m for m in (body.named_children if body else []) if m.type == "method_definition"] if body else []
        FT = set()
        for _ in range(4):
            grew = False
            for m in methods:
                mb = m.child_by_field_name("body")
                fw = _TsFn(mb, src, _params_of(m, src), field_seed=FT).field_writes()
                if not fw <= FT:
                    FT |= fw; grew = True
            if not grew:
                break
        for m in methods:
            mb = m.child_by_field_name("body")
            ft = _TsFn(mb, src, _params_of(m, src), field_seed=FT)
            out.update(ft.tainted_sinks())
    # standalone functions
    for fn in _walk(tree.root_node):
        if fn.type in _FN_TYPES:
            body = fn.child_by_field_name("body")
            ft = _TsFn(body, src, _params_of(fn, src))
            out.update(ft.tainted_sinks())
    return out
