"""
Hermes Shield — ingress -> sink taint (v1, intra-function + store-aware). Connects UNTRUSTED input to a
dangerous SINK so the finder reports reachable ATTACK PATHS, not two unrelated lists.

HONEST CEILING (stated, never hidden): sound whole-program taint in dynamic Python is undecidable —
every practical tool (Pysa, Semgrep, CodeQL) is best-effort/unsound. This is INTRA-FUNCTION taint plus
STORE-AWARE sources (a worker that reads a queue/DB row and acts on it is caught IN that function).
Taint is still LOST (not tracked) across: inter-procedural returns (x = helper(text)), the persistent
store WRITE side in another process, dynamic dispatch, and unresolved attribute flows. Those are
honest limitations, never silent. v1 closed the skeptic gaps: store reads, for/augassign/annassign/
tuple bindings, os.environ / argparse / stdin / open().read() / LLM-output sources, broader params.

Static + read-only. Returns {call_lineno: source_description} for calls whose args carry taint.
"""
from __future__ import annotations
import ast

# parameter names conventionally carrying untrusted input. PRECISION FIX (taint-precision audit): the
# generic names (cmd/url/args/data/row/item/obj/m/q/update/query) were ~72% false positives on real
# code (developer-controlled argv/config/internal values), so they are REMOVED. Kept: names that
# specifically denote inbound external content. Web-handler names (request/req/webhook) stay — they
# fire on Flask/FastAPI targets, not this local-automation repo.
_UNTRUSTED_PARAMS = {
    "text", "content", "body", "message", "msg", "prompt", "payload", "user_input", "user_text",
    "comment", "reply", "reply_text", "tweet", "post_text", "raw", "html", "feed", "response_text",
    "untrusted", "external", "incoming", "webhook", "event", "notification", "req", "request", "input_text",
}
# source-method names on a request/response-like object. `get`/`getlist` are the common Flask/FastAPI
# idiom (`request.args.get("x")`) — they only fire here when the receiver is request-like (the _REQ_HINTS
# check below), so innocent `dict.get`/`os.environ.get`/`cfg.get` stay quiet.
_SOURCE_ATTRS = {"json", "form", "args", "values", "data", "get_json", "read", "text", "content", "body",
                 "get", "getlist"}
# store reads — a queue/DB row is untrusted (it holds whatever an ingress wrote). Skeptic FN1.
_STORE_READS = {"fetchone", "fetchall", "fetchmany", "get_next", "select_due", "dequeue", "next_due",
                "select_due_dm", "get_pending", "read_row", "poll"}
# S3.1 RAG retrieval reads — a vector/memory store returns whatever was ingested (poisoned corpus ->
# read back as trusted context). Distinctive names fire always; generic query/search need a store receiver.
_RETRIEVAL_READS = {"similarity_search", "similarity_search_with_score", "get_relevant_documents",
                    "max_marginal_relevance_search", "similarity_search_by_vector"}
_RETRIEVAL_GENERIC = {"query", "search", "retrieve", "recall"}
_RETRIEVAL_HINTS = ("vector", "retriever", "collection", "index", "store", "rag", "embed", "chroma",
                    "qdrant", "memory", "knowledge")
# LLM-output methods — the model boundary (constant prompt, tainted output). Skeptic FN3.
_LLM_METHODS = {"invoke", "chat", "complete", "completion", "generate", "predict", "call"}
_LLM_OUTPUTS = {"content", "text", "message", "output_text", "result"}
_SOURCE_NAMES = {"input"}
_REQ_HINTS = ("request", "req", "response", "resp", "flask", "message", "event", "webhook", "stdin")


def _root_str(node) -> str:
    s, cur = "", node
    while isinstance(cur, ast.Attribute):
        s = cur.attr + "." + s
        cur = cur.value
    if isinstance(cur, ast.Name):
        s = cur.id + "." + s
    return s.lower()


def _is_source_call(node, cli_main: bool = False) -> bool:
    """A call/subscript/attribute that yields untrusted data. `cli_main`=True when the enclosing module is a
    CLI child/script (`if __name__ == "__main__":`) — then `sys.stdin` is operator/parent-supplied IPC, NOT
    an attacker channel, so it is NOT a source (parallel to the argv/environ precision removal). S8.85."""
    if isinstance(node, ast.Call):
        f = node.func
        if isinstance(f, ast.Name) and f.id in _SOURCE_NAMES:
            return True
        if isinstance(f, ast.Attribute):
            if f.attr in _STORE_READS:
                return True                                   # queue/DB read row (load-bearing source)
            if f.attr in _RETRIEVAL_READS:
                return True                                   # RAG retrieval (poisoned corpus read-back)
            if f.attr in _RETRIEVAL_GENERIC and any(h in _root_str(f.value) for h in _RETRIEVAL_HINTS):
                return True
            # PRECISION FIX: getenv/parse_args REMOVED — env vars + operator CLI are developer/config-
            # controlled, not attacker input under this threat model (they were ~48+65 false positives).
            if f.attr in _SOURCE_ATTRS:
                recv = _root_str(f.value)
                # S8.85: `sys.stdin.read()` in a CLI __main__ script = trusted parent/operator IPC, not attacker.
                if cli_main and "stdin" in recv:
                    return False
                if any(h in recv for h in _REQ_HINTS):
                    return True
                if f.attr == "read" and isinstance(f.value, ast.Call):   # open(x).read()
                    return True
            if f.attr in _LLM_OUTPUTS and isinstance(f.value, ast.Call):  # not used (attr path below)
                return True
    if isinstance(node, ast.Attribute):
        # LLM output: <...>.invoke(prompt).content  — a source attr whose value is an LLM call
        if node.attr in _LLM_OUTPUTS and isinstance(node.value, ast.Call):
            vf = node.value.func
            if isinstance(vf, ast.Attribute) and vf.attr in _LLM_METHODS:
                return True
    if isinstance(node, ast.Subscript):
        s = _root_str(node.value)
        if "request" in s:                                    # request.args[] (web handler)
            return True                                       # argv/environ REMOVED (precision fix)
    return False


def _targets(node):
    """Yield bare Name targets from assign/for/with targets, incl. tuple/list unpacking."""
    if isinstance(node, ast.Name):
        yield node.id
    elif isinstance(node, (ast.Tuple, ast.List)):
        for e in node.elts:
            yield from _targets(e)


def _ap(node):
    """S8.23 access path: 'buf' for a Name, 'self.buf'/'obj.buf' for a simple Attribute chain rooted at a
    Name, else None. Case-preserving (do NOT lowercase). Generalises the tainted set from bare names to
    dotted field/container paths — bare-name behaviour is unchanged."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _ap(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


_CONTAINER_MUTATORS = {"append", "extend", "insert", "add", "update"}


class _FnTaint:
    def __init__(self, fnode, seed_params=None, call_returns_taint=None, field_taint_seed=None, cli_main=False):
        # S8 inter-procedural seams (defaults reproduce the intra-function behaviour exactly):
        #  * seed_params=None -> seed from _UNTRUSTED_PARAMS (today). seed_params=set -> seed EXACTLY those
        #    params (the inter-taint pass passes untrusted-params UNION inbound-tainted-params, or {} to
        #    ask "does this return an internal source regardless of args").
        #  * call_returns_taint(callnode, tainted) -> bool: a hook so a call that RETURNS taint (x =
        #    helper(untrusted)) is a source at the call site — the inter-procedural return flow.
        self.tainted = set()
        self.source = {}
        self.fnode = fnode
        self.call_returns_taint = call_returns_taint
        self.cli_main = cli_main                     # S8.85: suppress sys.stdin source in CLI __main__ scripts
        args = getattr(fnode, "args", None)
        if args:
            allp = list(args.args) + list(getattr(args, "kwonlyargs", [])) + list(getattr(args, "posonlyargs", []))
            if seed_params is None:
                for a in allp:
                    if a.arg in _UNTRUSTED_PARAMS:
                        self.tainted.add(a.arg)
                        self.source[a.arg] = f"untrusted param '{a.arg}'"
            else:
                for a in allp:
                    if a.arg in seed_params:
                        self.tainted.add(a.arg)
                        self.source[a.arg] = f"tainted param '{a.arg}'"
        if field_taint_seed:                       # S8.23: class field-cell seeds (self.<attr> tainted elsewhere)
            for ap in field_taint_seed:
                if ap not in self.tainted:
                    self.tainted.add(ap)
                    self.source[ap] = f"tainted field '{ap}'"
        for _ in range(5):  # cheap fixpoint
            changed = False
            for n in ast.walk(fnode):
                tainted, src, targets = False, "", []
                if isinstance(n, (ast.Assign, ast.AnnAssign)):
                    tainted, src = self._expr_taint(n.value)
                    targets = list(n.targets) if isinstance(n, ast.Assign) else ([n.target] if n.target else [])
                elif isinstance(n, ast.AugAssign):   # cmd += text
                    t1, s1 = self._expr_taint(n.value)
                    tainted, src = t1, s1
                    targets = [n.target]
                elif isinstance(n, (ast.For, ast.AsyncFor)):   # for row in payload
                    tainted, src = self._expr_taint(n.iter)
                    targets = [n.target]
                elif isinstance(n, ast.With):
                    for it in n.items:                          # with open(x) as f (rarely tainted)
                        t1, s1 = self._expr_taint(it.context_expr)
                        if t1 and it.optional_vars:
                            tainted, src, targets = True, s1, [it.optional_vars]
                elif (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                      and n.func.attr in _CONTAINER_MUTATORS):
                    # S8.23 container mutator: lst.append(untrusted) / d.update(x) -> taint the receiver path.
                    recv = _ap(n.func.value)
                    if recv:
                        for a in n.args:
                            t1, s1 = self._expr_taint(a)
                            if t1 and recv not in self.tainted:
                                self.tainted.add(recv)
                                self.source[recv] = s1
                                changed = True
                                break
                if tainted:
                    for tg in targets:
                        for name in _targets(tg):
                            if name not in self.tainted:
                                self.tainted.add(name)
                                self.source[name] = src
                                changed = True
                        # S8.23 field/subscript write: self.x = t -> taint 'self.x'; d[k] = t -> taint 'd'.
                        base = _ap(tg) if isinstance(tg, ast.Attribute) else (
                            _ap(tg.value) if isinstance(tg, ast.Subscript) else None)
                        if base and base not in self.tainted:
                            self.tainted.add(base)
                            self.source[base] = src
                            changed = True
            if not changed:
                break

    def _expr_taint(self, node):
        if node is None:
            return False, ""
        if _is_source_call(node, self.cli_main):
            return True, "untrusted source"
        if isinstance(node, ast.Call) and self.call_returns_taint and self.call_returns_taint(node, self.tainted):
            return True, "tainted return"
        for x in ast.walk(node):
            if isinstance(x, ast.Name) and x.id in self.tainted:
                return True, self.source.get(x.id, f"tainted var '{x.id}'")
            # S8.23 read side: a field/container access path in the tainted set (self.buf, d, obj.items).
            if isinstance(x, ast.Attribute):
                _p = _ap(x)
                if _p and _p in self.tainted:
                    return True, self.source.get(_p, f"tainted field '{_p}'")
            if isinstance(x, ast.Subscript):
                _p = _ap(x.value)
                if _p and _p in self.tainted:
                    return True, self.source.get(_p, f"tainted container '{_p}'")
            if isinstance(x, ast.Call) and self.call_returns_taint and self.call_returns_taint(x, self.tainted):
                return True, "tainted return"
            if isinstance(x, (ast.Call, ast.Subscript, ast.Attribute)) and _is_source_call(x, self.cli_main):
                return True, "untrusted source"
        return False, ""

    def arg_taint(self, argnode):
        """ADDITIVE public wrapper over the private expr-taint logic: does THIS single argument node carry
        taint, and via which source label? Returns (bool, src). The prove lane uses this to decide
        drivability on the INJECTABLE sink argument ONLY (dataflow-gated, not name-gated). Pure delegation
        — it changes neither `_UNTRUSTED_PARAMS`, `analyze()`, nor the default `seed_params=None` path."""
        return self._expr_taint(argnode)

    def field_writes(self):
        """S8.23: the self.<attr>/cls.<attr> paths this function taints — the class field-cell consumes these."""
        return {ap for ap in self.tainted if ap.startswith(("self.", "cls."))}

    def sink_source(self, callnode):
        for a in list(callnode.args) + [k.value for k in callnode.keywords]:
            t, src = self._expr_taint(a)
            if t:
                return src
        return None

    def returns_tainted(self):
        """(bool, src): does any `return` in this function carry taint? Used for the RET summary."""
        for n in ast.walk(self.fnode):
            if isinstance(n, ast.Return) and n.value is not None:
                t, src = self._expr_taint(n.value)
                if t:
                    return True, src
        return False, ""

    def tainted_sinks(self):
        """{call_lineno: src} for calls in THIS function whose args carry taint (per-function analyze)."""
        out = {}
        for n in ast.walk(self.fnode):
            if isinstance(n, ast.Call):
                src = self.sink_source(n)
                if src:
                    out[n.lineno] = src
        return out


def analyze(tree, cli_main: bool = False) -> dict:
    """Return {call_lineno: source_desc} for calls whose arguments carry untrusted taint. `cli_main`=True
    (module has a `__main__` guard) suppresses the sys.stdin source (trusted parent/operator IPC). S8.85."""
    out = {}
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            ft = _FnTaint(fn, cli_main=cli_main)
            # NB: do NOT skip when ft.tainted is empty — a source can appear DIRECTLY in a sink arg
            # (os.system(os.environ['X'])) with no intermediate tainted variable.
            for n in ast.walk(fn):
                if isinstance(n, ast.Call):
                    src = ft.sink_source(n)
                    if src:
                        out[n.lineno] = src
    return out
