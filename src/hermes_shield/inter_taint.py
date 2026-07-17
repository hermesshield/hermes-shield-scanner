"""
inter_taint.py (S8) — cross-function (inter-procedural) taint. NO LLM.

Extends the intra-function taint (taint.py) ACROSS the call graph so an injected input that reaches a sink
THROUGH helper functions/files is proven reachable — the fix for "SuperAGI 259 dangerous but only 5 proven
reachable". Drives guard_attribution's tainted axis -> the "X surfaces an injected prompt can ACTUALLY reach
unguarded" number that sells.

SOUND-LEANING: a sink is marked tainted only when a CONCRETE, RESOLVED origin->param->arg->...->sink chain
exists. Unresolved calls (dynamic dispatch, getattr, ambiguous/star imports, *args) are SKIPPED, never
guessed. Upgrade-only (never flips a sink from reachable to not); fail-open to the intra-function bit.

Two per-function summaries converged by a bounded worklist fixpoint, then materialised:
  RET[(rel,fn)] = (ret_intrinsic, ret_params)  -> fixes `x = helper(untrusted); sink(x)`
  TP[(rel,fn)]  = params tainted at some real call site  -> the caller->callee direction
"""
from __future__ import annotations
import ast
from pathlib import Path
from typing import Dict, Optional, Tuple

from . import taint as T
from . import call_graph as CG
from . import cross_module as XM

_MAX_ROUNDS = 6


def _build_defs(root: Path, graphs) -> Dict[Tuple[str, str], ast.AST]:
    defs = {}
    for rel in graphs:
        try:
            tree = ast.parse((root / rel).read_text(encoding="utf-8"))
        except Exception:
            continue
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defs.setdefault((rel, n.name), n)
    return defs


def _build_classes(root: Path, graphs):
    """S8.23: structural class membership (never name-based). Returns (fk2class, class2methods): a method's
    class is the ClassDef whose DIRECT body contains it, so same-named methods in two classes never collide."""
    fk2class, class2methods = {}, {}
    for rel in graphs:
        try:
            tree = ast.parse((root / rel).read_text(encoding="utf-8"))
        except Exception:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                ck = (rel, node.name)
                for m in node.body:                       # DIRECT body only
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        mk = (rel, m.name)
                        fk2class[mk] = ck
                        class2methods.setdefault(ck, set()).add(mk)
    return fk2class, class2methods


def _params(defnode) -> list:
    a = getattr(defnode, "args", None)
    if not a:
        return []
    return [p.arg for p in (list(a.posonlyargs) + list(a.args))]


def _resolve_call(callnode, caller_rel, caller_graph, defs, mod2files):
    """-> (target_rel, funcname, is_method) or None. Sound-leaning: unresolved -> None (skip the edge)."""
    f = callnode.func
    if isinstance(f, ast.Name):                                   # helper(...)
        name = f.id
        if (caller_rel, name) in defs and name in caller_graph.local_names:
            return (caller_rel, name, False)
        imp = caller_graph.imports.get(name)
        if imp:
            orig = imp.get("orig") or name
            tf = XM.resolve_import_to_file(imp, caller_rel, mod2files)
            if tf and (tf, orig) in defs:
                return (tf, orig, False)
        return None
    if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == "self":
        name = f.attr                                            # self.method(...)
        if (caller_rel, name) in defs:
            return (caller_rel, name, True)
    return None                                                  # obj.m / mod.func / getattr -> skip (safe)


def _map_args_to_params(callnode, defnode, is_method):
    """Yield (argnode, param_name). Positional (drop self on a method call), then keywords. *args/**kwargs
    or an arity mismatch -> yield nothing for the affected args (never smear across an unknown boundary)."""
    params = _params(defnode)
    if is_method and params:
        params = params[1:]                                      # drop the implicit self
    if any(isinstance(a, ast.Starred) for a in callnode.args):
        return
    for i, a in enumerate(callnode.args):
        if i < len(params):
            yield a, params[i]
    for kw in callnode.keywords:
        if kw.arg and kw.arg in params:
            yield kw.value, kw.arg


def _shallow_tainted(node, tainted_set, cli_main: bool = False) -> bool:
    """Does `node` carry taint given `tainted_set` — a Name in the set OR a direct source call? Non-recursive
    into the return-hook (avoids unbounded recursion), so no _expr_taint re-entry. `cli_main` suppresses the
    sys.stdin source in a CLI __main__ script (trusted parent IPC). S8.85."""
    for x in ast.walk(node):
        if isinstance(x, ast.Name) and x.id in tainted_set:
            return True
        if isinstance(x, (ast.Call, ast.Subscript, ast.Attribute)) and T._is_source_call(x, cli_main):
            return True
    return False


def _ai_line_taint(ft, defnode, line):
    """S8.83: does a CONCRETE resolved taint chain reach the AI-asserted action line? Same sound standard
    as a static sink — the Call at `line` must carry taint in an ARG/keyword (identical to sink_source) OR
    in its RECEIVER (obj.action() where obj holds untrusted data — the untrusted object performs the action).
    Bounded to the actual call on that line; no window/tolerance -> cannot over-mark a neighbouring line."""
    for n in ast.walk(defnode):
        if isinstance(n, ast.Call) and getattr(n, "lineno", None) == line:
            src = ft.sink_source(n)               # args/keywords tainted (the static-sink standard)
            if src:
                return src
            f = n.func                            # receiver-taint: the one AI-target extension, tested below
            if isinstance(f, ast.Attribute):
                t, s = ft._expr_taint(f.value)
                if t:
                    return s
    return None


def compute(root: Path, graphs, mod2files, extra_targets=None) -> dict:
    """Return {rel: {sink_call_line: source_desc}} for cross-function-reachable sinks. `extra_targets`
    (S8.83) = {rel: {line,...}} of AI-asserted action lines to ALSO test for reachability using the same
    sound taint fixpoint, so an AI surface at a line the static sink-patterns don't recognise is still
    reachability-tested. Empty/None -> behaviour byte-identical to before (off-path unchanged)."""
    root = Path(root)
    extra_targets = extra_targets or {}
    defs = _build_defs(root, graphs)
    RET = {fk: (False, set()) for fk in defs}       # (ret_intrinsic, ret_params)
    TP = {fk: set() for fk in defs}
    limits = {"unresolved_calls": 0}
    from .entrypoints import detect_entrypoints         # S8.42: ground taint in REAL entrypoints
    entrypoints = detect_entrypoints(graphs)
    # S8.85: modules that run as a CLI child/script (`__main__` guard) — their sys.stdin is trusted parent IPC.
    cli_main_rels = {rel for rel, g in graphs.items() if getattr(g, "cli_main", False)}

    def make_hook(caller_rel, caller_graph):
        _caller_cli = caller_rel in cli_main_rels
        def hook(callnode, tainted_set):
            g = _resolve_call(callnode, caller_rel, caller_graph, defs, mod2files)
            if not g:
                return False
            gk = (g[0], g[1])
            intrinsic, ret_params = RET.get(gk, (False, set()))
            if intrinsic:
                return True
            for argnode, pname in _map_args_to_params(callnode, defs[gk], g[2]):
                if pname in ret_params and _shallow_tainted(argnode, tainted_set, _caller_cli):
                    return True
            return False
        return hook

    worklist = set(defs)
    for _round in range(_MAX_ROUNDS):
        if not worklist:
            break
        nxt = set()
        for fk in sorted(worklist):
            rel, fn = fk
            cg = graphs.get(rel)
            if not cg or fn not in cg.funcs:
                continue
            hook = make_hook(rel, cg)
            _cli = rel in cli_main_rels
            seed = _entrypoint_untrusted_of(fk, entrypoints) | TP[fk]
            ft = T._FnTaint(defs[fk], seed_params=seed, call_returns_taint=hook, cli_main=_cli)
            # (a) RET update
            new_intrinsic = T._FnTaint(defs[fk], seed_params=set(), call_returns_taint=hook, cli_main=_cli).returns_tainted()[0]
            new_ret_params = {p for p in _params(defs[fk])
                              if T._FnTaint(defs[fk], seed_params={p}, call_returns_taint=hook, cli_main=_cli).returns_tainted()[0]}
            old = RET[fk]
            if new_intrinsic != old[0] or not new_ret_params <= old[1]:
                RET[fk] = (old[0] or new_intrinsic, old[1] | new_ret_params)
                # a grown summary re-enqueues callers (approximated as all funcs in the calling files)
                nxt |= {k for k in defs}
            # (b) propagate param -> arg into callees
            for callnode in ast.walk(defs[fk]):
                if not isinstance(callnode, ast.Call):
                    continue
                g = _resolve_call(callnode, rel, cg, defs, mod2files)
                if not g:
                    continue
                gk = (g[0], g[1])
                for argnode, pname in _map_args_to_params(callnode, defs[gk], g[2]):
                    if _shallow_tainted(argnode, ft.tainted, _cli) and pname not in TP[gk]:
                        TP[gk].add(pname)
                        nxt.add(gk)
        worklist = nxt if _round < _MAX_ROUNDS - 1 else set()

    # S8.23 CLASS FIELD-CELL: FT[(rel,class)] = self.<attr> paths some method of the class taints. A field
    # read in ANOTHER method of the SAME class is then tainted (the receive()->act() agent-injection shape).
    # Sound bounds: same-class only, self/cls only, real-tainted RHS only (all enforced inside _FnTaint).
    fk2class, class2methods = _build_classes(root, graphs)
    FT = {ck: set() for ck in class2methods}
    for _ in range(_MAX_ROUNDS):
        grew = False
        for ck, methods in class2methods.items():
            for mk in methods:
                if mk not in defs:
                    continue
                cg = graphs.get(mk[0])
                hook = make_hook(mk[0], cg) if cg else None
                seed = _entrypoint_untrusted_of(mk, entrypoints) | TP.get(mk, set())
                fw = T._FnTaint(defs[mk], seed_params=seed, call_returns_taint=hook,
                                field_taint_seed=FT[ck], cli_main=(mk[0] in cli_main_rels)).field_writes()
                if not fw <= FT[ck]:
                    FT[ck] |= fw
                    grew = True
        if not grew:
            break

    # materialise (now seeding each method with its class field-cell)
    result: Dict[str, dict] = {}
    for fk in defs:
        rel, fn = fk
        cg = graphs.get(rel)
        if not cg or fn not in cg.funcs:
            continue
        hook = make_hook(rel, cg)
        seed = _entrypoint_untrusted_of(fk, entrypoints) | TP[fk]
        fseed = FT.get(fk2class.get(fk), set())
        ft = T._FnTaint(defs[fk], seed_params=seed, call_returns_taint=hook, field_taint_seed=fseed,
                        cli_main=(rel in cli_main_rels))
        for line, src in ft.tainted_sinks().items():
            result.setdefault(rel, {})[line] = src
        # S8.83: also test AI-asserted action lines inside this function's range as first-class sink targets.
        want = extra_targets.get(rel)
        if want:
            lo = defs[fk].lineno
            hi = getattr(defs[fk], "end_lineno", lo) or lo
            rel_res = result.setdefault(rel, {})
            for line in want:
                if lo <= line <= hi and line not in rel_res:
                    src = _ai_line_taint(ft, defs[fk], line)
                    if src:
                        rel_res[line] = f"ai-target: {src}"
    result["_limits"] = limits
    return result


def _UNTRUSTED_of(defnode) -> set:
    # Tier-B (candidate) name heuristic — kept ONLY for the candidate pass, no longer the grounded root source.
    return {p for p in _params(defnode) if p in T._UNTRUSTED_PARAMS}


def _entrypoint_untrusted_of(fk, entrypoints) -> set:
    """S8.42: the grounded root source — untrusted params ONLY if this (rel, fn) is a detected real entrypoint
    (HTTP route / event handler). Empty for every other function, killing the param-name over-mark."""
    info = entrypoints.get(fk)
    return set(info["untrusted_params"]) if info else set()


def apply(root, surfaces, graphs, mod2files) -> dict:
    """Upgrade tainted_reachable for cross-function-reachable sinks. Joins on the sink line (sink_line if the
    surface has it, else line_start). Upgrade-only; feeds guard_attribution's tainted axis untouched.

    S8.83: AI-tier surfaces (detection_source != 'static') contribute their action LINES as extra sink
    targets so they are reachability-tested by the SAME sound machinery (was: never tested -> a reachable
    AI surface could never be promoted). Empty when the AI tier is off -> compute() is byte-identical."""
    extra = {}
    for s in surfaces:
        if getattr(s, "detection_source", "static") == "static":
            continue
        if s.context != "prod" or getattr(s, "tainted_reachable", False):
            continue
        ln = getattr(s, "sink_line", 0) or s.line_start
        if ln:
            extra.setdefault(s.file_path, set()).add(ln)
    try:
        result = compute(Path(root), graphs, mod2files, extra_targets=extra)
    except Exception as e:
        return {"error": str(e)[:200]}
    upgraded = 0
    for s in surfaces:
        if s.context != "prod" or getattr(s, "tainted_reachable", False):
            continue
        rel_map = result.get(s.file_path, {})
        line = getattr(s, "sink_line", 0) or s.line_start
        # sink_line join if present; else accept any tainted sink within the surface's def range (line_start)
        hit = rel_map.get(line)
        if hit is None and not getattr(s, "sink_line", 0):
            hit = next((v for ln, v in rel_map.items() if s.line_start <= ln <= (s.line_end or s.line_start)), None)
        if hit:
            s.tainted_reachable = True
            s.taint_source = f"cross-function: {hit}"
            upgraded += 1
    return {"cross_function_upgraded": upgraded, "limits": result.get("_limits", {})}
