"""
Hermes Shield MVP — AST call-graph guard proof (P2.9B + P2.9C).

Proves whether a recognised, IDENTITY-RESOLVED guard runs BEFORE an action sink. AST-only (comments/
strings never count). Guard identity is resolved to a real source (import/local/gateway) so a method
that merely shares a name (ADV04) does not count. Conservative — anything uncertain is unproven.

Dominance (a guard "runs before" the sink) is established by:
  * a top-level guard call statement;               guard(); ... sink()
  * an early-return / raise guard;                  if not guard(): return  (then) sink()
Guards nested in a non-dominating branch, or after the sink, never count.

Proof types: same_function_before_sink | private_wrapper_guarded (one-hop, in-file).
Cross-module proof (cross_module_entry_guard_before_helper) is added by cross_module.py.
"""
from __future__ import annotations
import ast
from typing import Dict, List, Optional, Tuple

from . import module_index as MI


def _call_name(node: ast.Call) -> Tuple[Optional[str], bool]:
    """Return (name, is_method). Name calls -> (id, False); Attribute -> (attr, True) unless the
    value is a plain module Name (mod.func) -> ('mod.func', False-ish handled by caller)."""
    f = node.func
    if isinstance(f, ast.Name):
        return f.id, False
    if isinstance(f, ast.Attribute):
        if isinstance(f.value, ast.Name):
            return f"{f.value.id}.{f.attr}", False  # module.func or obj.attr (resolved by identity)
        return f.attr, True  # method on an expression/self -> method call
    return None, False


def _dotted(node: ast.Call) -> Optional[str]:
    f = node.func
    parts: List[str] = []
    cur = f
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts)) if parts else None


def _decorator_names(d):
    """S8.42: dotted names of a def's decorators (the func part if the decorator is a call, e.g.
    @app.post('/x') -> 'app.post'). Used by the entrypoint detector."""
    out = []
    for dec in getattr(d, "decorator_list", []):
        node = dec.func if isinstance(dec, ast.Call) else dec
        parts, cur = [], node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        if parts:
            out.append(".".join(reversed(parts)))
    return out


def _param_specs(d):
    """S8.42: (param_name, has_depends) for each positional/kw param. has_depends = the default is a
    Depends(...)/Security(...) call (FastAPI dependency-injection -> NOT an untrusted body param)."""
    a = d.args
    pos = list(getattr(a, "posonlyargs", [])) + list(a.args)
    # positional defaults align to the TAIL of pos; kwonly defaults are a separate list
    pos_defaults = {}
    dflts = list(a.defaults)
    if dflts:
        for arg, dv in zip(pos[-len(dflts):], dflts):
            pos_defaults[arg.arg] = dv
    kwd = {ka.arg: kd for ka, kd in zip(a.kwonlyargs, a.kw_defaults) if kd is not None}
    specs = []
    for arg in pos + list(a.kwonlyargs):
        default = pos_defaults.get(arg.arg) or kwd.get(arg.arg)
        # S8.50 FIX: pass the CALL to _dotted (it reads node.func) — the old _dotted(default.func) crashed
        # when default.func was an ast.Name (e.g. Depends(...)), taking down the scan on ~40% of real repos.
        has_dep = isinstance(default, ast.Call) and (_dotted(default) or "").split(".")[-1] in ("Depends", "Security")
        specs.append((arg.arg, bool(has_dep)))
    return specs


def _is_cli_command(d):
    """S8.84: True when this def is an OPERATOR CLI verb (Typer/Click) — developer-controlled, NOT a
    chatbot command handler. The `command` decorator tail is AMBIGUOUS: @bot.command (chatbot, untrusted)
    vs @app.command / @click.command (operator CLI, trusted). Two discriminating signals for the CLI form:
      (a) a click/typer decorator — click.command/group/option/argument or typer app .command, or a stacked
          @*.option / @*.argument (Click binds args as separate decorators);
      (b) a Typer param default — def cmd(name: str = typer.Argument(...) / typer.Option(...)).
    Used by the entrypoint detector to STOP seeding CLI verbs as untrusted (removes false reachables only —
    a genuine @bot.command has neither signal, so it stays untrusted). Sound-leaning: under-mark."""
    # (a) decorators
    for dec in getattr(d, "decorator_list", []):
        node = dec.func if isinstance(dec, ast.Call) else dec
        parts, cur = [], node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        if not parts:
            continue
        dotted = list(reversed(parts))
        base, tail = dotted[0], dotted[-1]
        if base in ("click", "typer") and tail in ("command", "group", "option", "argument", "password_option"):
            return True
        if tail in ("option", "argument"):   # stacked @click.option / @click.argument (any receiver) -> CLI
            return True
    # (b) Typer/Click param defaults: def cmd(name = typer.Argument(...))
    a = d.args
    for dv in list(a.defaults) + list(a.kw_defaults):
        if isinstance(dv, ast.Call):
            dn = _dotted(dv) or ""
            base, tail = (dn.split(".")[0], dn.split(".")[-1])
            if tail in ("Argument", "Option") and base in ("typer", "click"):
                return True
    return False


def _body_exits(body) -> bool:
    """True when a guarded branch UNCONDITIONALLY exits — return/raise only, or a single exit()/quit()/
    sys.exit()/os._exit() call. Pass/Continue/log-only bodies do NOT dominate a straight-line sink."""
    types = {type(s) for s in body}
    if types and types <= {ast.Return, ast.Raise}:
        return True
    if len(body) == 1 and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Call):
        f = body[0].value.func
        if isinstance(f, ast.Name) and f.id in ("exit", "quit"):
            return True
        if isinstance(f, ast.Attribute) and f.attr in ("exit", "_exit"):
            return True
    return False


def _has_main_guard(tree) -> bool:
    """S8.85: True when the module has a top-level `if __name__ == "__main__":` guard — i.e. it runs as a
    CLI child/script whose stdin/argv is operator/parent-supplied (trusted IPC), not an attacker channel."""
    for n in getattr(tree, "body", []):
        if not isinstance(n, ast.If):
            continue
        t = n.test
        if isinstance(t, ast.Compare) and isinstance(t.left, ast.Name) and t.left.id == "__name__":
            for c in t.comparators:
                if isinstance(c, ast.Constant) and c.value == "__main__":
                    return True
    return False


class FileGraph:
    def __init__(self, text: str):
        self.ok = True
        self.funcs: Dict[str, dict] = {}
        self.local_names: set = set()
        self.imports: Dict[str, dict] = {}
        try:
            tree = ast.parse(text)
        except Exception:
            self.ok = False
            return
        self.imports = MI.parse_imports(tree)
        # S8.85: is this module a CLI child/script? A top-level `if __name__ == "__main__":` guard means the
        # process reads its input from the operator/parent (argv/stdin = trusted IPC), not an attacker channel.
        # Used to stop `sys.stdin.read()` in such a script being seeded as an untrusted taint source (the julep
        # `_resolve_child.py` false-reachable: parent-written stdin, not attacker input).
        self.cli_main = _has_main_guard(tree)
        # P2.9D-REVIEW: line ranges of `finally` blocks — a sink there runs even if the guard raised,
        # so a preceding guard does NOT dominate it.
        self.finally_ranges = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Try) and n.finalbody:
                start = n.finalbody[0].lineno
                end = max(getattr(s, "end_lineno", s.lineno) for s in n.finalbody)
                self.finally_ranges.append((start, end))
        # fix C: per-line variable arguments of every call — the sink's tainted-variable correspondence set.
        # A guard credits a sink only if it is action-level (no variable arg) OR one of its argument variables
        # is a variable the sink consumes (see prove / guard_attribution). Top-level Name args only.
        self.call_arg_vars: Dict[int, set] = {}
        for c in ast.walk(tree):
            if isinstance(c, ast.Call):
                names = {a.id for a in list(c.args) + [k.value for k in c.keywords]
                         if isinstance(a, ast.Name)}
                if names:
                    self.call_arg_vars.setdefault(c.lineno, set()).update(names)
        # fix A/C: per-guard metadata keyed by the guard's credited line — its argument variables (for the
        # sink-correspondence check) and HOW its control value is consumed (bare_raise/if_test/assert/
        # assign_branch). A bare_raise credit is a raise-ASSUMPTION; guard_integrity re-checks the def.
        self._guard_meta: Dict[int, dict] = {}
        defs = [n for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        self.local_names = {d.name for d in defs}
        for d in defs:
            local_calls: List[tuple] = []
            all_calls: List[tuple] = []
            for c in ast.walk(d):
                if isinstance(c, ast.Call):
                    bare, is_method = _call_name(c)
                    if bare in self.local_names:
                        local_calls.append((c.lineno, bare))
                    all_calls.append((c.lineno, bare, _dotted(c), is_method))
            self.funcs[d.name] = {
                "start": d.lineno, "end": getattr(d, "end_lineno", d.lineno),
                "local_calls": sorted(local_calls), "all_calls": all_calls,
                "top_guards": sorted(self._dominating_guards(d)),  # [(line, kind, identity)]
                "private": d.name.startswith("_"),
                "decorators": _decorator_names(d),                 # S8.42: for entrypoint detection
                "params": _param_specs(d),                         # [(name, has_depends)]
                "cli_command": _is_cli_command(d),                 # S8.84: Typer/Click CLI verb (not a bot cmd)
            }

    def _resolve(self, call_node: ast.Call) -> dict:
        bare, is_method = _call_name(call_node)
        if bare is None:
            return {"strong": False, "identity": MI.REJECTED_COLLISION, "kind": None}
        return MI.resolve_guard_identity(bare, is_method, self.imports, self.local_names)

    def _record_guard(self, line: int, call: ast.Call, consumed: str) -> None:
        """fix A/C: record a credited guard's argument variables + consumption mode, keyed by the line the
        top_guards tuple carries (so prove/guard_attribution can look it up)."""
        names = {a.id for a in list(call.args) + [k.value for k in call.keywords]
                 if isinstance(a, ast.Name)}
        self._guard_meta[line] = {"arg_vars": frozenset(names), "consumed": consumed}

    def _is_side_effect_gate(self, call: ast.Call) -> bool:
        """fix A: a BARE guard call credits ONLY if the guard is a raise-style (side-effect) gate — it aborts
        on failure, so the control value is consumed by the abort. Resolves import aliases to the ORIGINAL
        symbol so `... import assert_live_action_allowed as _ks` is still recognised as raise-style."""
        bare, _ = _call_name(call)
        if bare is None:
            return False
        orig = bare
        imp = self.imports.get(bare)
        if imp and imp.get("orig"):
            orig = imp["orig"]
        elif "." in bare:
            orig = bare.split(".")[-1]
        return MI.guard_symbol_raises(orig)

    def _guards_from_stmts(self, stmts, source: str) -> List[tuple]:
        """Dominating guards among a list of top-level statements. Returns (line, kind, identity, source).

        fix A (ignored-return no-op): a guard credits ONLY when its control value is CONSUMED — a raise-style
        BARE call (aborts on failure), an `assert guard(...)`, an early-exit `if <guard-test>: return/raise/
        exit`, or an `x = guard(); if not x: return`. A bare RETURN-based call whose boolean is DISCARDED
        (`live_actions_blocked()` / `allow_action()` on its own line) is a no-op and is NOT credited."""
        out: List[tuple] = []
        for idx, stmt in enumerate(stmts):
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                r = self._resolve(stmt.value)
                if r["strong"] and self._is_side_effect_gate(stmt.value):
                    self._record_guard(stmt.lineno, stmt.value, "bare_raise")
                    out.append((stmt.lineno, r["kind"], r["identity"], source))
            elif isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
                r = self._resolve(stmt.value)
                # credit ONLY when the assigned decision is consumed by a following dominating early-exit
                # branch (`flag = guard(); if not flag: return`). A bare unused assignment is a no-op.
                # HOLE 1 FIX (Fable-5 re-run): the credited guard LINE is the CONSUMING EXIT BRANCH's line,
                # NOT the assign line. The assign itself gates nothing — the `if not flag: return/raise/exit`
                # is what aborts — so the guard only "runs before" a sink that comes AFTER that branch. Using
                # the assign line let prove() credit a consuming branch that lies AFTER the sink (the sink
                # ran unconditionally, then a late `if not ok: raise` gave bogus credit). prove() filters on
                # guard_line < sink_line, so pinning the credit to the branch line makes a post-sink branch
                # (branch_line > sink_line) correctly fail to dominate.
                if r["strong"]:
                    gl = self._assign_consumed_exit(stmt, stmts[idx + 1:])
                    if gl is not None:
                        self._record_guard(gl, stmt.value, "assign_branch")
                        out.append((gl, r["kind"], r["identity"], source))
            elif isinstance(stmt, ast.Assert):
                # `assert guard(...)` — the boolean is consumed (AssertionError on false) -> dominating.
                # HOLE 2 FIX (Fable-5 re-run): the recognised guard must be UNCONDITIONALLY evaluated. Mirror
                # the if-branch reasoning — reject a short-circuiting / tautological test where a truthy
                # operand can skip past the guard: `assert cmd or allow_action(cmd)` (guard never runs when
                # cmd is truthy) and `assert allow_action(cmd) or True` (tautology) each carry exactly one
                # call yet the guard is not guaranteed to run. Only credit when the SOLE call in the test is
                # the top-level operand (no ast.BoolOp / ast.IfExp anywhere in the test to short-circuit it).
                short_circuit = any(isinstance(n, (ast.BoolOp, ast.IfExp)) for n in ast.walk(stmt.test))
                calls = [c for c in ast.walk(stmt.test) if isinstance(c, ast.Call)]
                if len(calls) == 1 and not short_circuit:
                    r = self._resolve(calls[0])
                    if r["strong"]:
                        self._record_guard(stmt.lineno, calls[0], "assert")
                        out.append((stmt.lineno, r["kind"], r["identity"], source + "_assert"))
            elif isinstance(stmt, ast.If):
                # early-exit guard: `if <guard-test>: return/raise/exit`. SOUND only if (a) the guarded
                # branch UNCONDITIONALLY EXITS — return/raise/exit ONLY (Pass does not exit; Continue only
                # skips a loop iteration and does not dominate a straight-line sink) — and (b) the guard
                # call SOLELY determines the branch: exactly one call in the test, so a compound
                # `if not guard() and other(): return` cannot short-circuit past the guard to the sink.
                # (CTO-REVIEW P2.9G soundness fix.) Residual: we cannot resolve the guard's return
                # POLARITY statically (`if is_blocked(): return` vs `if allows(): return`) — that needs
                # guard-integrity analysis (Stage 1.5); documented limitation.
                if _body_exits(stmt.body):
                    calls = [c for c in ast.walk(stmt.test) if isinstance(c, ast.Call)]
                    if len(calls) == 1:
                        r = self._resolve(calls[0])
                        if r["strong"]:
                            gl = getattr(stmt, "end_lineno", stmt.lineno)
                            self._record_guard(gl, calls[0], "if_test")
                            out.append((gl, r["kind"], r["identity"], source + "_early_return"))
        return out

    def _assign_consumed_exit(self, assign: ast.Assign, following) -> Optional[int]:
        """fix A + HOLE 1: return the LINE of the earliest following dominating early-exit branch that
        CONSUMES an assigned guard result (`flag = guard(); ...; if not flag: return/raise/exit`), or None
        when the assigned value is never consumed. The RETURNED line is the guard's credited dominance line —
        the sink is only protected if it comes AFTER this branch (prove() filters guard_line < sink_line), so
        a consuming branch that lies AFTER the sink cannot credit it. A bare, never-branched assignment is a
        no-op (None)."""
        targets = {n.id for tg in assign.targets for n in ast.walk(tg) if isinstance(n, ast.Name)}
        if not targets:
            return None
        for s in following:
            if isinstance(s, ast.If) and _body_exits(s.body):
                used = {n.id for n in ast.walk(s.test) if isinstance(n, ast.Name)}
                if used & targets:
                    return s.lineno
        return None

    def _guard_corresponds(self, guard_line: int, sink_vars: set) -> bool:
        """fix C (wrong-variable guard): a guard downgrades a sink only if it plausibly inspects the sink's
        tainted variable — either it is an ACTION-LEVEL gate (no variable argument: kill-switch / approval /
        constant-descriptor) OR one of its argument variables is a variable the sink consumes. A guard that
        inspects only a DIFFERENT variable (`allow_action(user_id)` guarding `eval(text)`) does not gate the
        tainted data flow and must NOT be credited."""
        meta = self._guard_meta.get(guard_line)
        if not meta:
            return True
        gvars = meta.get("arg_vars") or frozenset()
        if not gvars:
            return True                       # action-level gate (no data-variable argument)
        return bool(gvars & set(sink_vars))

    @staticmethod
    def _all_handlers_reraise(trynode) -> bool:
        """Sound only if EVERY except handler UNCONDITIONALLY exits (last statement is raise/return).
        A conditional raise (`if bad: raise` then fall-through) or a log-only handler can reach the
        sink unguarded and must NOT count (P2.9D-REVIEW fix). Also reject bare/finally-less swallow."""
        if not trynode.handlers:
            return False
        # a `finally` that contains the sink is out of scope; if there is an orelse, be conservative
        for h in trynode.handlers:
            body = [s for s in h.body if not isinstance(s, ast.Pass)]
            if not body:
                return False  # empty/pass handler swallows
            last = body[-1]
            if not isinstance(last, (ast.Raise, ast.Return)):
                return False  # falls through (log-only, conditional raise, etc.)
        return True

    def _dominating_guards(self, fnode) -> List[tuple]:
        return self._collect_dominating(getattr(fnode, "body", []), "body", 0)

    def _collect_dominating(self, stmts, source: str, depth: int) -> List[tuple]:
        """Guards that dominate straight-line sinks in `stmts`. P2.9D + S6.1: descend RECURSIVELY into
        NESTED try blocks whose handlers all unconditionally exit — a guard two `try` levels deep (as in
        x_reply_autosend.try_autosend) still dominates code after the try. Bounded depth; sound (only
        descends when the handler cannot fall through to the sink)."""
        out: List[tuple] = list(self._guards_from_stmts(stmts, source))
        if depth >= 5:
            return out
        for stmt in stmts:
            if isinstance(stmt, ast.Try) and self._all_handlers_reraise(stmt):
                out.extend(self._collect_dominating(stmt.body, "try_block", depth + 1))
        return out

    def enclosing(self, line: int) -> Optional[str]:
        best, best_start = None, -1
        for name, f in self.funcs.items():
            if f["start"] <= line <= f["end"] and f["start"] > best_start:
                best, best_start = name, f["start"]
        return best

    def prove(self, sink_line: int) -> dict:
        if not self.ok:
            return _unproven("parse_failed", ["file did not parse; static evidence only"])
        fn = self.enclosing(sink_line)
        if not fn:
            return _unproven("no_enclosing_function", ["sink at module scope; no function to trace"])
        if any(a <= sink_line <= b for a, b in self.finally_ranges):
            return _unproven("sink_in_finally",
                             ["sink is inside a finally block; it runs even if the guard raised"])
        f = self.funcs[fn]
        # fix C: a guard credits this sink only if it corresponds to the sink's tainted variable (or is an
        # action-level gate). A wrong-variable guard (`allow_action(user_id)` before `eval(text)`) is ignored.
        sink_vars = self.call_arg_vars.get(sink_line, set())
        before = [g for g in f["top_guards"]
                  if g[0] < sink_line and self._guard_corresponds(g[0], sink_vars)]
        if before:
            g = before[-1]
            src = g[3] if len(g) > 3 else "body"
            if src.startswith("try_block"):
                ptype = "try_block_early_return_guard" if src.endswith("_early_return") else "try_block_guard_before_sink"
            elif src.endswith("_early_return"):
                ptype = "early_return_guard"
            else:
                ptype = "same_function_before_sink"
            from . import module_index as _MI
            # fix B input: whether the credited guard's control value is genuinely CONSUMED at this site.
            # A bare_raise credit is a raise-ASSUMPTION — guard_integrity re-checks the def and, if it is
            # return-based (the assumption was wrong), re-escalates the discarded-return no-op to BLOCK.
            _meta = self._guard_meta.get(g[0], {})
            return {"status": "proven", "proof_type": ptype,
                    "guard_kind": g[1], "guard_identity": g[2],
                    "configured_guard_id": _MI.configured_guard_id(None) or g[1],
                    "guard_identity_source": "configured", "guard_line": g[0], "sink_line": sink_line,
                    "guard_return_consumed": _meta.get("consumed") != "bare_raise",
                    "enclosing_symbol": fn, "scope": "intraprocedural", "modules_involved": [],
                    "limitations": []}
        callers = self._callers_of(fn)
        if callers:
            if not f["private"]:
                return _unproven("caller_guarded_not_proven",
                                 [f"{fn} is public/exposed; external callers cannot be proven guarded"], fn)
            all_guarded, proof_callers = True, []
            for caller, call_line in callers:
                cf = self.funcs[caller]
                if any(g[0] < call_line for g in cf["top_guards"]):
                    proof_callers.append(caller)
                else:
                    all_guarded = False
                    break
            if all_guarded and proof_callers:
                # fix D: this proof rests on IN-FILE callers ONLY. It is NOT whole-program: a cross-file
                # caller may reach the sink unguarded. Mark it so guard_attribution never lets this in-file
                # proof override its own cross-file traversal — if that traversal finds any reachable
                # unguarded path (state 'partial'/'no'), the sink stays RED, not downgraded to protected.
                return {"status": "proven", "proof_type": "private_wrapper_guarded",
                        "guard_kind": "caller", "guard_identity": MI.RESOLVED_IMPORT,
                        "enclosing_symbol": fn, "proof_callers": proof_callers, "sink_line": sink_line,
                        "in_file_only": True,
                        "scope": "intraprocedural", "modules_involved": [], "limitations": []}
            return _unproven("caller_guarded_not_proven",
                             [f"{fn} has at least one unguarded in-file caller"], fn)
        file_has_guard = any(f2["top_guards"] for f2 in self.funcs.values())
        if file_has_guard:
            return _unproven("guard_elsewhere_in_file",
                             ["a guard exists in the file but not proven before this sink"], fn)
        return _unproven("no_guard_found", ["no recognised guard call reaches this sink"], fn)

    def _callers_of(self, name: str) -> List[tuple]:
        out = []
        for cname, f in self.funcs.items():
            if cname == name:
                continue
            for (line, callee) in f["local_calls"]:
                if callee == name:
                    out.append((cname, line))
        return out


def _unproven(reason: str, limitations: List[str], symbol: str = "") -> dict:
    status = "caller_guarded_not_proven" if reason == "caller_guarded_not_proven" else "unproven"
    return {"status": status, "proof_type": reason, "enclosing_symbol": symbol, "guard_kind": None,
            "guard_identity": None, "sink_line": 0, "scope": "intraprocedural",
            "modules_involved": [], "limitations": limitations}
