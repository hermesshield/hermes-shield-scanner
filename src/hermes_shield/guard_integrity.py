"""
Hermes Shield — guard-integrity v0.2 (Stage 1.5). REBUILT after an adversarial audit demolished v0.

The hard truth (skeptic + Rice's theorem): whether a control actually BLOCKS a disallowed action is
statically UNDECIDABLE. Polarity (`if allowed(): raise` vs `if blocked(): raise`), reachability (dead
code), and consumption (is a returned verdict acted on?) cannot be resolved. So v0's confident
"GUARD_HAS_BLOCK_PATH" was FALSE COMFORT — it proved "contains a control-flow keyword", not "can block".

v0.2 makes two honest moves:
  1. It only makes a HIGH-CONFIDENCE claim in ONE direction — that a guard is a NO-OP / FAIL-OPEN
     (GUARD_NOOP_CONFIRMED / GUARD_FAIL_OPEN_SUSPECT). Those are the reliable catches; they downgrade
     the surface to GUARD_INTEGRITY_SUSPECT (BLOCK).
  2. For everything that merely LOOKS like a gate, it says exactly that and no more:
     GUARD_BLOCK_SHAPED_UNVERIFIED — "a block-shaped construct is present, but polarity / reachability
     / consumption are NOT verified; a human must review this gate." It does NOT certify, does NOT
     claim the gate works, and does NOT flip the surface to a clean pass. GUARD_DEF_UNRESOLVED is
     treated the same (review-required), never a silent pass.

STATIC + READ-ONLY: locates guard DEFINITIONS and AST-analyses them; never imports/executes; skips the
scanner's own corpus/tests so a fixture no-op can never mask a real guard.
"""
from __future__ import annotations
import ast
import functools
from pathlib import Path
from typing import Optional

from . import patterns as PAT

# ONLY the actual BLOCKING / CHECK functions — never recorders, hashers, or constructors. Rating a
# recorder (record_approved) or a content-wrapper (make_untrusted_content) as a 'no-op gate' is a
# category error: they were never gates. (v0.2 fix — a recorder was poisoning a whole guard type.)
_GUARD_SYMBOLS = {
    "kill_switch": ["assert_live_action_allowed", "check_live_action_allowed", "live_actions_blocked"],
    "final_action_gate": ["allow_action", "require_final_action_approval"],
    "approval_hash_gate": ["get_approved"],          # the CHECK; record_approved/hash_file are not gates
    "csrf_token": ["is_dashboard_post_allowed"],
    "untrusted_fence": ["screen_source"],            # the screen/check; not the make_/wrap_ constructors
}
_SKIP_GUARD_DIRS = {"corpus", "tests", "test_outputs"}  # never resolve a guard def to a fixture/decoy


def _reachable_exits(stmts):
    """Return the Raise/Return nodes reachable within a straight-line block — statements AFTER a
    terminator in the same block are dead and excluded (kills the dead-code-raise bypass)."""
    exits = []
    for s in stmts:
        if isinstance(s, (ast.Return, ast.Raise)):
            exits.append(s)
            break  # rest of THIS block is unreachable
        if isinstance(s, ast.If):
            exits += _reachable_exits(s.body) + _reachable_exits(s.orelse)
        elif isinstance(s, (ast.For, ast.While, ast.With, ast.AsyncWith)):
            exits += _reachable_exits(s.body)
        elif isinstance(s, ast.Try):
            exits += _reachable_exits(s.body) + _reachable_exits(s.orelse) + _reachable_exits(s.finalbody)
            for h in s.handlers:
                exits += _reachable_exits(h.body)
    return exits


def _is_broad_except(h: ast.ExceptHandler) -> bool:
    if h.type is None:
        return True
    return isinstance(h.type, ast.Name) and h.type.id in ("Exception", "BaseException")


def _analyse_fn(fn) -> dict:
    reach = _reachable_exits(fn.body)
    rraises = [e for e in reach if isinstance(e, ast.Raise)]
    rreturns = [e for e in reach if isinstance(e, ast.Return)]
    has_assert = any(isinstance(n, ast.Assert) for n in ast.walk(fn))
    has_exit_call = any(
        isinstance(n, ast.Call) and (
            (isinstance(n.func, ast.Attribute) and n.func.attr in ("exit", "_exit"))
            or (isinstance(n.func, ast.Name) and n.func.id in ("exit", "quit")))
        for n in ast.walk(fn))
    const_returns = {ast.dump(r.value) for r in rreturns if isinstance(getattr(r, "value", None), ast.Constant)}
    # a return that COMPUTES a value (Name/Call/Compare/BoolOp/...) makes the output depend on input —
    # NOT a confirmed no-op (`return get_approved(x)` / `return is_ok` is a real return-based check).
    computed_returns = [r for r in rreturns
                        if getattr(r, "value", None) is not None and not isinstance(r.value, ast.Constant)]
    real_block = bool(rraises) or has_assert or has_exit_call
    decision_returns = len(const_returns) > 1 or bool(computed_returns)
    # delegation: the (only) reachable return returns a Call — the real block lives one level deeper
    delegates = (not real_block and len(rreturns) == 1
                 and isinstance(getattr(rreturns[0], "value", None), ast.Call))
    # confirmed no-op ONLY when the output is INVARIANT: pass, or all returns the SAME constant / None,
    # nothing computed, no raise/assert/exit. Output cannot depend on the action -> cannot block.
    is_noop = (not real_block) and (not computed_returns) and (len(const_returns) <= 1)
    # fail-open: a try whose body RAISES but a BROAD handler swallows it (pass-only OR returns a value)
    swallow_risk = any(
        any(isinstance(x, ast.Raise) for s in n.body for x in ast.walk(s))
        and any(_is_broad_except(h) and (
            [s for s in h.body if not isinstance(s, ast.Pass)] == []
            or any(isinstance(s, ast.Return) for s in h.body))
                for h in n.handlers)
        for n in ast.walk(fn) if isinstance(n, ast.Try))
    reads_mutable = any(
        (isinstance(n, ast.Attribute) and n.attr in ("environ", "getenv"))
        or (isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "open")
        for n in ast.walk(fn))
    return {"real_block": real_block, "decision_returns": decision_returns, "delegates": delegates,
            "is_noop": is_noop, "swallow_risk": swallow_risk, "reads_mutable_input": reads_mutable}


def _verdict(a: dict) -> tuple:
    flags = []
    if a["reads_mutable_input"]:
        flags.append("CONTROL_INPUT_MUTABLE")
    if a["delegates"]:
        flags.append("DELEGATES_TO_CALLEE")
    if a["decision_returns"] and not a["real_block"]:
        flags.append("RETURN_BASED_MAY_BE_IGNORED")
    if a["swallow_risk"]:
        return "GUARD_FAIL_OPEN_SUSPECT", flags + ["SWALLOW_RISK"]     # high-confidence: swallows a raise
    if a["is_noop"]:
        return "GUARD_NOOP_CONFIRMED", flags                          # high-confidence: cannot block
    # everything else merely LOOKS like a gate — we do NOT verify it works
    return "GUARD_BLOCK_SHAPED_UNVERIFIED", flags


# verdicts that mean "this control is DEMONSTRABLY not protecting" -> downgrade + BLOCK
_SUSPECT = {"GUARD_NOOP_CONFIRMED", "GUARD_FAIL_OPEN_SUSPECT"}
# verdicts that mean "we cannot verify — a human must review" -> keep verdict, require review
_REVIEW = {"GUARD_BLOCK_SHAPED_UNVERIFIED", "GUARD_DEF_UNRESOLVED"}


def _find_def(root: Path, symbol: str):
    for p in root.rglob("*.py"):
        parts = set(p.parts)
        if parts & PAT.SKIP_DIRS or parts & _SKIP_GUARD_DIRS or "worktrees" in parts:
            continue
        try:
            if p.stat().st_size > 400_000:
                continue
            src = p.read_text(encoding="utf-8", errors="ignore")
            if f"def {symbol}" not in src:
                continue
            tree = ast.parse(src)
        except Exception:
            continue
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == symbol:
                return n, str(p.relative_to(root))
    return None


@functools.lru_cache(maxsize=8)
def build(root_str: str) -> dict:
    root = Path(root_str)
    out = {}
    for gtype, symbols in _GUARD_SYMBOLS.items():
        cands = []
        for sym in symbols:
            found = _find_def(root, sym)
            if found:
                fn, rel = found
                verdict, flags = _verdict(_analyse_fn(fn))
                cands.append({"verdict": verdict, "flags": flags, "symbol": sym, "file": rel})
        if not cands:
            out[gtype] = {"verdict": "GUARD_DEF_UNRESOLVED", "flags": [],
                          "symbol": symbols[0] if symbols else "", "file": None}
            continue
        # SAFETY: if ANY resolved definition of this guard type is a confirmed no-op / fail-open,
        # surface the WORST verdict — never let a raising decoy mask a real no-op (or vice-versa).
        rank = {"GUARD_FAIL_OPEN_SUSPECT": 0, "GUARD_NOOP_CONFIRMED": 1,
                "GUARD_BLOCK_SHAPED_UNVERIFIED": 2, "GUARD_DEF_UNRESOLVED": 3}
        out[gtype] = min(cands, key=lambda c: rank.get(c["verdict"], 9))
    return out


def annotate(root: Path, surfaces) -> dict:
    """Attach guard-integrity to every PROVEN surface. High-confidence no-op/fail-open -> downgrade to
    GUARD_INTEGRITY_SUSPECT (BLOCK). Block-shaped/unresolved -> KEEP the verdict but require manual
    review (never certified). Advisory: never turns unproven into proven."""
    integ = build(str(root))
    counts = {"block_shaped_unverified": 0, "suspect": 0, "unresolved": 0}
    for s in surfaces:
        if s.guard_proof.get("status") != "proven":
            continue
        kind = s.guard_proof.get("guard_kind")
        gi = integ.get(kind) if kind else None
        if not gi:
            gi = integ.get("kill_switch")
        if not gi:
            continue
        s.guard_proof["guard_integrity"] = {"verdict": gi["verdict"], "flags": gi["flags"],
                                            "guard_symbol": gi.get("symbol"), "guard_file": gi.get("file")}
        if gi["verdict"] in _SUSPECT:
            s.guard_proof["integrity_warning"] = ("control is a DEMONSTRABLE no-op / fail-open — "
                                                  "the action is effectively unguarded")
            s.verdict = "GUARD_INTEGRITY_SUSPECT"
            s.live_promotion_verdict = "BLOCK"
            counts["suspect"] += 1
        else:
            # BLOCK_SHAPED_UNVERIFIED or DEF_UNRESOLVED: honest — we cannot verify the gate works.
            s.guard_proof["integrity_review_required"] = True
            s.guard_proof["integrity_warning"] = (
                "control is present but polarity / reachability / semantics are NOT statically verified "
                "— a human must confirm this gate actually blocks (guard def unresolved)"
                if gi["verdict"] == "GUARD_DEF_UNRESOLVED" else
                "control is block-shaped but polarity / reachability / consumption are NOT statically "
                "verified — a human must confirm this gate actually blocks")
            if s.live_promotion_verdict == "ALLOW":
                s.live_promotion_verdict = "REVIEW"
            counts["unresolved" if gi["verdict"] == "GUARD_DEF_UNRESOLVED" else "block_shaped_unverified"] += 1
        for f in gi["flags"]:
            s.guard_proof.setdefault("integrity_flags", []).append(f)
    return counts
