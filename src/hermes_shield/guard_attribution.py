"""
Hermes Shield MVP — generalised guard-attribution (S6.1).

Fixes the severity INVERSION the S5.0 red-team found: the scanner rated an UNGUARDED live-post path
(x_feed_scout) as LESS severe than a GUARDED one (x_reply_autosend), because the old severity keyed on
caller TOPOLOGY (where the caller lives) rather than on whether a CRITICAL guard actually dominates the
sink. This post-pass runs on EVERY prod critical-capability surface (not just config-modelled helpers)
and asks one deterministic question: does a CRITICAL guard (kill-switch / final-action-gate / approval)
dominate the sink on EVERY resolvable path from an entry?

DESIGN INVARIANTS (cyber-lead spec):
  * DOWNGRADE-ONLY — a proven critical guard can move a surface DOWN the severity ladder; the absence of
    a guard never moves anything down. So the DEFAULT for an unproven path is the HIGHER severity.
  * NEVER OVER-CREDIT — unknown / unresolved / dynamic dispatch = "no critical guard proven" = the worse
    rank. Over-crediting (calling an unguarded path guarded) is the catastrophic failure; under-crediting
    is merely annoying. Sound, not complete.
  * PRESENCE + DOMINANCE only — this proves a critical guard is CALLED before the sink on every path. It
    does NOT prove the guard fails-closed (polarity) — that is guard_integrity (Stage 1.5). So "yes"
    yields REVIEW, never ALLOW on its own.

Static, read-only. Reuses call_graph dominance + module_index guard identity/criticality; adds only the
traversal + aggregation + a single new verdict (UNGUARDED_CRITICAL_LIVE_SINK).
"""
from __future__ import annotations
from pathlib import Path
from typing import Dict, Optional

from . import patterns as PAT
from . import module_index as MI
from .call_graph import FileGraph

_MAX_DEPTH = 4

# verdicts the scanner ENFORCES as block-live-promotion. UNGUARDED_CRITICAL_LIVE_SINK joins the set so
# the rank-0 floor actually gates (adversarial-marker blocker: the signal enforced nothing before).
_ENFORCED_BLOCK = {"BLOCK_LIVE_PROMOTION", "GUARD_LOST", "UNGUARDED_CRITICAL_LIVE_SINK"}

# THE QUADRANT (cyber-lead severity model): severity = tainted_reachable  ×  critical_guard_on_path.
# The dangerous quadrant is tainted=True AND guard=no. Ordering (0 = most severe):
#   CRITICAL (T, no) > (T, partial) > (T, unknown) > REVIEW (T, yes)
#     > MEDIUM (F, no) > (F, partial) > (F, unknown) > LOW (F, yes)
# so a proven-reachable unguarded sink outranks EVERYTHING, and a tainted-but-contained sink (REVIEW)
# still outranks an unguarded-but-not-proven-reachable one (MEDIUM). verdict=None -> keep classifier's.
_QUADRANT = {
    (True,  "no"):      (0, "UNGUARDED_CRITICAL_LIVE_SINK", "BLOCK"),
    (True,  "partial"): (1, "UNGUARDED_CRITICAL_LIVE_SINK", "BLOCK"),   # an unguarded path to a tainted sink IS exploitable -> enforce
    (True,  "unknown"): (2, "NEEDS_CALL_GRAPH",             "REVIEW"),
    (True,  "yes"):     (3, None,                           "REVIEW"),
    (False, "no"):      (4, "EXPECTED_GUARD_MISSING",       "BLOCK"),
    (False, "partial"): (5, "CALLER_GUARDED_NOT_PROVEN",    "REVIEW"),
    (False, "unknown"): (6, "NEEDS_CALL_GRAPH",             "REVIEW"),
    (False, "yes"):     (7, None,                           "REVIEW"),
}


# A critical guard is credited ONLY on a RESOLVED-to-source identity — never a LOCAL_DEFINITION, so a
# local no-op `def assert_action_allowed(): return True` decoy cannot downgrade a sink (code-review MED-1).
_CRITICAL_IDENTITY = {MI.RESOLVED_IMPORT, MI.CERTIFIED_GATEWAY, MI.CONFIGURED_GUARD}


def _critical_before(fg: FileGraph, fn: str, upto_line: int, cap: str):
    """The dominating CRITICAL guard for `cap` before `upto_line` in `fn`, or None. Reuses the sound
    dominance in FileGraph.top_guards; credits only a resolved-import/gateway critical guard identity."""
    f = fg.funcs.get(fn)
    if not f:
        return None
    for g in f["top_guards"]:
        identity = g[2] if len(g) > 2 else None
        if g[0] < upto_line and MI.guard_class(g[1], cap) == "critical" and identity in _CRITICAL_IDENTITY:
            return g
    return None


def _in_file_callers(fg: FileGraph, fn: str):
    out = []
    for cname, f in fg.funcs.items():
        if cname == fn:
            continue
        for (line, callee) in f["local_calls"]:
            if callee == fn:
                out.append((cname, line))
    return out


def _cross_file_callers(fn: str, home_path: str, mod2files: dict, graphs: Dict[str, FileGraph]):
    """Cross-file callers whose import of `fn` resolves to the sink's ACTUAL home FILE. Uses the SAME
    unique-file resolver as cross_module (resolve_import_to_file) so there is ONE resolution code path —
    no more twin-bug drift (marker rounds 4-6). A wrong-file / ambiguous same-name import never counts."""
    from .cross_module import resolve_import_to_file
    out = []
    for caller_path, fg in graphs.items():
        if not fg.ok:
            continue
        imp = fg.imports.get(fn)
        if not imp or imp.get("orig") not in (fn, None):
            continue
        if resolve_import_to_file(imp, caller_path, mod2files) != home_path:
            continue
        for cname, f in fg.funcs.items():
            for call in f["all_calls"]:
                if call[1] == fn:
                    out.append((fg, cname, call[0]))
    return out


def _mod_tail(file_path: str) -> str:
    return Path(file_path).stem


def attribute(surface, graphs: Dict[str, FileGraph], mod2files: dict = None) -> dict:
    """Compute critical_guard_on_path for one surface. Returns the guard_attribution dict."""
    if mod2files is None:
        from .cross_module import build_mod2files
        mod2files = build_mod2files(graphs)
    cap = surface.capability
    guards_found: list = []
    unguarded: list = []
    limits: list = []
    scope = {"cross": False}
    seen: set = set()

    fg = graphs.get(surface.file_path)
    if not fg or not fg.ok:
        return {"critical_guard_on_path": "unknown", "guards_found": [], "unguarded_paths": [],
                "resolution_limits": ["no_graph_for_file"], "path_scope": "intraprocedural"}
    sink_fn = fg.enclosing(surface.line_start)
    if not sink_fn:
        return {"critical_guard_on_path": "unknown", "guards_found": [], "unguarded_paths": [],
                "resolution_limits": ["sink_at_module_scope"], "path_scope": "intraprocedural"}

    def visit(cur_fg: FileGraph, fn: str, upto_line: int, depth: int) -> str:
        key = (id(cur_fg), fn)
        if key in seen:
            return "unknown"
        seen.add(key)
        if depth > _MAX_DEPTH:
            # NEVER OVER-CREDIT: giving up (chain deeper than the cap) must yield the WORSE outcome, not a
            # softer REVIEW that escapes enforcement. A merely-deep unguarded chain stays severe.
            limits.append(f"depth_exceeded@{fn}")
            return "no"
        g = _critical_before(cur_fg, fn, upto_line, cap)
        if g:
            guards_found.append({"guard_type": g[1], "identity": g[2], "guard_line": g[0], "at": fn})
            return "yes"
        # no critical guard in this function -> it must be guarded by EVERY caller path
        callers = [(cur_fg, c, l) for c, l in _in_file_callers(cur_fg, fn)]
        cross = _cross_file_callers(fn, _path_of(cur_fg, graphs), mod2files, graphs)
        if cross:
            scope["cross"] = True
            callers += [(cfg, cn, cl) for cfg, cn, cl in cross]
        if not callers:
            unguarded.append({"entry": fn, "call_line": upto_line, "reason": "no_critical_guard_no_caller"})
            return "no"
        legs = [visit(cfg, cn, cl, depth + 1) for cfg, cn, cl in callers]
        if legs and all(x == "yes" for x in legs):
            return "yes"
        if any(x == "no" for x in legs):
            if fn not in [u["entry"] for u in unguarded]:
                unguarded.append({"entry": fn, "call_line": upto_line, "reason": "unguarded_caller_path"})
            return "partial" if any(x == "yes" for x in legs) else "no"
        return "unknown"

    result = visit(fg, sink_fn, surface.line_start, 0)
    return {"critical_guard_on_path": result, "guards_found": guards_found,
            "unguarded_paths": unguarded, "resolution_limits": limits,
            "path_scope": "interprocedural_visible" if scope["cross"] else "intraprocedural"}


def _path_of(fg: FileGraph, graphs: Dict[str, FileGraph]) -> str:
    for p, g in graphs.items():
        if g is fg:
            return p
    return ""


def apply(root: Path, surfaces, graphs: Optional[Dict[str, FileGraph]] = None, progress=None) -> dict:
    """Post-pass: attribute critical-guard coverage to every prod critical-cap surface and set a
    deterministic severity_rank + verdict. DOWNGRADE-ONLY: never moves a surface to ALLOW; only marks
    the unguarded/partial/unknown cases more severe and records the proof object. Returns counts.

    `progress` (optional) is a callback fired periodically with (traced, total) so a caller can stream a
    live reachability counter. None => byte-identical; it only reports the pass, never changes it."""
    if graphs is None:
        from .cross_module import build_graphs, _all_py_rel
        graphs = build_graphs(root, _all_py_rel(root))
    from .cross_module import build_mod2files
    mod2files = build_mod2files(graphs)
    counts = {"unguarded_critical": 0, "guarded_review": 0, "partial": 0, "unknown": 0,
              "unguarded_unproven_reach": 0, "attributed": 0}
    _total = len(surfaces)
    for _i, s in enumerate(surfaces):
        if progress and _i % 40 == 0:
            progress({"phase": "reach", "step": "guards", "traced": _i, "total": _total})
        if s.context != "prod" or s.capability not in PAT.CRITICAL_CAPS:
            continue
        attr = attribute(s, graphs, mod2files)
        s.guard_attribution = attr
        state = attr["critical_guard_on_path"]
        # taint axis: True = PROVEN reachable from untrusted input (taint is intra-function, incomplete,
        # so False = NOT-PROVEN-reachable, not "safe" — an unguarded (F,no) sink is still flagged, just
        # below a proven-reachable one). Honest, avoids ranking everything CRITICAL.
        tainted = bool(getattr(s, "tainted_reachable", False))
        # AI-SUSPECTED SURFACES ARE ADVISORY — NEVER a deterministic verdict (the honesty invariant).
        # A model GUESS (detection_source in {ai_suspected, ai_corroborated}, verdict AI_SUSPECTED_REVIEW)
        # must not run through the deterministic verdict machinery that writes UNGUARDED_CRITICAL_LIVE_SINK
        # into the shared .verdict field — that single guess would flip a clean repo's RED/AMBER banner,
        # inflate the reachable count + coverage, and feed the fix-plan. We STILL compute + PRESERVE the
        # "AI suggests, engine checks reachability" signal, but record it in the SEPARATE advisory field
        # s.ai_reachability and leave .verdict == "AI_SUSPECTED_REVIEW". The surface still appears in the
        # dedicated "AI-suspected — needs review" report section; it is only kept out of the deterministic
        # headline/banner/coverage/fix-plan.
        if getattr(s, "detection_source", "static") != "static":
            _wb = _QUADRANT.get((tainted, state), (99, None, "REVIEW"))
            s.ai_reachability = {
                "critical_guard_on_path": state,
                "tainted_reachable": tainted,
                "severity_rank": _wb[0],
                "would_be_verdict": _wb[1],        # what the deterministic machinery WOULD have said
                "note": "advisory only — AI-suspected surface; never a deterministic verdict/headline input",
            }
            continue
        counts["attributed"] += 1
        # FP4 auth-gate: an authenticated route (FastAPI Depends(current_org/user)) proves the CALLER is
        # authenticated -> soften BLOCK to REVIEW (never ALLOW, never delete). Sanctioned exception to the
        # downgrade-only invariant, bounded to REVIEW, on POSITIVE evidence (a curated auth dependency).
        if getattr(s, "auth_gated", False):
            s.severity_rank = 3 if tainted else 7
            s.verdict = "AUTH_GATED_REVIEW"
            s.live_promotion_verdict = "REVIEW"
            counts["guarded_review"] += 1
            continue
        # FP3 config-destination: an external_write whose DESTINATION is a constant/config value is not
        # exfil regardless of whether the DATA is tainted — exfil needs an attacker-controlled DESTINATION,
        # not merely untrusted data going to a fixed endpoint. (The harder constructed-URL cases are caught
        # by the adversarial verifier, which reads the code.)
        if (s.capability == "external_write" and getattr(s, "dest_provenance", "unknown") in ("constant", "config")):
            s.severity_rank = 5
            s.verdict = "CONFIG_DESTINATION_WRITE_REVIEW"
            s.live_promotion_verdict = "REVIEW"
            counts["guarded_review"] += 1
            continue
        # S8.46 subprocess shell-form: a subprocess with a tainted DATA argument but NO shell interpretation
        # (subprocess.run([list])/Popen without shell=True) is NOT command injection — the arg is passed
        # literally, not parsed by a shell. Downgrade to review; shell=True and os.system stay critical.
        if (s.capability == "subprocess_exec" and not getattr(s, "shell_form", True)):
            s.severity_rank = 5
            s.verdict = "SUBPROCESS_NON_SHELL_REVIEW"
            s.live_promotion_verdict = "REVIEW"
            counts["guarded_review"] += 1
            continue
        # Defer to a prior PROVEN protection verdict only when that proof rests on a STRONG RESOLVED guard
        # identity — NOT a LOCAL_DEFINITION (marker re-verify: call_graph.prove credits a local decoy named
        # after a gate; trusting that here let a decoy downgrade a critical sink to rank 3). A resolved-
        # import/gateway cross-module proof still wins; a local-def proof does not for a critical sink.
        _proof_id = s.guard_proof.get("guard_identity")
        _proof_strong = (s.guard_proof.get("status") == "proven" and _proof_id in _CRITICAL_IDENTITY)
        if state != "yes" and _proof_strong:
            s.severity_rank = 3 if tainted else 7
            counts["guarded_review"] += 1
            continue
        rank, verdict, promo = _QUADRANT[(tainted, state)]
        s.severity_rank = rank
        # NEVER DE-ESCALATE (adversarial-marker blocker): guard-attribution may only make a surface MORE
        # severe. If a prior pass already put it in the enforced-BLOCK set, do not relabel it to a
        # review-level verdict (that dropped BLOCK surfaces out of enforcement). Keep the block verdict;
        # only replace it when GA's own verdict is itself enforced-block (e.g. UNGUARDED_CRITICAL).
        if verdict is not None and s.verdict in _ENFORCED_BLOCK and verdict not in _ENFORCED_BLOCK:
            counts["guarded_review"] += 1
            continue
        # DOWNGRADE-ONLY: set a severity verdict only for the un-/under-guarded cases; never override an
        # already-proven verdict for a "yes" surface (keep the classifier's; only record the rank).
        if verdict is not None:
            s.verdict = verdict
            s.live_promotion_verdict = promo
            if state == "no" and tainted:
                counts["unguarded_critical"] += 1
            elif state == "no":
                counts["unguarded_unproven_reach"] += 1
            elif state == "partial":
                counts["partial"] += 1
            else:
                counts["unknown"] += 1
        else:
            counts["guarded_review"] += 1
    return counts
