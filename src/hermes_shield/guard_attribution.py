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

# Fix1: fixed-channel / external capabilities whose DESTINATION argument is separable from the CONTENT.
# A tainted-CONTENT send to a non-attacker-controlled destination is demoted to AMBER review (see apply).
_FIXED_DEST_CAPS = {"external_write", "telegram_send", "email_send"}

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


def attribute(surface, graphs: Dict[str, FileGraph], mod2files: dict = None, inner_sinks: dict = None) -> dict:
    """Compute critical_guard_on_path for one surface. Returns the guard_attribution dict.

    `inner_sinks` (Fix 2) maps (file_rel, enclosing_fn) -> [critical-cap sink lines] and enables a bounded
    ONE-HOP DOWNWARD guard credit: when the sink LINE is itself a direct call to a RESOLVED in-repo wrapper
    function whose OWN inner action sink is dominated by a critical guard, the guarded wrapper call-site is
    credited (state 'yes' -> REVIEW), instead of double-counting the phantom entrypoint call-site as
    unguarded. Sound: the callee must RESOLVE (local def or resolved import) and EVERY inner critical sink
    must be guarded — a name match or an unguarded sibling is never credited."""
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
    # Fix 2: one-hop DOWNWARD credit. If the sink line is a call INTO a resolved in-repo wrapper that is
    # itself critically guarded, the call-site is guarded — do not leave it rank-0 as a phantom entrypoint.
    if result != "yes" and inner_sinks:
        hop = _one_hop_guarded(surface, fg, sink_fn, graphs, mod2files, inner_sinks)
        if hop:
            for g in hop["guards"]:
                guards_found.append({"guard_type": g[1], "identity": g[2], "guard_line": g[0],
                                     "at": f'{hop["callee_path"]}::{hop["callee"]}', "via": "one_hop_callee"})
            result = "yes"
            if hop["callee_path"] != surface.file_path:
                scope["cross"] = True

    return {"critical_guard_on_path": result, "guards_found": guards_found,
            "unguarded_paths": unguarded, "resolution_limits": limits,
            "path_scope": "interprocedural_visible" if scope["cross"] else "intraprocedural"}


def _resolve_callee(name: str, fg: FileGraph, home_rel: str, graphs: Dict[str, FileGraph], mod2files: dict):
    """Resolve a name called at a sink line to its (callee_fg, callee_fn, callee_rel) — either a local def
    in the SAME file or a RESOLVED cross-file import (unique-file resolver; ambiguous/foreign -> None).
    Never a bare name match: an unresolved / dynamically-imported callee returns None (stays severe)."""
    if name in fg.funcs:
        return fg, name, home_rel
    imp = fg.imports.get(name)
    if imp and imp.get("orig") in (name, None):
        from .cross_module import resolve_import_to_file
        target = resolve_import_to_file(imp, home_rel, mod2files)
        if target and target in graphs and graphs[target].ok:
            callee_fn = imp.get("orig") or name
            if callee_fn in graphs[target].funcs:
                return graphs[target], callee_fn, target
    return None, None, None


def _one_hop_guarded(surface, fg: FileGraph, sink_fn: str, graphs: Dict[str, FileGraph],
                     mod2files: dict, inner_sinks: dict):
    """If the sink LINE is a direct call to a resolved in-repo wrapper whose EVERY inner critical sink is
    dominated by a critical guard, return {callee, callee_path, guards}. Else None. Bounded to one hop."""
    cap = surface.capability
    f = fg.funcs.get(sink_fn)
    if not f:
        return None
    sink_line = getattr(surface, "sink_line", 0) or surface.line_start
    # BLOCKER 1: bind the guard credit to THIS surface's OWN sink call — never a sibling/nested call that
    # merely shares the physical line. The physical line can carry several plain-name calls (a guarded
    # sibling, or an enclosing wrapper wrapping the real sink's RESULT); crediting ANY of them would let a
    # guarded neighbour hijack the credit for an unrelated, genuinely-unguarded sink and silence a real
    # exfil to BLUE. So we consider ONLY the callee whose bare name IS this surface's sink call name
    # (surface.sink_name == the sink's own call_expr). A dotted/method sink never matches (it carries "."),
    # so it is never one-hop credited — correctly staying severe.
    own = (getattr(surface, "sink_name", "") or "").strip()
    names = [bare for (ln, bare, _dotted, is_method) in f["all_calls"]
             if ln == sink_line and bare and not is_method and "." not in bare and bare == own]
    for name in names:
        if name == sink_fn:
            continue                                          # never descend into self (recursion)
        callee_fg, callee_fn, callee_rel = _resolve_callee(name, fg, surface.file_path, graphs, mod2files)
        if not callee_fg or callee_fn not in callee_fg.funcs:
            continue
        # BLOCKER 1 (cont.): the credited inner sink must bear THIS surface's capability — a wrapper whose
        # only guarded inner sink is of a DIFFERENT capability is not proof that the surface's own action is
        # guarded. inner_sinks carries (line, capability); filter to the surface's capability.
        inner = [ln for (ln, icap) in inner_sinks.get((callee_rel, callee_fn), [])
                 if ln != sink_line and icap == cap]
        if not inner:
            continue                                          # no proven same-capability inner sink to credit
        guards, ok = [], True
        for inner_line in inner:
            g = _critical_before(callee_fg, callee_fn, inner_line, cap)
            if not g:
                ok = False                                    # an unguarded inner sink -> never credit
                break
            guards.append(g)
        if ok and guards:
            return {"callee": callee_fn, "callee_path": callee_rel, "guards": guards}
    return None


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
    # Fix 2: index of every critical-capability sink by (file, enclosing_fn) so the one-hop descent can find
    # a wrapper callee's OWN inner action sink line(s) and check they are critically guarded. Each entry is
    # (sink_line, capability) so BLOCKER 1's one-hop credit can require the inner sink to bear the SURFACE's
    # OWN capability (a guarded inner sink of a different capability is not proof this surface is guarded).
    from collections import defaultdict as _dd
    inner_sinks = _dd(list)
    for _s in surfaces:
        if _s.capability not in PAT.CRITICAL_CAPS:
            continue
        _g = graphs.get(_s.file_path)
        if not _g or not _g.ok:
            continue
        _ln = getattr(_s, "sink_line", 0) or _s.line_start
        _fn = _g.enclosing(_ln)
        if _fn:
            inner_sinks[(_s.file_path, _fn)].append((_ln, _s.capability))
    counts = {"unguarded_critical": 0, "guarded_review": 0, "partial": 0, "unknown": 0,
              "unguarded_unproven_reach": 0, "attributed": 0}
    _total = len(surfaces)
    for _i, s in enumerate(surfaces):
        if progress and _i % 40 == 0:
            progress({"phase": "reach", "step": "guards", "traced": _i, "total": _total})
        if s.context != "prod" or s.capability not in PAT.CRITICAL_CAPS:
            continue
        attr = attribute(s, graphs, mod2files, inner_sinks)
        s.guard_attribution = attr
        state = attr["critical_guard_on_path"]
        # taint axis: True = PROVEN reachable from untrusted input (taint is intra-function, incomplete,
        # so False = NOT-PROVEN-reachable, not "safe" — an unguarded (F,no) sink is still flagged, just
        # below a proven-reachable one). Honest, avoids ranking everything CRITICAL.
        tainted = bool(getattr(s, "tainted_reachable", False))
        # A send is proven-guarded either interprocedurally (state == "yes") OR by a STRONG in-function
        # guard proof (a resolved-import/gateway kill-switch dominating the sink — the visit boundary keys
        # on the enclosing def line so it cannot itself see an in-function guard; guard_proof does). This
        # combined "guarded" signal gates BOTH the fixed-dest demotion (BLOCKER 2 — a guarded send is never
        # demoted to the amber band) and the later strong-proof downgrade.
        _proof_id = s.guard_proof.get("guard_identity")
        _proof_strong = (s.guard_proof.get("status") == "proven" and _proof_id in _CRITICAL_IDENTITY)
        _guarded = (state == "yes") or _proof_strong
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
        # FP3/Fix1 fixed-destination: a fixed-channel messaging / external send whose DESTINATION is not
        # attacker-controlled is not exfil, regardless of whether the CONTENT is tainted — exfil needs an
        # attacker-controlled DESTINATION, not merely untrusted data going to a fixed endpoint. Demote to
        # the AMBER review band (never ALLOW, never BLUE — see install_report.is_reachable_fixed_dest_review),
        # on POSITIVE evidence, and ONLY when the destination arg itself is not tainted (CRUCIAL INVARIANT:
        # a tainted chat_id / recipient / url stays RED -> falls through).
        #   * external_write / email_send / telegram_send: ALL require a PROVEN constant/config destination.
        #     An unknown destination is a real exfil channel and must stay RED — a chat_id / recipient / URL
        #     that arrives as a bare parameter or is derived from a name removed from the untrusted set is
        #     NOT proof of a fixed channel (the sole tainted_destination bit is intra-function and incomplete),
        #     so telegram_send gets NO capability-based exemption: it is demoted only on the same
        #     constant/config provenance evidence as the other two channels.
        # (The harder constructed-destination cases are left RED for the adversarial verifier, which reads
        # the code.)
        # BLOCKER 2: a fixed-dest send lands in the AMBER review band iff it would OTHERWISE be RED — i.e.
        # its CONTENT is tainted (tainted_reachable) AND no critical guard dominates it (state != "yes",
        # unguarded). That AMBER condition is split across two honest gates so neither over-fires:
        #   * GUARD gate (here): a KILL-SWITCH-GUARDED send (_guarded — state == "yes" OR a strong in-function
        #     guard proof) is NOT demoted — it flows to the guarded/strong-proof path (rank 3/7, blue/gated),
        #     exactly as on main. Only genuinely unguarded sends demote.
        #   * TAINT gate (install_report.is_reachable_fixed_dest_review): only a tainted-content demoted send
        #     drives the AMBER band. An UNTAINTED config-dest send is still demoted OUT of the hard-block
        #     verdict (preserving the FP3 suppression — a benign config webhook is never a block) but, being
        #     untainted, it is not counted into the fixed-dest AMBER band and so resolves BLUE, not amber.
        # (A tainted DESTINATION already stays RED via the tainted_destination guard below.)
        if (not _guarded
                and s.capability in _FIXED_DEST_CAPS and not getattr(s, "tainted_destination", False)):
            _prov = getattr(s, "dest_provenance", "unknown")
            if _prov in ("constant", "config"):
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
        # (_proof_id / _proof_strong were computed once above, alongside the combined _guarded signal.)
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
            # GAP-2 (Fable-5 artefact coherence): a reachable+unguarded AMBER-capability action
            # (post/reply/like/comment/browser_click ...) correctly KEEPS the UNGUARDED_CRITICAL_LIVE_SINK
            # verdict — that is the string install_report.is_reachable_amber_action keys on to drive the AMBER
            # "reachable actions — review" band and guarantee the send is never dropped to BLUE. But an amber
            # reversible/social action is a "review before you ship", NOT a hard live-promotion BLOCK: the
            # patch plan (block_live_promotion=False), the dashboard block set (is_non_gated_vulnerable filters
            # to _VULN_CAPS, which EXCLUDES the amber set) and every renderer already treat it as review. The
            # RAW per-surface artefact (hermes_action_surface_scan.json) must AGREE on the LIVE-PROMOTION
            # decision — otherwise it stamps live_promotion_verdict='BLOCK' on the SAME file:line that
            # hermes_patch_plan.json calls block_live_promotion=false, the exact same-file:line cross-artefact
            # contradiction this fix class targets, one layer lower. So stamp the amber surface's promotion
            # verdict REVIEW. (severity_rank stays the guard-axis ordering key — 0 for reachable+unguarded is
            # honest and is what the amber band's within-band ordering uses; risk_level stays the capability's
            # inherent risk and is byte-identical across the two JSONs, so neither is a cross-artefact
            # contradiction — only the promotion decision was.) SAFETY: this fires ONLY for _AMBER_ACTION_CAPS,
            # never a RED _VULN_CAPS sink, so no real hard block is ever softened and the RED band /
            # non_gated_vulnerable count (verdict + _VULN_CAPS) is untouched.
            from . import install_report as _IR
            if s.capability in _IR._AMBER_ACTION_CAPS:
                s.live_promotion_verdict = "REVIEW"
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
