"""
Hermes Shield MVP — conservative cross-module guard tracing (P2.9C).

Proves `cross_module_entry_guard_before_helper` ONLY when the evidence is strong and unambiguous:
a helper function H (containing an action sink) is called from entry functions that each run a
resolved, dominating guard BEFORE calling H, AND every resolvable call site of H across the repo is
so guarded. If ANY call site is unguarded, ambiguous, dynamic, or unresolved -> NOT proven.

Static only (uses AST FileGraphs already built by call_graph). Never executes target code. Defaults
safe: dynamic import / getattr / monkeypatch / ambiguous alias / missing source / same-name-wrong-
module all yield "unproven". No secrets.
"""
from __future__ import annotations
from pathlib import Path
from typing import Dict, List

from . import patterns as PAT
from .call_graph import FileGraph


def _dotted(rel: str) -> str:
    return ".".join(Path(rel).with_suffix("").parts)


def build_graphs(root: Path, rel_paths: List[str], progress=None) -> Dict[str, FileGraph]:
    # S8.93: optional `progress` reports call-graph build progress (the big time-sink on large repos) so a
    # caller can stream a live "building call graph X/N" counter. None => byte-identical.
    graphs: Dict[str, FileGraph] = {}
    total = len(rel_paths)
    for i, rel in enumerate(rel_paths):
        if progress and i % 12 == 0:
            progress({"phase": "reach", "step": "call-graph", "traced": i, "total": total})
        p = root / rel
        try:
            graphs[rel] = FileGraph(p.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            continue
    return graphs


def build_mod2files(graphs: Dict[str, FileGraph]) -> Dict[str, set]:
    """dotted-suffix -> set of file rels, ANCHORED AT THE PACKAGE ROOT. marker round 7: registering the
    bare filename stem let a FOREIGN import ('from external_lib.util import send') match an unrelated
    in-tree pkg_a/util.py by stem. Fix: a file inside a package registers only suffixes from its
    package-root component upward (pkg_a/util.py -> 'pkg_a.util' and longer, never bare 'util'); a
    top-level non-package file registers its stem. A prefix can be stripped ABOVE the package root
    (sys.path prefixes, the xmod corpus case) but never INTO the package. Ambiguous suffix -> None.

    KNOWN RESIDUAL (marker round 8, accepted): a file with NO package boundary above it (a top-level
    module, or a PEP-420 namespace package with no __init__.py) is importable as its BARE STEM, so a
    foreign `from external.util import fn` cannot be distinguished from a real top-level `from util
    import fn` — fundamental sys.path ambiguity, not a defect. Bounded three ways: (1) the stem must be
    globally UNIQUE (two -> None); (2) ANY real in-repo caller drops the sink to partial/rank-1 which is
    still enforced BLOCK — the phantom only mis-credits a critical sink with ZERO real callers (a dead/
    library-export surface); (3) it is downgrade-only (REVIEW, never ALLOW). The invariant holds for
    every REACHABLE sink; never observed on the real repo (stable 155 BLOCK / 58 critical)."""
    allp = set(graphs.keys())
    m: Dict[str, set] = {}
    for path in graphs:
        pcomps = path.replace("\\", "/").split("/")[:-1]        # directory components
        parts = _dotted(path).split(".")                        # dotted components incl. stem
        # topmost consecutive package-ancestor: walk up while each dir has an __init__.py in the tree
        d, pkg_top = len(pcomps), len(pcomps)
        while d >= 1 and "/".join(pcomps[:d] + ["__init__.py"]) in allp:
            pkg_top, d = d - 1, d - 1
        for i in range(0, pkg_top + 1):                          # full path down to the package-root anchor
            m.setdefault(".".join(parts[i:]), set()).add(path)
    return m


def resolve_import_to_file(imp: dict, caller_rel: str, mod2files: Dict[str, set]):
    """Resolve a caller's import (absolute OR relative) to the UNIQUE file it names, or None if ambiguous
    / unresolvable. Relative imports are first made ABSOLUTE via the caller's package + level. Then the
    dotted module is matched by its LONGEST suffix that names a file — trying the full name first, then
    shorter suffixes — so a sys.path-prefixed import ('xmod.mod_b_helper' when the scanned tree is rooted
    below 'xmod') still resolves, while an AMBIGUOUS suffix (the same stem in two packages) resolves to
    NOTHING. Longest-first means the most specific match wins; ambiguity at any level fails safe."""
    mod = imp.get("module") or ""
    level = imp.get("level", 0) or 0
    if level >= 1:
        pkg = _dotted(caller_rel).split(".")[:-1]           # caller's package parts
        if level > 1:
            pkg = pkg[:-(level - 1)] if len(pkg) >= (level - 1) else []
        mod = ".".join([p for p in pkg if p] + ([mod] if mod else []))
    if not mod:
        return None
    parts = mod.split(".")
    for i in range(len(parts)):                             # longest suffix first
        files = mod2files.get(".".join(parts[i:]))
        if files is not None:
            return next(iter(files)) if len(files) == 1 else None   # ambiguous -> unresolvable (safe)
    return None


def _resolves_to(caller_rel: str, symbol: str, caller_graph: FileGraph, helper_rel: str,
                 mod2files: Dict[str, set]) -> bool:
    """Does `symbol` in the caller resolve (by import) to the HELPER'S ACTUAL FILE? Resolve to a unique
    file and require it to equal helper_rel — kills the stem/substring/relative wrong-file collisions."""
    imp = caller_graph.imports.get(symbol)
    if not imp:
        return False
    return resolve_import_to_file(imp, caller_rel, mod2files) == helper_rel


def trace_surface(surface, graphs: Dict[str, FileGraph], mod2files: Dict[str, set] = None) -> dict:
    """Attempt a cross-module proof for one unproven critical surface. Returns a proof dict or None."""
    if mod2files is None:
        mod2files = build_mod2files(graphs)
    helper_rel = surface.file_path
    helper_fn = surface.symbol
    if not helper_fn:
        return None
    hg = graphs.get(helper_rel)
    if not hg or helper_fn not in hg.funcs:
        return None
    helper_mod = _dotted(helper_rel)
    is_private = hg.funcs[helper_fn]["private"]

    guarded_sites: List[dict] = []
    unguarded_or_ambiguous = 0
    for rel, g in graphs.items():
        for caller_name, f in g.funcs.items():
            for (line, callee, dotted, is_method) in f["all_calls"]:
                if callee != helper_fn:
                    continue
                # a call to something named helper_fn. Three-way resolution:
                same_file = (rel == helper_rel)
                imp = g.imports.get(helper_fn)
                if same_file:
                    pass  # local call to our helper
                elif imp is not None:
                    # imported: if it resolves to a DIFFERENT file it is a different function -> ignore it
                    if not _resolves_to(rel, helper_fn, g, helper_rel, mod2files):
                        continue
                else:
                    # called but not imported here (star-import/global?) -> ambiguous -> conservative fail
                    unguarded_or_ambiguous += 1
                    continue
                # dominating strong guard before this call line in the caller?
                if any(gl[0] < line for gl in f["top_guards"]):
                    guarded_sites.append({"caller_module": _dotted(rel), "caller_symbol": caller_name,
                                          "call_line": line, "guard_kind": f["top_guards"][-1][1]})
                else:
                    unguarded_or_ambiguous += 1

    # P2.9D entrypoint policy: if this helper is explicitly modelled with allowed_callers, every
    # guarded site's caller module must be an allowed entrypoint; otherwise NEEDS_ENTRYPOINT_CONFIG.
    from .config_loader import load_entrypoints
    _entrypoints, _helpers = load_entrypoints()
    policy = _helpers.get((helper_mod.split(".")[-1], helper_fn))
    if policy and policy.get("proof_policy") == "entrypoint_required":
        allowed = set(policy.get("allowed_callers", []))
        entry_ids = {e["id"]: e for e in _entrypoints}
        for site in guarded_sites:
            if not any(entry_ids.get(a, {}).get("module", "").split(".")[-1] == site["caller_module"].split(".")[-1]
                       or a == site["caller_symbol"] for a in allowed):
                return {"status": "needs_entrypoint_config", "proof_type": "needs_entrypoint_config",
                        "scope": "interprocedural", "helper_symbol": f"{helper_mod}.{helper_fn}",
                        "entrypoint_model_status": "helper_modelled_caller_not_allowed",
                        "modules_involved": [helper_mod], "limitations": ["caller not in allowed_callers"]}

    # PROVEN only if: at least one guarded site, and (helper is private with all sites guarded, OR
    # no unguarded/ambiguous site anywhere). Conservative.
    if guarded_sites and unguarded_or_ambiguous == 0:
        modules = sorted({helper_mod} | {s["caller_module"] for s in guarded_sites})
        return {"status": "proven", "proof_type": "cross_module_entry_guard_before_helper",
                "scope": "interprocedural", "helper_symbol": f"{helper_mod}.{helper_fn}",
                "sink_call": surface.sink_name, "guard_sites": guarded_sites[:5],
                "modules_involved": modules, "guard_identity": "resolved_import",
                "limitations": ["only statically-visible call sites checked; dynamic/reflective "
                                "callers (getattr/importlib/monkeypatch) are not visible"]}
    if guarded_sites and unguarded_or_ambiguous:
        return {"status": "cross_module_guarded_not_proven",
                "proof_type": "cross_module_guarded_not_proven", "scope": "interprocedural",
                "helper_symbol": f"{helper_mod}.{helper_fn}",
                "modules_involved": sorted({helper_mod} | {s["caller_module"] for s in guarded_sites}),
                "limitations": [f"{unguarded_or_ambiguous} unguarded/ambiguous call site(s) of {helper_fn}"]}
    return None  # no cross-module guard evidence -> leave the intraprocedural verdict


def _all_py_rel(root: Path) -> List[str]:
    out = []
    for p in root.rglob("*.py"):
        if set(p.parts) & PAT.SKIP_DIRS or PAT.DEAD_FILE.search(p.name):
            continue
        try:
            if p.stat().st_size > 400_000:
                continue
            out.append(str(p.relative_to(root)))
        except (OSError, ValueError):
            continue
    return out


def apply(root: Path, surfaces, rel_paths, graphs=None, mod2files=None) -> int:
    """Post-pass: upgrade unproven critical surfaces with a cross-module proof where provable.
    Returns the number of surfaces upgraded to proven. Read-only. S8 speed: accepts a shared graph build."""
    # index ALL files (callers of a sink-helper usually contain no sink themselves)
    if graphs is None:
        graphs = build_graphs(root, _all_py_rel(root))
    if mod2files is None:
        mod2files = build_mod2files(graphs)
    upgraded = 0
    for s in surfaces:
        if s.context != "prod" or s.capability not in PAT.CRITICAL_CAPS:
            continue
        if s.guard_proof.get("status") == "proven":
            continue
        res = trace_surface(s, graphs, mod2files)
        if not res:
            continue
        s.guard_proof = res
        if res["status"] == "proven":
            s.guard_evidence_level = "cross_module_proven"
            s.protection_confidence = "medium"
            upgraded += 1
    return upgraded
