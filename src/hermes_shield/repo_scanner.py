"""Hermes Shield MVP-1A — read-only repo scanner. Walks a target repo, detects action surfaces +
untrusted ingresses + guard evidence via AST + patterns. NEVER writes to the target, never reads
secrets. Deterministic."""
from __future__ import annotations
import ast
import hashlib
from pathlib import Path
from typing import List, Tuple

from . import patterns as PAT
from . import call_graph as _CG
from . import ast_sinks as _AST
from .models import ActionSurface, UntrustedIngress, GuardEvidence, TestEvidence, SCANNER_VERSION


def _context(rel: str) -> str:
    if "discovery_corpus" in rel or "audit_harness" in rel:   # our own attack fixtures are NOT prod
        return "test"
    if PAT.TEST_HINT.search(rel):
        return "test"
    if PAT.REPORT_HINT.search(rel):
        return "report"
    if PAT.DEV_HINT.search(rel):
        return "dev"
    return "prod"


def _fingerprint(text: str) -> str:
    norm = " ".join(text.split())
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:16]


def within_root(p: Path, root_resolved: Path) -> bool:
    """audit finding #2 (CWE-61/CWE-22): the target repo is UNTRUSTED input. Reject any candidate that
    is a symlink, or whose CANONICAL (fully-resolved) path escapes the canonical target root. This blocks
    out-of-root reads via a symlinked `*.py` file OR a symlinked parent directory. `root_resolved` must
    already be root.resolve() (both sides resolved so a legitimately symlinked root — e.g. /tmp on macOS —
    is not falsely rejected)."""
    try:
        if p.is_symlink():
            return False
        rp = p.resolve()
        return rp == root_resolved or root_resolved in rp.parents
    except OSError:
        return False


def _iter_py(root: Path):
    root_resolved = root.resolve()
    for p in root.rglob("*.py"):
        parts = set(p.parts)
        if parts & PAT.SKIP_DIRS:
            continue
        if PAT.DEAD_FILE.search(p.name):   # skip backup/archived/dead copies
            continue
        if not within_root(p, root_resolved):   # audit #2: no symlink / out-of-root reads
            continue
        try:
            if p.stat().st_size > 400_000:
                continue
        except OSError:
            continue
        yield p


def _function_ranges(tree) -> List[Tuple[int, int, str]]:
    out = []
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            end = getattr(n, "end_lineno", n.lineno)
            out.append((n.lineno, end, n.name))
    return out


def _enclosing(ranges, line: int) -> Tuple[str, int, int]:
    best = ("", 0, 0)
    for start, end, name in ranges:
        if start <= line <= end and (best[1] == 0 or start >= best[1]):
            best = (name, start, end)
    return best


def _likely_lane(rel: str) -> str:
    r = rel.lower()
    for key, lane in (
        ("linkedin", "linkedin"), ("gmail", "gmail"), ("investor", "investor"),
        ("breaking", "breaking_news"), ("quote", "quote_bot"), ("reply", "reply"),
        ("youtube", "youtube"), ("scheduler", "scheduler"), ("lane2", "lane2"),
        ("lane3", "lane3"), ("dashboard", "dashboard"), ("telegram", "telegram"),
        ("hermes_shield", "shield_scanner"), ("security/", "security"),
    ):
        if key in r:
            return lane
    return Path(rel).stem


def scan_file(path: Path, root: Path):
    rel = str(path.relative_to(root))
    ctx = _context(rel)
    lane = _likely_lane(rel)
    text = path.read_text(encoding="utf-8", errors="ignore")
    lines = text.splitlines()
    surfaces: List[ActionSurface] = []
    ingresses: List[UntrustedIngress] = []

    ranges = []
    taint_edges = {}
    _tree = None
    _cli_main = False
    try:
        _tree = ast.parse(text)
        ranges = _function_ranges(_tree)
        from . import taint as _TAINT
        from . import call_graph as _CGmod
        _cli_main = _CGmod._has_main_guard(_tree)   # S8.85: CLI-__main__ -> stdin is trusted parent IPC
        taint_edges = _TAINT.analyze(_tree, cli_main=_cli_main)   # {call_line: source} from untrusted input
    except Exception:
        ranges = []
        _tree = None

    file_has_fence = bool(PAT.FENCE_MARKERS.search(text))
    _seen_caps = {}
    fg = _CG.FileGraph(text)  # P2.9B: AST call graph for guard-before-sink proof
    file_is_debug = bool(PAT.DEBUG_HINT.search(rel))
    file_is_collector = bool(PAT.COLLECTOR_HINT.search(rel))

    def _make(i, cap, mutating, sym, sink_name, mode, module_scope):
        _, fstart, fend = _enclosing(ranges, i) if ranges else ("", max(1, i - 20), min(len(lines), i + 20))
        window = "\n".join(lines[max(0, (fstart or i) - 1):(fend or i)])
        guards = _detect_guards(window, text)
        proof = fg.prove(i)
        proven = proof.get("status") == "proven"
        base = "critical" if cap in PAT.CRITICAL_CAPS else "medium"
        surf = ActionSurface(
            id=f"{rel}:{i}:{cap}", file_path=rel, line_start=(fstart or i), line_end=(fend or i),
            symbol=sym, capability=cap, risk_level=_risk(cap, base, ctx),
            live_capable=_live_capable(cap, ctx, guards),
            dry_run_supported="yes" if guards.dry_run else "unknown",
            context=ctx, likely_lane=lane, guards=guards, fingerprint=_fingerprint(window[:2000]),
            tests=TestEvidence(), sink_name=str(sink_name)[:40], mutating=mutating, guard_proof=proof,
            guard_evidence_level=("proven_before_sink" if proof.get("proof_type") in ("same_function_before_sink", "try_block_guard_before_sink", "try_block_early_return_guard", "early_return_guard")
                                  else "wrapper_proven" if proven
                                  else "static_only" if (guards.kill_switch or guards.final_action_gate)
                                  else "none"),
            protection_confidence=("high" if proof.get("proof_type") == "same_function_before_sink" else "medium" if proven else "low"),
            sink_detection_mode=mode, module_scope=module_scope)
        surf.stable_id = f"{rel}::{sym or '<module>'}::{cap}::{surf.sink_name}"
        surf.sink_line = i                            # S8: exact sink call line for inter-procedural join
        if i in taint_edges:                          # S1.6: reachable from untrusted input
            surf.tainted_reachable = True
            surf.taint_source = taint_edges[i]
        if mode != "regex_fallback":
            proof.setdefault("sink_detection_mode", mode)
        if file_is_debug:
            surf.context = "dev"
        elif file_is_collector and mutating != "yes":
            surf.context = "dev"
        return surf

    # P2.9E: AST-backed sink detection is PRIMARY (actual Call/write nodes only — import/def/reference/
    # string/comment lines are structurally excluded). Regex is a parse-failure fallback (weak).
    ast_ok, ast_sinks = _AST.detect(text)
    # S8.72 WIRE-IN: the focused agent-specific detectors (were built + tested but never called by the pipeline).
    # secret-exfil -> new sinks; eval-on-LLM-output -> tag the code_exec surface so the report can name the class.
    llm_eval_lines = {}
    if ast_ok:
        try:
            from . import secret_exfil_detector as _SE, llm_eval_detector as _LE
            for f in _SE.detect(text):
                ast_sinks.append({"line": f["line"], "capability": "secret_exfil", "mutating": "yes",
                                  "sink_kind": "secret_exfil:" + f["pattern"], "enclosing_symbol": "",
                                  "module_scope": False, "call_expr": f["pattern"], "auth_gated": False,
                                  "dest_provenance": "unknown", "shell_form": True})
            llm_eval_lines = {f["line"]: f["confidence"] for f in _LE.detect(text)}
        except Exception:
            pass
    # Fix1: dataflow-aware DESTINATION analysis for fixed-channel / external sinks. Resolves the
    # destination arg (through one shallow level of local variable / payload-dict indirection), classifies
    # its provenance (constant/config/unknown) and — crucially — whether TAINT reaches the DESTINATION
    # specifically. A tainted-CONTENT send to a fixed destination is demoted downstream; a tainted
    # DESTINATION stays RED. {sink_line: (provenance, tainted_destination)}.
    dest_info = {}
    if ast_ok and _tree is not None:
        _dest_caps = {sk["line"]: sk["capability"] for sk in ast_sinks
                      if sk.get("capability") in _AST._DEST_AWARE_CAPS}
        if _dest_caps:
            try:
                dest_info = _AST.analyse_destinations(_tree, _dest_caps, cli_main=_cli_main)
            except Exception:
                dest_info = {}
    # Fable-5 tainted-executable: for subprocess sinks, resolve whether the PROGRAM (argv0) is
    # attacker-controlled. shell=False only strips shell parsing; a tainted argv0 is still arbitrary-program
    # RCE, so it must stay RED and NOT be downgraded by guard_attribution's shell-form rule. {sink_line}.
    subproc_tainted_exec = set()
    if ast_ok and _tree is not None:
        _subproc_lines = {sk["line"] for sk in ast_sinks if sk.get("capability") == "subprocess_exec"}
        if _subproc_lines:
            try:
                subproc_tainted_exec = _AST.analyse_subprocess_executables(_tree, _subproc_lines, cli_main=_cli_main)
            except Exception:
                subproc_tainted_exec = set()
    if ast_ok:
        from collections import defaultdict
        # P2.9F-REVIEW census fix: a browser SUBMIT inside a dedicated DM-send module IS a direct
        # message send (`dm`), not a generic browser_submit. Relabel so the census reflects DM risk.
        _is_dm_mod = any(k in rel.lower() for k in ("linkedin_dm_send_runner", "linkedin_dm_bridge", "dm_send_runner"))
        groups = defaultdict(list)
        for sk in ast_sinks:
            cap = sk["capability"]
            if _is_dm_mod and cap == "browser_submit":
                cap = sk["capability"] = "dm"
            # S8.94 recall fix: group by the FULL scope path, not the bare enclosing name. Two distinct
            # methods that share a name (ClassA.handle vs ClassB.handle) previously collided into one group,
            # hiding the second real sink as a sibling (Gate-4: output_handler.py:180 hidden behind :149).
            # Distinct scopes -> distinct surfaces; TRUE same-scope duplicates (two sinks in one function)
            # share a scope_path and still collapse (intentional noise control). Fall back to the bare name
            # for sinks that carry no scope_path (regex/route/other front-ends) — byte-identical for them.
            scope = sk.get("scope_path")
            if scope is None:
                scope = sk["enclosing_symbol"]
            groups[(scope, cap)].append(sk)

        def _sink_severity(sk):
            # ROOT FIX (Fable-5 taint + destination axes) — danger ranking used to pick the dedup
            # representative. It mirrors EXACTLY the signals guard_attribution reads to band a surface:
            #   * tainted CONTENT (tainted_reachable, via taint_edges) is the RED driver (the quadrant
            #     (True,"no") -> UNGUARDED_CRITICAL_LIVE_SINK);
            #   * an attacker-controlled / UNKNOWN destination stays RED, while a PROVEN constant/config
            #     destination is the ONLY thing demoted to the AMBER fixed-dest review band.
            # Guard is already homogeneous within a partition (the proof-status split + the guardable-axis
            # split above), so taint and destination are the two remaining severity axes. Higher tuple ==
            # more severe; equal tuples fall back to source order (max keeps the FIRST maximal member), so
            # an all-benign / untainted / constant-dest partition is byte-identical to the old first-wins
            # behaviour — no over-fire, surface counts unchanged.
            line = sk["line"]
            tainted = 1 if line in taint_edges else 0
            if line in dest_info:
                _prov, _tdest = dest_info[line]
            else:
                _prov, _tdest = sk.get("dest_provenance", "unknown"), False
            prov_rank = {"unknown": 2, "config": 1, "constant": 0}.get(_prov, 2)
            return (tainted, 1 if _tdest else 0, prov_rank)

        for (scope, cap), sks in groups.items():
            # P2.9E-REVIEW: a function may have several sinks of one capability. Surface a
            # representative for EACH proof-status so an UNGUARDED live-action sink is never hidden by
            # a guarded sibling: one PROVEN (if any) AND one UNPROVEN (if any). Same-status siblings
            # are genuinely redundant and merged; their lines are recorded as sibling_sinks.
            proven = [sk for sk in sks if fg.prove(sk["line"]).get("status") == "proven"]
            unproven = [sk for sk in sks if sk not in proven]
            for group in (proven, unproven):
                if not group:
                    continue
                # BLOCKER-1 (Fable-5 adversarial re-run): the proof-status split alone is NOT enough to keep
                # the P2.9E-REVIEW promise ("an UNGUARDED live-action sink is never hidden by a guarded
                # sibling"). A one-hop-GUARDED wrapper CALL-SITE (`send_draft(...)`) and an unguarded DIRECT
                # sink of the same capability (`service...send(...)`) both return fg.prove()=="unproven", so
                # they land in the SAME bucket; surfacing only group[0] (the textually-first = the guarded
                # wrapper) folded the genuinely-unguarded direct sink into sibling_sink_lines, where it never
                # got its own guard verdict — and guard_attribution's one-hop credit then marked the surviving
                # wrapper surface "yes" -> BLUE, silencing a real reachable+tainted exfil (`guarded(); send()`
                # on one physical line collapsed the whole repo to BLUE).
                #
                # FIX (keys the de-hiding split on the GUARD/ATTRIBUTION axis, per the review): partition each
                # proof-status bucket by whether the sink is ONE-HOP-GUARDABLE — a bare-name call whose target
                # has no "." — versus a DIRECT dotted/method sink. This mirrors guard_attribution._one_hop_guarded
                # EXACTLY: the one-hop guard credit is only ever applied to a bare-name sink (a dotted/method sink
                # carries "." so it can NEVER be one-hop credited). A direct sink therefore CANNOT be over-credited
                # by a guarded wrapper, so it must keep its OWN representative and can never be dropped in favour of
                # a guardable (potentially one-hop-guarded) sibling. Same-axis siblings still collapse (intentional
                # noise control — a nested guarded-wrapper arg on the sink line, or a duplicate call, stays folded).
                # The textually-first sink of each partition is the representative: within one function an
                # in-function guard can only dominate LATER lines, so the earliest occurrence is the least-guarded
                # (most severe) — picking it never over-credits.
                def _guardable(sk):
                    ce = (sk.get("call_expr", "") or "").strip()
                    return bool(ce) and "." not in ce
                by_axis = defaultdict(list)
                for sk in group:
                    # A guarded wrapper is one-hop-credited by its own bare NAME, not its position, so two
                    # DIFFERENT bare-name calls (a guarded wrapper textually before a distinct unguarded sink
                    # of the same capability/scope) must NOT share a representative — else the guarded-first
                    # call survives and one-hop-credits the group to BLUE, silencing the real exfil. Key the
                    # guardable partition on the distinct call name; dotted/direct sinks (never one-hop
                    # credited) still share one representative.
                    g = _guardable(sk)
                    # BLOCKER (Fable-5 shell_form axis): shell_form is a VERDICT-DETERMINING axis for
                    # subprocess_exec — guard_attribution downgrades a NON-shell subprocess (subprocess.run([list]),
                    # shell_form=False) to the AMBER SUBPROCESS_NON_SHELL_REVIEW band, while a SHELL subprocess
                    # (os.system / shell=True, shell_form=True) with a tainted arg is RED command injection
                    # (UNGUARDED_CRITICAL_LIVE_SINK). Both are capability=subprocess_exec and both dotted, so
                    # without this key they collapse into one guardable-axis partition; when the non-shell sibling
                    # sorts first, worst-member selection ties them on the taint/dest tuple (dest axes are
                    # homogeneous for a non-dest-aware RCE cap) and the textually-first AMBER hid the RED shell
                    # injection — an order-dependent BLUE/AMBER collapse. Partition on shell_form so each form
                    # keeps its OWN representative and its OWN verdict, exactly like the guardable/proof-status
                    # splits. Non-subprocess caps carry shell_form=True uniformly (ast_sinks), so this never
                    # splits a non-subprocess group — no over-report, benign groups unchanged.
                    by_axis[(g, (sk.get("call_expr", "") or "").strip() if g else "",
                             bool(sk.get("shell_form", True)))].append(sk)
                for _axis_key, target_group in by_axis.items():
                    # STRUCTURAL REDESIGN (Fable-5 dedup class — close band-suppression on EVERY axis).
                    # Representative-selection by a PRE-VERDICT proxy (_sink_severity ranks only taint/dest) was
                    # whack-a-mole: any verdict-determining input that is neither a partition key nor in the proxy
                    # was a latent hole where a benign representative hid a band-driving sibling. The proven axis
                    # was guard STRENGTH vs proof-identity — fg.prove() counts a LOCAL_DEFINITION decoy as
                    # 'proven', but guard_attribution rejects it (MED-1 _CRITICAL_IDENTITY), so a decoy-guarded RED
                    # sink and a critically-guarded REVIEW sink shared one 'proven' partition and the proxy folded
                    # the RED one behind the guarded sibling with the higher taint/dest tuple (context/mutating was
                    # a 6th candidate). Rather than add a 7th partition key, we now BUILD a full surface for EVERY
                    # raw sink of the partition and DEFER the one-row collapse to a POST-VERDICT pass
                    # (install_report.collapse_dedup_to_worst_band, run in scan_hermes AFTER guard_attribution) that
                    # keeps the WORST-BANDED member. The survivor then drives the max band over ALL raw members on
                    # every axis — a folded sibling can NEVER lower the band — while display/counts stay one row per
                    # partition. repo_scanner still RETURNS one representative per partition (the display-preferred
                    # = worst-_sink_severity member, byte-identical to before for direct scan_repo callers); the
                    # other raw surfaces ride on it as `_dedup_folded` and are merged into the surface set for the
                    # verdict passes, then collapsed away.
                    pid = f"{rel}::{scope}::{cap}::{'proven' if group is proven else 'unproven'}::{_axis_key!r}"
                    display_pref = max(target_group, key=_sink_severity)
                    built = []
                    for sk in target_group:
                        # DISPLAY symbol stays the BARE enclosing name (scope path is a grouping key only).
                        sym = sk["enclosing_symbol"]
                        surf = _make(sk["line"], cap, sk["mutating"], sym,
                                     sk["call_expr"], sk["sink_kind"], sk["module_scope"])
                        surf.dest_provenance = sk.get("dest_provenance", "unknown")   # FP3
                        if surf.sink_line in dest_info:                               # Fix1: dataflow refinement
                            _prov, _tdest = dest_info[surf.sink_line]
                            surf.dest_provenance = _prov
                            surf.tainted_destination = _tdest
                        surf.auth_gated = sk.get("auth_gated", False)                 # FP4
                        surf.shell_form = sk.get("shell_form", True)                  # S8.46
                        if cap == "subprocess_exec":                                   # Fable-5 tainted-executable
                            surf.tainted_executable = surf.sink_line in subproc_tainted_exec
                        if cap == "code_exec" and sk["line"] in llm_eval_lines:        # S8.72 eval-on-LLM-output
                            surf.guard_proof["llm_output_eval"] = llm_eval_lines[sk["line"]]
                        surf.dedup_partition_id = pid
                        surf.dedup_display_pref = (sk is display_pref)
                        if proven and unproven:
                            surf.guard_proof["dedup_group"] = f"{sym}:{cap}"
                        built.append(surf)
                    rep = next(s for s in built if s.dedup_display_pref)
                    # Preliminary sibling trail for DIRECT scan_repo callers (the collapse pass runs only under
                    # scan_hermes.run_scan). collapse_dedup_to_worst_band recomputes it for the true survivor.
                    rep.guard_proof.setdefault(
                        "sibling_sink_lines", sorted({b.sink_line for b in built if b is not rep}))
                    rep._dedup_folded = [b for b in built if b is not rep]
                    surfaces.append(rep)
    else:
        # regex fallback ONLY when the file does not parse — labelled weak, never full-path.
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", '"""', "'''", "def ", "async def ", "class ", "import ", "from ", "@")):
                continue
            for cap, risk, rx in PAT.ACTION_PATTERNS:
                m = rx.search(line)
                if m:
                    _end = m.end(); _last = m.group(0)[-1]
                    if (_last.isalnum() or _last == "_") and _end < len(line) and (line[_end].isalnum() or line[_end] == "_"):
                        continue
                    sym, _, _ = _enclosing(ranges, i) if ranges else ("", 0, 0)
                    key = (sym, cap)
                    if key in _seen_caps:
                        _seen_caps[key] += 1
                        break
                    _seen_caps[key] = 1
                    mutating = "yes" if cap in PAT.MUTATING_CAPS else ("no" if cap in PAT.READONLY_CAPS else "unknown")
                    surfaces.append(_make(i, cap, mutating, sym, m.group(0), "regex_fallback", not sym))
                    break

    for src, rx in PAT.INGRESS_PATTERNS:
        if rx.search(text):
            cls = "fenced_full_path" if file_has_fence else "unfenced"
            if file_has_fence and ctx in ("report", "test"):
                cls = "static_instruction_only"
            ingresses.append(UntrustedIngress(
                id=f"{rel}:{src}", file_path=rel, source_type=src,
                fenced=file_has_fence,
                fence_markers=["hermes_untrusted"] if file_has_fence else [],
                classification=cls, context=ctx))
    return surfaces, ingresses


def _detect_guards(window: str, whole_file: str) -> GuardEvidence:
    g = GuardEvidence()
    markers = []
    # structural guards are usually module-level imports used across the file -> whole-file scope.
    FILE_SCOPE = {"kill_switch", "final_action_gate", "untrusted_fence", "strict_hash", "csrf_token"}
    for name, rx in PAT.GUARD_MARKERS.items():
        if rx.search(window):
            setattr(g, name, True); markers.append(name)
        elif name in FILE_SCOPE and rx.search(whole_file):
            setattr(g, name, True); markers.append(name + "(file)")
    g.markers = markers
    return g


def _risk(cap: str, base_risk: str, ctx: str) -> str:
    if ctx in ("test", "report"):
        return "low"
    if cap in PAT.CRITICAL_CAPS and base_risk == "critical":
        return "critical"
    return base_risk


def _live_capable(cap: str, ctx: str, guards: GuardEvidence) -> str:
    if ctx in ("test", "report"):
        return "no"
    if cap in PAT.CRITICAL_CAPS:
        return "yes"
    return "unknown"


def _lang_surfaces(rel, sinks, guards, language, mode, taint_map=None):
    """S8.24/27 shared builder for a non-Python front-end. taint_map (sink_line -> source) upgrades
    tainted_reachable; but with no guard model the guard axis stays 'unknown' -> guard-attribution's
    (True, unknown) quadrant = NEEDS_CALL_GRAPH / REVIEW. NEVER UNGUARDED_CRITICAL (no proven 'no guard')."""
    taint_map = taint_map or {}
    out = []
    for sk in sinks:
        i, cap = sk["line"], sk["capability"]
        base = "critical" if cap in PAT.CRITICAL_CAPS else "medium"
        surf = ActionSurface(
            id=f"{rel}:{i}:{cap}", file_path=rel, line_start=i, line_end=i, symbol="",
            capability=cap, risk_level=_risk(cap, base, "prod"), live_capable="unknown",
            dry_run_supported="unknown", context="prod", likely_lane="", guards=guards, fingerprint="",
            tests=TestEvidence(), sink_name=sk["call_expr"][:40], mutating=sk.get("mutating", "yes"),
            guard_proof={"status": "unproven", "proof_type": f"{language}_no_call_graph",
                         "limitations": [f"{language} v1: sinks-only, no taint/guard analysis"]},
            guard_evidence_level="none", protection_confidence="low",
            sink_detection_mode=mode, module_scope=False)
        surf.sink_line = i
        surf.language = language
        if i in taint_map:
            surf.tainted_reachable = True
            surf.taint_source = f"{language}-flow: {taint_map[i]}"
            # no guard model for a third-party repo -> guard 'unknown' -> quadrant gives REVIEW, never BLOCK.
            surf.guard_attribution = {"critical_guard_on_path": "unknown", "path_scope": "no_guard_model",
                                      "resolution_limits": [f"{language} v2: taint yes, guard unknown"]}
        else:
            surf.tainted_reachable = False
        out.append(surf)
    return out


def scan_ts_file(path: Path, root: Path):
    from . import ts_sinks
    rel = str(path.relative_to(root))
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    ok, sinks = ts_sinks.detect(text, tsx=(path.suffix == ".tsx"))
    if not ok:
        return []
    from . import ts_taint
    tmap = ts_taint.analyze(text, tsx=(path.suffix == ".tsx"))
    return _lang_surfaces(rel, sinks, _detect_guards("", text), "typescript", "ts_tree_sitter", tmap)


def scan_cs_file(path: Path, root: Path):
    from . import cs_sinks
    rel = str(path.relative_to(root))
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    ok, sinks = cs_sinks.detect(text)
    if not ok:
        return []
    return _lang_surfaces(rel, sinks, _detect_guards("", text), "csharp", "cs_tree_sitter")


def _iter_lang(root: Path, suffixes):
    root_resolved = root.resolve()
    for suf in suffixes:
        for p in root.rglob(suf):
            parts = set(p.parts)
            if parts & PAT.SKIP_DIRS or ".test." in p.name or ".spec." in p.name or ".d.ts" in p.name:
                continue
            if not within_root(p, root_resolved):   # audit #2: no symlink / out-of-root reads
                continue
            yield p


_RCE_STREAM = {"code_exec", "subprocess_exec", "deserialize", "ssti"}


def scan_repo(root: Path, languages=("python", "typescript", "csharp"), progress=None):
    # S8.93: `progress` is an OPTIONAL per-file callback (None => byte-identical behaviour). It fires once
    # per real file processed with the running file/surface counts + any RCE-class surfaces just found, so a
    # caller can stream genuine live progress. It never changes the scan — it only reports it.
    surfaces: List[ActionSurface] = []
    ingresses: List[UntrustedIngress] = []
    files = 0

    def _tick(new, relpath=None):
        if progress:
            rce = [(su.capability, su.file_path, getattr(su, "sink_line", 0) or su.line_start)
                   for su in new if su.capability in _RCE_STREAM]
            # `file`/`count` are ADDITIVE (S8.94 --live upward log): the current file being read + its
            # per-file surface count. Extra keys only; existing consumers (stream.py) ignore them, so the
            # default no-progress path stays byte-identical.
            progress({"phase": "map", "files": files, "surfaces": len(surfaces), "new": rce,
                      "file": relpath, "count": len(new)})

    def _rel(p):
        try:
            return str(Path(p).relative_to(root))
        except Exception:
            return Path(p).name

    if "python" in languages:
        for p in _iter_py(root):
            files += 1
            s, ing = scan_file(p, root)
            surfaces.extend(s)
            ingresses.extend(ing)
            _tick(s, _rel(p))
    if "typescript" in languages:
        for p in _iter_lang(root, ("*.ts", "*.tsx", "*.mts", "*.cts", "*.js", "*.mjs")):
            files += 1
            ts = scan_ts_file(p, root)
            surfaces.extend(ts)
            _tick(ts, _rel(p))
    if "csharp" in languages:
        for p in _iter_lang(root, ("*.cs",)):
            files += 1
            cs = scan_cs_file(p, root)
            surfaces.extend(cs)
            _tick(cs, _rel(p))
    return {"root": str(root), "files_scanned": files, "scanner_version": SCANNER_VERSION,
            "surfaces": surfaces, "ingresses": ingresses}
