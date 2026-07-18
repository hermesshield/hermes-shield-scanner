#!/usr/bin/env python3
"""
Hermes Shield — scan entrypoint. READ-ONLY: scans a target repo (default = the enclosing git repo),
classifies action surfaces + untrusted ingresses + guard evidence, builds a lane protection matrix,
and (optionally) baselines / diffs. Writes ONLY under the report dir. Never reads secrets, never
writes to the target repo, never takes a live action.

Usage:
  hermes-shield scan <repo>            # via the installed CLI (preferred)
  python3 -m hermes_shield.scan_hermes --scan --root <repo>
"""
from __future__ import annotations
import argparse
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

from . import repo_scanner, surface_classifier, guard_detector, baseline as BL, drift as DR
from . import patch_plan, dashboard_export, report_writer as RW
from .models import SCANNER_VERSION


def current_repo_root():
    """Default scan root when --root is not given: the nearest enclosing git repo of the CWD,
    else the CWD itself. Never the scanner package."""
    p = Path.cwd().resolve()
    for a in (p, *p.parents):
        if (a / ".git").exists():
            return a
    return p


def resolve_out_paths(root, out_arg=None):
    """(S8.87, product shape) Decide WHERE scan outputs + baseline go — NEVER inside the scanner
    package, never inside the target repo (the target stays strictly read-only). Resolution order:
      1. explicit --out DIR       -> DIR/outputs, DIR/baseline/...
      2. env HERMES_SHIELD_OUT    -> same
      3. default                  -> ./shield-report/ in the CWD
    """
    base = out_arg or os.getenv("HERMES_SHIELD_OUT")
    if base:
        b = Path(base).resolve()
        return b / "outputs", b / "baseline" / "scan_baseline.json"
    b = (Path.cwd() / "shield-report").resolve()
    return b / "outputs", b / "baseline" / "scan_baseline.json"


def _head(root: Path) -> str:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=root,
                              capture_output=True, text=True, timeout=30).stdout.strip()[:12]
    except Exception:
        return "unknown"


def _now() -> str:
    # stamped by caller-provided arg or git; avoid nondeterministic Date in the module
    try:
        return subprocess.run(["git", "log", "-1", "--format=%cI"], capture_output=True,
                              text=True, timeout=30).stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def _operator_trusts_target_guards(root) -> bool:
    """audit finding #3: target-declared guards earn CRITICAL credit ONLY on an explicit OPERATOR opt-in
    made OUTSIDE the untrusted target. Two operator channels:
      - HERMES_SHIELD_TRUST_TARGET_GUARDS=1   (blanket opt-in), or
      - HERMES_SHIELD_GUARD_POLICY=<path>     pointing at a trusted policy file that lives OUTSIDE the
        target root (a policy inside the target would itself be attacker-controlled, so it is ignored).
    Default: False (advisory-only)."""
    if os.getenv("HERMES_SHIELD_TRUST_TARGET_GUARDS") == "1":
        return True
    pol = os.getenv("HERMES_SHIELD_GUARD_POLICY")
    if pol:
        try:
            pp = Path(pol).resolve()
            rr = Path(root).resolve()
            inside_target = pp == rr or rr in pp.parents
            if pp.is_file() and not inside_target:
                return True
        except OSError:
            pass
    return False


def run_scan(root: Path, progress=None, out_dir=None):
    # S8.93: `progress` is an OPTIONAL event callback (None => byte-identical). run_scan emits phase
    # boundaries; repo_scanner + guard_attribution emit live sub-progress. It only REPORTS the scan.
    # `out_dir` (operator-owned) is where the AI-tier cache lives — NEVER under the untrusted target root.
    def _emit(**kw):
        if progress:
            try:
                progress(kw)
            except Exception:
                pass
    # guard-onboarding: recognise the TARGET repo's own control functions (.hermes-shield.json) so a
    # stranger's gated actions are not falsely reported as un-gated. Reset per scan (isolated). audit #3:
    # target declarations are ADVISORY (non-critical) unless the operator explicitly trusts them.
    _tg_modules, _tg_symbols, _tg_trusted = [], [], False
    try:
        from . import module_index, config_loader
        _tg_modules, _tg_symbols = config_loader.load_target_guards(root)
        _tg_trusted = _operator_trusts_target_guards(root)
        module_index.set_user_guards(_tg_modules, _tg_symbols, trusted=_tg_trusted)
    except Exception:
        pass
    _emit(phase="map", start=True)
    scan = repo_scanner.scan_repo(root, progress=progress)
    # audit #3: make the trust status of target-declared guards VISIBLE in the scan record, so any
    # config-assisted credit is attributable (target-self-declared vs operator-trusted).
    scan["target_guards"] = {"declared_symbols": len(_tg_symbols or []),
                             "declared_modules": len(_tg_modules or []),
                             "trusted_by_operator": bool(_tg_trusted),
                             "status": "operator-trusted" if _tg_trusted else "advisory-only (untrusted)"}
    _emit(phase="map", done=True, files=scan["files_scanned"], surfaces=len(scan["surfaces"]))
    # STRUCTURAL dedup redesign (Fable-5 band-suppression class): repo_scanner returns ONE display
    # representative per dedup partition but parks the OTHER raw sinks of the partition on it (._dedup_folded).
    # Merge those shadows into the surface set so the verdict passes (cross-module, taint, guard-attribution)
    # band EVERY raw sink; install_report.collapse_dedup_to_worst_band (after guard-attribution) then folds each
    # partition back to ONE display row — the WORST-BANDED member — so a folded sibling can never lower the
    # band on ANY axis. Off-partition surfaces (regex-fallback etc.) carry no ._dedup_folded and are untouched.
    _folded_shadows = []
    for _s in scan["surfaces"]:
        _fs = getattr(_s, "_dedup_folded", None)
        if _fs:
            _folded_shadows.extend(_fs)
            _s._dedup_folded = None
    if _folded_shadows:
        scan["surfaces"].extend(_folded_shadows)
    _emit(phase="reach", start=True, total=len(scan["surfaces"]))
    guard_detector.attach_test_evidence(scan["surfaces"], root)
    # S8 SPEED: build the whole-repo call graph ONCE and share it across cross_module, inter_taint,
    # guard_attribution and entrypoint_proof (was built 3x per scan — ~2/3 of the graph-parse cost gone).
    _shared_graphs, _shared_m2f = None, None
    try:
        from .cross_module import build_graphs, _all_py_rel, build_mod2files
        _shared_graphs = build_graphs(root, _all_py_rel(root), progress=progress)
        _shared_m2f = build_mod2files(_shared_graphs)
    except Exception:
        _shared_graphs, _shared_m2f = None, None
    # P2.9C: conservative cross-module guard-proof post-pass (may upgrade unproven criticals).
    try:
        from . import cross_module
        _emit(phase="reach", step="cross-module")
        rel_paths = sorted({s.file_path for s in scan["surfaces"]})
        scan["cross_module_upgraded"] = cross_module.apply(root, scan["surfaces"], rel_paths, _shared_graphs, _shared_m2f)
    except Exception:
        scan["cross_module_upgraded"] = 0
    for s in scan["surfaces"]:
        surface_classifier.classify(s)
    # S6.1: generalised guard-attribution — the deterministic severity fix (fixes the S5.0
    # feed-scout-vs-autosend inversion). Runs on EVERY prod critical surface, not just modelled helpers;
    # sets severity_rank + a downgrade-only verdict so an UNGUARDED live sink outranks a guarded one.
    _ga_graphs = None
    try:
        from . import guard_attribution
        from .cross_module import build_graphs, _all_py_rel
        _ga_graphs = _shared_graphs if _shared_graphs is not None else build_graphs(root, _all_py_rel(root))
        # S8 inter-procedural taint: upgrade tainted_reachable for CROSS-FUNCTION-reachable sinks BEFORE
        # guard-attribution reads the tainted axis -> turns "N dangerous surfaces" into "X an injected
        # prompt can ACTUALLY reach unguarded". Upgrade-only, fail-open to the intra-function bit.
        try:
            from . import inter_taint
            from .cross_module import build_mod2files
            _it_m2f = _shared_m2f if _shared_m2f is not None else build_mod2files(_ga_graphs)
            _emit(phase="reach", step="taint")
            scan["inter_taint_counts"] = inter_taint.apply(root, scan["surfaces"], _ga_graphs, _it_m2f)
        except Exception as _it_err:
            import sys as _s2
            print(f"WARNING: inter_taint FAILED ({_it_err}); intra-function taint stands", file=_s2.stderr)
            scan["inter_taint_counts"] = {"error": str(_it_err)[:200]}
        scan["guard_attribution_counts"] = guard_attribution.apply(root, scan["surfaces"], _ga_graphs, progress=progress)
    except Exception as _ga_err:
        # code-review: do NOT fail silently — a swallowed error no-ops the whole severity fix and leaves
        # every surface at the least-severe default. Record it loudly so the failure is visible.
        import sys as _sys
        print(f"WARNING: guard_attribution pass FAILED ({_ga_err}); severity ranking not applied", file=_sys.stderr)
        scan["guard_attribution_counts"] = {"error": str(_ga_err)}
    # STRUCTURAL dedup collapse (Fable-5 band-suppression class): every raw sink of each dedup partition now
    # carries its TRUE post-guard-attribution band, so fold each partition to its WORST-BANDED member. Runs
    # BEFORE entrypoint_proof / guard_integrity / the live HUD / build_report so they all see the one-row-per-
    # partition set (identical to before) — only the survivor's band is now provably the max over all raw
    # members. Runs UNCONDITIONALLY (even on a guard_attribution failure) so the merged shadows never leak into
    # the reported surface set as over-counted duplicate rows. Band-complete here: entrypoint_proof /
    # guard_integrity never escalate to the band-driving verdicts (UNGUARDED_CRITICAL_LIVE_SINK /
    # CONFIG_DESTINATION_WRITE_REVIEW), so no later pass can raise a folded sibling above the chosen survivor.
    from . import install_report as _IR_collapse
    scan["dedup_collapse"] = _IR_collapse.collapse_dedup_to_worst_band(scan["surfaces"])
    # P2.9F: reviewed real-entrypoint proof for modelled public helpers (runs AFTER classify; it sets
    # the final verdict directly for modelled helpers).
    try:
        from . import entrypoint_proof
        scan["entrypoint_patch_items"] = []
        scan["entrypoint_counts"] = entrypoint_proof.apply(root, scan["surfaces"], scan["entrypoint_patch_items"], graphs=_shared_graphs)
    except Exception:
        scan["entrypoint_counts"] = {}
    # Stage 1.5: guard-integrity — annotate every PROVEN surface with whether its control can actually
    # BLOCK (block-path present) or looks like a no-op/fail-open stub. Advisory; flags suspicious gates.
    try:
        from . import guard_integrity
        scan["guard_integrity_counts"] = guard_integrity.annotate(root, scan["surfaces"])
    except Exception:
        scan["guard_integrity_counts"] = {}
    # Stream a handful of the REAL reachable-live findings as the payoff of the trace. HONESTY INVARIANT
    # (live_scan.py:22-24): the red "reachable & unguarded" stream must be driven by the SAME deterministic
    # predicate as the report's non_gated_vulnerable count — NOT by the raw verdict alone. A raw
    # UNGUARDED_CRITICAL_LIVE_SINK is written by guard_attribution onto ANY prod+tainted+unguarded
    # CRITICAL_CAPS surface (a broader set than install_report._VULN_CAPS), so filtering on the verdict alone
    # let the HUD flash red for a surface the finale correctly resolves to BLUE. install_report
    # .is_non_gated_vulnerable is that one shared predicate (static + prod + cap ∈ _VULN_CAPS + verdict).
    if progress:
        from . import install_report as _IR
        _live = [s for s in scan["surfaces"]
                 if _IR.is_non_gated_vulnerable(s)][:6]
        for _s in _live:
            _emit(phase="reach", live=(_s.capability, _s.file_path,
                                       getattr(_s, "sink_line", 0) or _s.line_start))
    _emit(phase="reach", done=True, total=len(scan["surfaces"]))

    # S2.4: AI-assist tier — flag-gated (HERMES_SHIELD_AI_TIER=1), residual-only, budget-capped, cached.
    # Appends model-proposed AST-verified surfaces as a SEPARATE ai_suspected tier; never touches the
    # static headline. Off by default so the deterministic scan is unchanged unless explicitly enabled.
    scan["ai_tier_counts"] = {}
    if os.getenv("HERMES_SHIELD_AI_TIER") == "1":
        try:
            from . import ai_tier, ai_backends
            budget = int(os.getenv("HERMES_SHIELD_AI_TIER_BUDGET", "120"))
            model = os.getenv("HERMES_SHIELD_AI_TIER_MODEL") or None
            # Backend selection (shared AI backend layer, first slice): HERMES_SHIELD_AI_BACKEND picks the
            # propose() transport. Unset => "claude" => ai_assist.claude_agent VERBATIM, i.e. byte-identical
            # to today's default AI path. Redaction + size-cap run INSIDE analyze_source, so every backend
            # threaded through this seam is protected for free.
            backend_id = os.getenv("HERMES_SHIELD_AI_BACKEND") or "claude"
            agent = ai_backends.get_backend(backend_id, model=model)
            # backend_id is threaded into the AI cache key (ai_tier) so a cache warmed by one backend can
            # never silently replay for another — cross-backend provenance stays isolated.
            scan["ai_tier_counts"] = ai_tier.apply(root, scan["surfaces"], budget=budget, model=model,
                                                   agent=agent, cache_dir=out_dir, backend_id=backend_id)
            # S8.83 GAP-2 CAPABILITY NORMALISATION: AI findings carry hyphen/free-text caps (tool-invoke,
            # code-execution, file-write...) that never match the engine's canonical underscore vocabulary
            # (PAT.CRITICAL_CAPS / install_report._RCE_CAPS|_ACT_CAPS), so a reachable AI surface could never
            # be rated. Conservatively map clear caps to canonical; LEAVE ambiguous ones (db-write,
            # network-fetch, dynamic-dispatch) non-canonical (no force-fit). MUST run before classify +
            # guard-attribution + install_report so the canonical cap drives every downstream gate.
            try:
                from . import cap_normalise
                scan["ai_cap_normalisation"] = cap_normalise.apply_to_surfaces(scan["surfaces"])
            except Exception as _cn_err:
                scan["ai_cap_normalisation"] = {"error": str(_cn_err)[:200]}
            # S8.81 "AI SUGGESTS, ENGINE PROVES": give AI-found surfaces the SAME reachability disposition as
            # static — classify + cross-module + inter-procedural taint (sets tainted_reachable) + entrypoint
            # grounding + guard-attribution — so a detected AI sink can be PROVEN reachable+unguarded (or
            # correctly left as install-liability), not stranded as "detected". The old S7.3 pass ran only
            # classify + guard-attribution, so AI surfaces never got tainted_reachable and could never become
            # UNGUARDED_CRITICAL — the reachability bug. This closes it in the pipeline (survives extraction).
            for s in scan["surfaces"]:
                if getattr(s, "detection_source", "static") != "static":
                    surface_classifier.classify(s)
                    # HONESTY INVARIANT: classify() sets scope/mutating and (for an unguarded critical) a
                    # DETERMINISTIC verdict such as BLOCK_LIVE_PROMOTION. That verdict must never stick on a
                    # model GUESS — it would leak into the deterministic headline. We keep the reachability
                    # disposition classify computed but RESTORE the advisory verdict, so guard_attribution /
                    # entrypoint_proof (which now skip non-static surfaces) leave it as AI_SUSPECTED_REVIEW.
                    s.verdict = "AI_SUSPECTED_REVIEW"
                    s.live_promotion_verdict = "REVIEW"
            if _ga_graphs is not None:
                from . import cross_module as _CM, inter_taint as _IT, entrypoint_proof as _EP
                _m2f = _shared_m2f
                if _m2f is None:
                    try:
                        from .cross_module import build_mod2files as _bm2f
                        _m2f = _bm2f(_ga_graphs)
                    except Exception:
                        _m2f = None
                _rel = sorted({s.file_path for s in scan["surfaces"]})
                # S8.82 (CTO review #5): MIRROR the first-pass order — CM -> IT -> guard_attribution -> EP
                # (the first pass runs GA at L106 THEN EP at L118). The old re-run ran EP before GA, which,
                # because GA does not defer to EP's proof, could flip a static surface's verdict between the
                # AI-ON and AI-OFF pipelines. entrypoint_proof is idempotent on patch_items (dedups by
                # surface_id), so the shared list cannot accrue duplicates across the two passes.
                for _step in (
                    lambda: _CM.apply(root, scan["surfaces"], _rel, _ga_graphs, _m2f),
                    lambda: _IT.apply(root, scan["surfaces"], _ga_graphs, _m2f),
                    lambda: guard_attribution.apply(root, scan["surfaces"], _ga_graphs),
                    lambda: _EP.apply(root, scan["surfaces"], scan.get("entrypoint_patch_items", []), graphs=_ga_graphs),
                ):
                    try:
                        _step()
                    except Exception:
                        pass
            else:
                try:
                    guard_attribution.apply(root, scan["surfaces"], _ga_graphs)
                except Exception:
                    pass
        except Exception as e:
            scan["ai_tier_counts"] = {"ai_error": str(e)[:200]}

    # S8.90: dependency-aware tier — flag-gated (HERMES_SHIELD_DEPS=1), network, opt-in. Fetches the repo's
    # OWN pinned first-party packages (never third-party), scans capability packages with this same engine,
    # and reports their findings in a SEPARATE `install-inherited-via-dependency` tier — never merged into
    # the tree headline. Closes the coverage gap where a repo relocates its dangerous capability into a
    # pinned dep that is not in the git tree. The recursion guard stops a nested scan from re-triggering the
    # dep tier. Off by default; fail-open.
    scan["dep_scan"] = {}
    if os.getenv("HERMES_SHIELD_DEPS") == "1" and not os.getenv("_HERMES_SHIELD_IN_DEP_SCAN"):
        try:
            from . import dep_scan
            scan["dep_scan"] = dep_scan.apply(root)
        except Exception as _dep_err:
            scan["dep_scan"] = {"error": str(_dep_err)[:200]}
    return scan


def _matrix_rows(scan):
    # aggregate by (lane, capability) for prod surfaces
    rows = []
    seen = {}
    for s in scan["surfaces"]:
        if s.context != "prod":
            continue
        key = (s.likely_lane, s.capability)
        if key in seen:
            continue
        seen[key] = True
        g = s.guards
        rows.append([s.likely_lane, s.capability,
                     "yes" if any(i.file_path == s.file_path for i in scan["ingresses"]) else "-",
                     s.live_capable, _b(g.kill_switch), _b(g.final_action_gate), _b(g.untrusted_fence),
                     _b(g.strict_hash), _b(g.dry_run), _b(g.human_approval), _b(g.csrf_token),
                     _b(g.certified), "yes" if s.tests.test_files else "-", s.scope, s.verdict])
    return sorted(rows, key=lambda r: (r[0], r[1]))


def _b(v):
    return "yes" if v else "-"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Hermes Shield MVP-1A read-only self-scan")
    ap.add_argument("--scan", action="store_true")
    ap.add_argument("--baseline", action="store_true")
    ap.add_argument("--diff", action="store_true")
    ap.add_argument("--root", default=None)
    ap.add_argument("--out", default=None,
                    help="output directory for scan artefacts (default: ./shield-report/ in the CWD). "
                         "Env: HERMES_SHIELD_OUT.")
    # Phase-1 PROVEN-LIVE self-attack lane. Consent-gated, OFF by default; when OFF the scan is byte-identical.
    ap.add_argument("--prove", action="store_true",
                    help="after the read-only scan, EXECUTE the drivable candidate RCE sinks in a sandbox to "
                         "prove they are live (benign canary, no network). Consent-gated; OFF by default.")
    ap.add_argument("--yes-execute-my-code", dest="yes_execute", action="store_true",
                    help="non-interactive consent for --prove (also: HERMES_SHIELD_PROVE_CONSENT=1)")
    # S8.94: opt-in cinematic live experience. Purely ADDITIVE — without --live the scan output is
    # byte-for-byte today's behaviour. On a TTY it streams a sticky HUD + the honest collapse + verdict;
    # off a TTY it emits stderr checkpoints and leaves stdout clean.
    ap.add_argument("--live", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    root = Path(args.root).resolve() if args.root else current_repo_root()
    out_dir, baseline_path = resolve_out_paths(root, args.out)

    # --prove: LOUD warning + consent gate BEFORE anything executes. The static scan itself is read-only
    # (always safe); execution only happens in the prove lane AFTER the scan. Without consent we still run
    # the read-only scan (the primary product) and simply skip the lane — nothing is ever executed.
    prove_ok = False
    if getattr(args, "prove", False):
        from . import prove as _PV
        sys.stderr.write(_PV.LOUD_WARNING)
        sys.stderr.flush()
        prove_ok = _PV.consent_granted(getattr(args, "yes_execute", False))
        if not prove_ok:
            print("hermes-shield: prove-live NOT confirmed — running the READ-ONLY scan only (no code "
                  "executed). Pass --yes-execute-my-code or set HERMES_SHIELD_PROVE_CONSENT=1 to enable it.",
                  file=sys.stderr)
    # S8.91/S8.92: branded banner + live progress. Cosmetic only (suppressed by --quiet / NO_COLOR /
    # HERMES_SHIELD_NO_BANNER; a spinner only animates on a TTY) — they never affect the scan or its numbers.
    _tiers = {"ai": os.getenv("HERMES_SHIELD_AI_TIER") == "1",
              "semgrep": os.getenv("HERMES_SHIELD_SEMGREP") == "1",
              "deps": os.getenv("HERMES_SHIELD_DEPS") == "1"}
    live = getattr(args, "live", False)
    _run_fn = lambda progress=None: run_scan(root, progress=progress, out_dir=out_dir)
    if args.quiet:
        # --quiet is quiet whether or not --live is set (the one-line verdict prints after the scan).
        scan = run_scan(root, out_dir=out_dir)
    elif live:
        # S8.94 opt-in cinematic path — sticky HUD on a TTY, stderr checkpoints off a TTY. Ctrl-C tears the
        # region down cleanly and exits 130; the deterministic scan + artefacts are otherwise untouched.
        from . import banner, live_scan as _LV
        banner.print_banner(SCANNER_VERSION, tiers=_tiers, target=f"~/{root.name}")
        try:
            scan = _LV.stream_live(_run_fn, tiers=_tiers)
        except KeyboardInterrupt:
            sys.stderr.write("\nscan interrupted\n")
            return 130
    else:
        from . import banner, stream as _ST
        banner.print_banner(SCANNER_VERSION, tiers=_tiers, target=f"~/{root.name}")
        scan = _ST.stream_scan(_run_fn)
    head = _head(root)
    scan_time = _now()

    prod = [s for s in scan["surfaces"] if s.context == "prod"]
    # Deterministic CLI summary counts static findings only — belt-and-braces so a re-stamped
    # AI-suspected surface can never inflate the printed verdict distribution or BLOCK count
    # (the writer-side reset already keeps AI surfaces at AI_SUSPECTED_REVIEW; this is defence-in-depth).
    _static_prod = [s for s in prod if getattr(s, "detection_source", "static") == "static"]
    verdicts = Counter(s.verdict for s in _static_prod)
    # BLOCK-COUNTER RECONCILIATION: agree with patch_plan.build + dashboard_export — an amber-capability
    # UNGUARDED_CRITICAL_LIVE_SINK (post/reply/like ...) is a reachable-action REVIEW, not a hard block.
    # is_non_gated_vulnerable is the shared predicate (static + prod + cap ∈ _VULN_CAPS + verdict).
    from . import install_report as _IR
    block = [s for s in _static_prod
             if s.verdict in ("BLOCK_LIVE_PROMOTION", "GUARD_LOST") or _IR.is_non_gated_vulnerable(s)]

    overall_drift, drift_findings = "NO_DRIFT", []
    baseline_status = "absent"
    if args.diff:
        base = BL.load_baseline(baseline_path)
        baseline_status = "present" if base else "absent"
        overall_drift, drift_findings = DR.diff(base, scan)

    patch_items = patch_plan.build(prod)

    # --prove (Phase 1): with consent, run the PROVEN-LIVE self-attack lane over the REAL scanned repo as a
    # sandboxed target (--ro-bind read-only). PROMOTE-ONLY: it fills `validated` and never mutates the scan,
    # so every base number above stays byte-identical; it only ADDS proven-live promotions to the reports
    # below. Only the Phase-0 provable set (code_exec, ssti) auto-runs; everything else is refused-recipe
    # (still a real candidate, never "safe"). Evidence lands under the operator out dir (never the target).
    validated, prove_records = set(), []
    if prove_ok and (args.scan or args.diff):
        from . import prove as _PV
        out_dir.mkdir(parents=True, exist_ok=True)
        validated, prove_records = _PV.run_lane(root, scan, out_dir=out_dir)

    if args.scan or args.diff:
        out_dir.mkdir(parents=True, exist_ok=True)
        RW.write_json({"root": str(root), "head": head, "scan_time": scan_time,
                       "files_scanned": scan["files_scanned"], "scanner_version": SCANNER_VERSION,
                       "surfaces": [s.to_dict() for s in scan["surfaces"]],
                       "ingresses": [i.to_dict() for i in scan["ingresses"]]},
                      out_dir / "hermes_action_surface_scan.json")
        RW.write_json({"rows": _matrix_rows(scan)}, out_dir / "hermes_lane_protection_matrix.json")
        RW.write_json([p.to_dict() for p in patch_items], out_dir / "hermes_patch_plan.json")
        RW.write_json(dashboard_export.build(scan, overall_drift, drift_findings, patch_items,
                                             baseline_status, scan_time),
                      out_dir / "hermes_shield_dashboard_export.json")
        # S8.76 P1 WIRE-IN: emit the OWASP-rated report (was BUILT-not-wired; the pipeline never rated a scan).
        from . import install_report as _IR
        _report = _IR.build_report(root, scan, validated)
        RW.write_json(_report, out_dir / "hermes_shield_report.json")
        (out_dir / "hermes_shield_report.md").write_text(_IR.render(_report), encoding="utf-8")
        # S8.88 WIRE-IN: emit the customer/auditor-facing multi-report (Gate #5) — was BUILT-not-wired.
        # Carries the mandatory honest caveats (install-liability = inert here / proven-live=0 = not
        # demonstrated). Deferred import: scan_hermes is fully loaded here, so shield_report's top-level
        # `from . import scan_hermes` binds the already-loaded module (no circular import).
        from . import shield_report as _SR
        (out_dir / "shield_customer_report.md").write_text(_SR.build_report(scan, root.name, validated, root=root), encoding="utf-8")
        (out_dir / "shield_customer_report.html").write_text(_SR.build_html(scan, root.name, root, validated), encoding="utf-8")
        # S8.89 WIRE-IN: isolated, ATTRIBUTED semgrep-classic comparator (Gate #4 external benchmark).
        # Flag-gated (HERMES_SHIELD_SEMGREP=1) so the default offline scan is byte-identical. Semgrep runs
        # in an isolated venv (NEVER the Hermes python) and its findings are NEVER merged into our headline —
        # they stay in the `semgrep-classic` tier. Fail-open: a bonus comparator never blocks our own scan.
        if os.getenv("HERMES_SHIELD_SEMGREP") == "1":
            try:
                from . import semgrep_runner as _SG
                _sem_dir = out_dir / "semgrep"
                _sem = _SG.run(root, _sem_dir, mode=os.getenv("HERMES_SHIELD_SEMGREP_MODE", "venv"))
                _findings = _sem.get("findings", [])
                _note = _SG.head_to_head(scan["surfaces"], _findings,
                                         hermes_proven=_report.get("proven_live_poc", 0),
                                         hermes_non_gated=_report.get("non_gated_vulnerable", 0))
                _sem_dir.mkdir(parents=True, exist_ok=True)
                (_sem_dir / "semgrep_head_to_head.md").write_text(_note, encoding="utf-8")
                RW.write_json({"tier": "semgrep-classic", "merged_into_headline": False,
                               "comparator": _SG.merge_attribute(scan["surfaces"], _findings),
                               "semgrep": _sem},
                              _sem_dir / "semgrep_comparator.json")
                # HS-04: the comparator tier is always attributed to a concrete semgrep version
                # (pinned docker image ref, or the venv/uvx binary's --version).
                scan["semgrep_counts"] = {"findings": len(_findings),
                                          "comparator_version": _sem.get("comparator_version", "unknown")}
            except Exception as _sg_err:
                scan["semgrep_counts"] = {"error": str(_sg_err)[:200]}
        # S8.90: emit the dependency-inherited tier artefact (only when the tier ran). Separate file so it
        # is never confused with the tree headline; carries the per-package triage + attributed counts.
        _dep = scan.get("dep_scan") or {}
        if _dep and not _dep.get("error"):
            RW.write_json(_dep, out_dir / "hermes_dep_inherited.json")
    if args.diff:
        RW.write_json({"overall": overall_drift, "findings": [d.to_dict() for d in drift_findings]},
                      out_dir / "hermes_drift_findings.json")
    if args.baseline:
        BL.save_baseline(BL.build_baseline(scan, head), baseline_path)

    # --live --quiet: exactly one honest verdict line + the report path (default --quiet stays silent).
    if args.quiet and live and (args.scan or args.diff):
        from . import install_report as _IR, live_scan as _LV
        _LV.render_quiet(_IR.build_report(root, scan, validated), scan, out_dir)

    if not args.quiet:
        from . import summary as _SM
        # --live on a TTY: the cinematic collapse + RED/AMBER/BLUE verdict + point-first block + Repairer
        # hand-off. Keyed on isatty (NOT colour) so NO_COLOR keeps the glyphs; off a TTY it falls through to
        # the terse stdout lines below (stdout stays clean, JSON-safe).
        from . import live_scan as _LV
        if live and _LV._tty(sys.stdout) and (args.scan or args.diff):
            from . import install_report as _IR
            _r = _IR.build_report(root, scan, validated)
            _LV.render_collapse(_r, scan)
            _LV.render_finale(_r, scan, out_dir, SCANNER_VERSION)
        # Default (no --live) on a TTY: the rich results panel (the demo "results landed" moment).
        elif _SM._colour(sys.stdout) and (args.scan or args.diff):
            from . import install_report as _IR
            # Phase 3/3: rating (fast) — a final beat so the OWASP verdict has a visible step of its own.
            print(f"  \033[38;5;208m▸ 3/3  Rating against OWASP LLM06 · Excessive Agency\033[0m")
            _r = _IR.build_report(root, scan, validated)
            print(f"  \033[38;5;71m✓\033[0m \033[1mVerdict computed\033[0m")
            print(_SM.render_results(_r, scan, out_dir, SCANNER_VERSION, colour=True))
        else:
            print(f"[shield-scan {SCANNER_VERSION}] root={root.name} head={head} files={scan['files_scanned']}")
            print(f"  surfaces={len(scan['surfaces'])} (prod={len(prod)}) ingresses={len(scan['ingresses'])}")
            print(f"  verdicts={dict(verdicts)}")
            print(f"  BLOCK_LIVE_PROMOTION={len(block)} patch_items={len(patch_items)} drift={overall_drift}({len(drift_findings)})")
            if args.scan or args.diff:
                from . import install_report as _IR
                _r = _IR.build_report(root, scan, validated)
                print(f"  OWASP rating (proven-live): {_r['overall_rating']} · candidate-High: {_r['candidate_high']} · "
                      f"non-gated: {_r['non_gated_vulnerable']} · coverage: {_r['coverage_pct']}%")
    # --prove: a clear, honest separation of PROVEN-LIVE vs CANDIDATE vs refused-recipe. A refused finding
    # is STILL A REAL CANDIDATE (the lane declined to auto-execute it — non-drivable / non-Python / outside
    # the provable set), never "safe". Only printed when the lane actually ran (consent granted).
    if prove_ok and (args.scan or args.diff) and not args.quiet:
        from . import prove as _PV
        _proven = [r for r in prove_records if r.get("verdict") == "proven"]
        _inconcl = [r for r in prove_records if r.get("verdict") == "inconclusive"]
        _refused = [r for r in prove_records if r.get("verdict") == "refused-recipe"]
        print("")
        print(f"[shield-prove] backend={_PV.isolation_backend()} — PROVEN-LIVE self-attack lane (Phase 1)")
        print(f"  PROVEN-LIVE (nonce fired via sink · negative-control clean · reproduced): {len(_proven)}")
        for r in _proven:
            print(f"   - [PROVEN ] {r['file']}:{r['sink_line']} [{r['capability']}]")
        print(f"  CANDIDATE (scanner-flagged, NOT proven — inconclusive proof): {len(_inconcl)}")
        print(f"  REFUSED-RECIPE (not auto-run: non-drivable / non-Python / outside provable set): {len(_refused)}")
        print("  NOTE: a refused finding is STILL A REAL CANDIDATE (never 'safe') — it just needs a manual "
              "PoC. PROMOTE-ONLY: proofs only ADD proven-live; no base scan number changed.")
        print(f"  evidence: {out_dir / 'prove'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
