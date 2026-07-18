"""
Hermes Shield — AI-assist TIER (S2.4). Wires the model-agnostic AI layer into the REAL scan as a
flag-gated, RESIDUAL-only, budget-capped, SHA-cached `ai_suspected` tier.

Discipline (per the CTO/integrity panel):
- RESIDUAL ONLY: the coding agent runs only on prod files the static engine found NOTHING dangerous in
  (where a novel sink could hide) — never where static already won (no double-count, no wasted budget).
- BUDGET-CAPPED: at most `budget` LLM calls per scan (a repo can be ~11k files; this keeps it affordable).
- SHA-CACHED: keyed on (file_sha256, model, prompt_version) with the raw findings persisted, so re-scans
  are near-free and byte-reproducible given the cache (the AST gate downstream is deterministic).
- SEPARATE TIER: every AI finding becomes an ActionSurface with detection_source='ai_suspected'
  (or 'ai_corroborated' when static's own classifier also fires on the callee) and verdict
  AI_SUSPECTED_REVIEW — it is NEVER folded into the static concrete-recall headline.

Enabled by env HERMES_SHIELD_AI_TIER=1 (default OFF). Read-only: sends code text to the pluggable agent,
statically verifies the JSON it returns, executes nothing.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
from pathlib import Path

from . import ai_assist, repo_scanner
from .models import ActionSurface

PROMPT_VERSION = "v3"   # v3 = HS-03: secret redaction + untrusted-data delimiters + size cap (cache key only)
# only spend an LLM call on a zero-finding file that at least LOOKS like it could act (cheap prefilter)
_RISK_HINT = re.compile(
    r"\b(subprocess|os\.|requests|httpx|urllib|socket|pickle|marshal|yaml|paramiko|fabric|asyncssh|boto3|"
    r"docker|kubernetes|redis|pymongo|neo4j|smtplib|kafka|pika|paho|torch|joblib|numpy|pandas|"
    r"eval|exec|__import__|getattr|Template|Popen|\.system|autogen|crewai|langchain|dspy|guidance|"
    r"haystack|upload|deserial|\.load\(|\.run\(|\.send\()", re.I)
# HIGH-PRIORITY agent-plumbing signals (verifier fix): guarantee these files get budget FIRST, before the
# hundreds of low-value utility files - that's where the tool-dispatch / MCP / delegation / dynamic-import
# surfaces static misses actually live.
_PLUMBING_HINT = re.compile(
    r"tool\.invoke|tool\.run|\.call_tool|register_tool|@tool|tool_execution_map|available_functions|"
    r"initiate_chat|\.kickoff|delegat|import_module|exec_module|attrgetter|__import__|BaseTool|"
    r"class \w*Tool\b|def _run\b|StdioServerParameters|AsyncClient|\.send\(", re.I)


def _target_files(root: Path, surfaces, limit: int):
    """COVERAGE FIX (S2.9): files worth an AI call = zero-finding files FIRST (highest novel potential),
    THEN files static already surfaced — because agent-plumbing sinks (the tool.invoke gateway, MCP,
    A2A delegation) hide in files flagged for OTHER reasons, and the old residual-only tier skipped them
    entirely. Findings are deduped against static lines in apply() so no double-count. Risk-hint gated."""
    surfaced = {s.file_path for s in surfaces if s.context == "prod"}
    root_resolved = root.resolve()
    plumbing, zero, covered = [], [], []
    for p in repo_scanner._iter_py(root):
        # audit finding #2 (defence in depth): _iter_py already skips symlinks / out-of-root, but the
        # AI tier forwards file CONTENT to the local `claude` CLI, so re-assert containment here before any
        # read — a linked file that resolves outside the target root is never selected or disclosed.
        if not repo_scanner.within_root(p, root_resolved):
            continue
        try:
            rel = str(p.relative_to(root))
        except Exception:
            continue
        if repo_scanner._context(rel) != "prod":
            continue
        try:
            txt = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if _PLUMBING_HINT.search(txt):
            plumbing.append((rel, txt))            # agent-plumbing -> highest priority, guaranteed budget
        elif _RISK_HINT.search(txt):
            (covered if rel in surfaced else zero).append((rel, txt))
    # PLUMBING first (the surfaces static misses), then interleave zero-finding + other surfaced files.
    from itertools import zip_longest
    rest = []
    for z, c in zip_longest(zero, covered):
        if z is not None:
            rest.append(z)
        if c is not None:
            rest.append(c)
    return (plumbing + rest)[:limit]


def _safe_cache_path(cache_path: Path, allowed_base: Path = None):
    """audit finding #1 (CWE-59 link-following) — validate a cache path BEFORE any read/write.

    REJECT (return None, so the caller does NOT read or write) if:
      - the final path is a symlink (writing through it would clobber the link's target — the PoC), or
      - the parent directory is a symlink (it could redirect the whole write), or
      - an operator base is supplied and the cache path resolves OUTSIDE that operator-owned directory.
    We never write THROUGH a link. When `allowed_base` is given (the scan output dir), the cache must stay
    under it; when only an explicit operator-chosen path is given (e.g. tests/API), symlink-safety still
    applies but the operator's own directory choice is honoured."""
    try:
        if cache_path.is_symlink():
            return None
        parent = cache_path.parent
        if parent.exists() and parent.is_symlink():
            return None
        if allowed_base is not None:
            base = allowed_base.resolve()
            rparent = parent.resolve()
            if not (rparent == base or base in rparent.parents):
                return None
        return cache_path
    except OSError:
        return None


def _load_cache(cache_path: Path) -> dict:
    if cache_path is None:
        return {}
    if cache_path.exists():
        try:
            return json.loads(cache_path.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def _default_cache_dir(cache_dir):
    """Operator-owned cache location — NEVER derived from the (untrusted) target root (audit #1). Prefer
    the scan output dir threaded in by the caller; else the operator CWD's ./shield-report/outputs."""
    if cache_dir is not None:
        return Path(cache_dir)
    return Path.cwd() / "shield-report" / "outputs"


def apply(root: Path, surfaces, budget: int = 120, model=None, cache_path=None, agent=None,
          cache_dir=None, backend_id=None) -> dict:
    # audit #1: the cache lives under an OPERATOR-owned directory (the scan output dir), never under the
    # untrusted target `root`. An explicit cache_path (tests/API) is honoured but still symlink-validated.
    if cache_path is not None:
        cache_path = Path(cache_path)
        safe_cache = _safe_cache_path(cache_path)          # symlink-safety only; operator chose the path
    else:
        base = _default_cache_dir(cache_dir)
        cache_path = base / ".hermes_shield_ai_cache.json"
        safe_cache = _safe_cache_path(cache_path, allowed_base=base)
    cache = _load_cache(safe_cache)
    targets = _target_files(root, surfaces, budget)
    # DEDUP map: static surface lines per file — the AI tier only ADDS what static MISSED (no double-count)
    static_lines: dict = {}
    for s in surfaces:
        if s.context == "prod":
            static_lines.setdefault(s.file_path, set()).update(
                range(s.line_start, (s.line_end or s.line_start) + 1))
    # S8.82 CACHE-ONLY mode: when HERMES_SHIELD_AI_TIER_CACHE_ONLY=1, a cache MISS is SKIPPED rather than
    # sent to ai_assist.analyze_source — which is the only place that spawns the `claude -p` subprocess. This
    # guarantees NO subprocess (so it cannot hang: the do_wait freeze on several repos) while cache HITS still
    # replay exactly. Byte-identical behaviour when the flag is off (the else-branch below is unchanged).
    cache_only = os.getenv("HERMES_SHIELD_AI_TIER_CACHE_ONLY") == "1"
    # PROVENANCE: the cache key MUST include the backend id. Backends are now operator-selectable, so a cache
    # warmed by one backend (e.g. claude) must NOT replay for another (e.g. ollama) — that would let a broken/
    # absent backend report ai_status="ok" with ai_calls=0 (the silent-zero antipattern) and silently mix one
    # backend's findings into another's run. Distinct backend => distinct key => real call or honest failure.
    backend_key = (backend_id or "default").strip().lower()
    added = calls = corroborated = deduped = skipped_miss = 0
    ai_failure = None
    for rel, txt in targets:
        key = hashlib.sha256(
            f"{txt}|{model or 'default'}|{backend_key}|{PROMPT_VERSION}".encode()).hexdigest()
        if key in cache:
            findings = cache[key]
        elif cache_only:
            skipped_miss += 1
            continue
        else:
            # FAIL-LOUD, FAIL-OPEN: a broken agent backend (CLI missing / won't launch / times out) raises
            # AIAgentError. We record a VISIBLE per-tier failure and stop spending budget on a backend that
            # cannot answer — but never abort the deterministic scan (surfaces gathered so far are kept).
            try:
                findings = ai_assist.analyze_source(txt, model=model, agent=agent)
            except ai_assist.AIAgentError as e:
                ai_failure = e.reason
                break
            cache[key] = findings
            calls += 1
            if calls % 10 == 0 and safe_cache is not None:   # never write through a rejected/symlinked path
                safe_cache.write_text(json.dumps(cache), encoding="utf-8")
        for f in findings:
            ln = int(f.get("line", 0) or 0)
            if any(abs(ln - sl) <= 2 for sl in static_lines.get(rel, ())):  # static already found this line
                deduped += 1
                continue
            cap = str(f.get("capability", "ai_flagged"))[:40]
            src = "ai_corroborated" if f.get("tier") == "corroborated" else "ai_suspected"
            corroborated += src == "ai_corroborated"
            # S8.84 DEFENCE-IN-DEPTH: inherit the REAL path classification (demo/test/report/prod) instead
            # of hard-coding "prod". _target_files already yields only prod-classified files, so on today's
            # path this is byte-identical ("prod"); but if a demo/sample file ever reaches here it is no
            # longer mis-seeded as an attacker-reachable prod surface (sound-leaning: under-mark, never over).
            surf = ActionSurface(
                id=f"ai::{rel}::{f.get('line')}",
                file_path=rel, line_start=int(f.get("line", 0) or 0), line_end=int(f.get("line", 0) or 0),
                symbol="", capability=cap, context=repo_scanner._context(rel),
                sink_name=str(f.get("call", ""))[:80],
                detection_source=src, verdict="AI_SUSPECTED_REVIEW",
                ai_confidence=float(f.get("confidence", 0.0) or 0.0),
            )
            surf.stable_id = f"{rel}::<ai>::{cap}::{surf.sink_name}"
            surfaces.append(surf)
            added += 1
    # audit #1: only PERSIST when we made real AI calls (new cache entries) AND the path is symlink-safe.
    # Cache-only mode NEVER writes (a cache miss is a no-op) — this closes the arbitrary-write PoC where a
    # symlinked cache file was clobbered to `{}` even though no AI call was made.
    if calls > 0 and not cache_only and safe_cache is not None:
        safe_cache.write_text(json.dumps(cache), encoding="utf-8")
    out = {"ai_target_files": len(targets), "ai_calls": calls,
           "ai_surfaces_added": added, "ai_corroborated": corroborated, "ai_deduped_vs_static": deduped,
           "ai_budget": budget, "ai_model": model or "default",
           # per-tier health: "failed" is surfaced by the summary panel + customer report so a broken AI
           # tier can never masquerade as "AI ran and found nothing" (the old silent-zero bug).
           "ai_status": "failed" if ai_failure else "ok"}
    if ai_failure:
        out["ai_failure"] = ai_failure
    if cache_only:  # additive metric, only present in cache-only mode -> off-path stays byte-identical
        out["ai_cache_only"] = True
        out["ai_skipped_cache_miss"] = skipped_miss
    return out
