"""
ai_finder.py (S7.4) — whole-repo AGENTIC AI finder (AI-first, model-agnostic).

The best model (default Claude Fable 5) reads ACROSS the repo via read-only Read/Grep/Glob tools, seeded by
the deterministic repo_map + static's findings (diff-against-static), to find the agent-plumbing surfaces
static structurally misses (tool.invoke gateways, cross-file delegation, dynamic dispatch). This is the
"AI proposes" half; every finding is then run through ai_verify ("deterministic disposes") so a stronger
finder yields more recall but can NEVER fabricate past the AST gate.

SAFETY: the finder gets ONLY Read/Grep/Glob on the target repo — no Write, no Bash, no network. It can find,
it cannot act. Model is a config seam (HERMES_SHIELD_FINDER_MODEL) so Fable 5 / Opus 4.8 / Sonnet 5 compete
in the autoresearch loop; the winner becomes the default.
"""
from __future__ import annotations
import json
import re
import subprocess
from pathlib import Path
from typing import List, Optional

from . import repo_map as RM
from . import ai_verify

_SYSTEM = '''You are a security auditor finding DANGEROUS ACTION-SURFACES in an AI-agent codebase — calls a
prompt-injected agent could be tricked into abusing: execute code/commands (eval/exec/subprocess/shell),
deserialize UNTRUSTED data (pickle/yaml.load), invoke an LLM-CHOSEN tool (tool.invoke / tool.run / _run /
call_tool / registry[name]() / agent.execute_task / delegate), dynamically import a NON-CONSTANT module or
attribute, WRITE/DELETE files/DB/vector-store, send/exfiltrate (post/dm/email/upload/requests.post), or move
money.

Read ACROSS files — that is the whole point: trace a `tool.invoke` to where the tool registry is populated;
enumerate every tool-like class's `_run`/`execute`/`run`; follow imports up a few hops. Use your Read, Grep
and Glob tools to explore the repo (your CWD).

A deterministic scanner has ALREADY found the surfaces listed under STATIC-FOUND below. Report ONLY what it
MISSED — the semantic agent-plumbing it has no signature for. If everything dangerous is already covered,
output [].

Output STRICT JSON ONLY — a list of:
{"file": "<repo-relative path>", "line": <int 1-based>, "call": "<the exact call expression as written>",
 "capability": "<short kind>", "why": "<one line>", "evidence_path": ["file:line", "file:line", ...],
 "confidence": <0.0-1.0>}
`evidence_path` is the chain of locations you followed to justify it (mandatory — a human must be able to
retrace every finding). No prose, no markdown fences.'''


def _static_summary(static_surfaces) -> str:
    if not static_surfaces:
        return "(none provided — report all dangerous action-surfaces you find)"
    by_file = {}
    for s in static_surfaces:
        fp = getattr(s, "file_path", None) or (s.get("file") if isinstance(s, dict) else None)
        ln = getattr(s, "line_start", None) or (s.get("line") if isinstance(s, dict) else None)
        cap = getattr(s, "capability", None) or (s.get("capability") if isinstance(s, dict) else "")
        if fp:
            by_file.setdefault(fp, []).append(f"{ln}:{cap}")
    return "\n".join(f"  {fp}: {', '.join(v[:20])}" for fp, v in list(by_file.items())[:200])


def _finder_agent(model: str, timeout: int):
    """Agentic backend via the local claude CLI with READ-ONLY tools, CWD scoped to the target repo."""
    def run(prompt: str, cwd: str) -> str:
        cmd = ["claude", "-p", prompt, "--model", model, "--allowedTools", "Read,Grep,Glob"]
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd).stdout or ""
        except Exception:
            return ""
    return run


def _parse(raw: str) -> List[dict]:
    m = re.search(r"\[.*\]", raw, re.DOTALL)
    if not m:
        return []
    try:
        data = json.loads(m.group(0))
    except Exception:
        return []
    out = []
    for d in data if isinstance(data, list) else []:
        if isinstance(d, dict) and d.get("file") and d.get("call"):
            out.append(d)
    return out


def find(repo_root, static_surfaces=None, model: Optional[str] = None, timeout: int = 600,
         agent=None) -> dict:
    """Run the whole-repo agentic finder + verify. Returns verified findings + the fabrication rate.
    model defaults to HERMES_SHIELD_FINDER_MODEL or claude-fable-5 (the seam the autoresearch loop tunes)."""
    import os
    root = Path(repo_root)
    model = model or os.getenv("HERMES_SHIELD_FINDER_MODEL") or "claude-fable-5"
    rmap = RM.build_repo_map(root)
    prompt = (_SYSTEM
              + "\n\n# REPO MAP (orient from this, then Read/Grep the interesting files):\n"
              + RM.render_compact(rmap)
              + "\n\n# STATIC-FOUND (report ONLY what static missed):\n"
              + _static_summary(static_surfaces or []))
    run = agent or _finder_agent(model, timeout)
    raw = run(prompt, str(root))
    proposed = _parse(raw)
    verified = ai_verify.verify_findings(root, proposed)
    return {"model": model, "verified": verified, "n_proposed": len(proposed),
            "n_verified": len(verified),
            "fabrication_rate": round(ai_verify.fabrication_rate(len(proposed), len(verified)), 3)}
