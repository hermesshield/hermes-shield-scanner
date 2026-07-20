"""
ai_finder.py (S7.4) — whole-repo AGENTIC AI finder (AI-first, model-agnostic).

The best model (default Claude Sonnet) reads ACROSS the repo via read-only Read/Grep/Glob tools, seeded by
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
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from . import repo_map as RM
from . import ai_verify
from . import ai_stream
from .ai_assist import AIAgentError

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


# A model content-refusal (AUP safeguard, "can't respond to this request", API-Error banner) is returned by
# the claude CLI on STDOUT with EXIT CODE 0. Without this the refusal prose falls through _parse (no JSON
# array) as [] and the tier records status="ok"/proposed=0 — the exact silent-zero antipattern this module
# exists to prevent ("backend refused" and "ran and found nothing" are different truths). These markers let
# _finder_agent detect an exit-0 refusal and raise AIAgentError so the wiring records a VISIBLE failed status.
_REFUSAL_MARKERS = (
    "safeguards flagged",
    "can't respond to this request",
    "cannot respond to this request",
    "usage policies",
    "usage policy",
    "https://www.anthropic.com/legal/aup",
)


def _json_array(raw: str):
    """Return the parsed list iff a bracketed span of `raw` PARSES as a JSON array, else None.

    This is the single arbiter of "did the backend actually emit a JSON array?" — it distinguishes a real
    (possibly empty) result from a refusal/prose that merely contains a stray bracket pair like `[x]`
    (which does not parse). Used by _is_refusal (FIX 3) and the nonzero-exit guard (FIX 2) so neither can
    be defeated by incidental brackets."""
    m = re.search(r"\[.*\]", raw, re.DOTALL)
    if not m:
        return None
    try:
        data = json.loads(m.group(0))
    except Exception:
        return None
    return data if isinstance(data, list) else None


def _is_toplevel_json_array(raw: str):
    """Return the parsed list iff `raw`, stripped, IS itself a JSON array — not merely a string that
    contains a bracketed span. This is the stricter arbiter used ONLY by the nonzero-exit guard: a backend
    that failed (exit != 0) is trusted as a genuine result only when its whole stdout is the array, so a
    JSON ERROR PAYLOAD such as `{"type":"error","errors":[],"message":"overloaded"}` (a rate-limit/overload
    failure) can no longer masquerade as an empty finding set via its embedded `[]`."""
    s = raw.strip()
    if not (s.startswith("[") and s.endswith("]")):
        return None
    try:
        data = json.loads(s)
    except Exception:
        return None
    return data if isinstance(data, list) else None


def _is_refusal(text: str) -> bool:
    """True iff the backend returned a content-refusal (no parseable JSON array + a refusal signature). A
    legitimate 'nothing found' reply (`[]` or terse prose without a signature) is NOT a refusal.

    FIX 3: a refusal is only defeated when the bracketed span genuinely PARSES as a JSON array — an empty
    `[]` or an array of finding objects. A refusal that happens to contain a stray `[x]` (which does not
    parse as JSON) still falls through to the refusal-marker check, so it is correctly detected."""
    if not text:
        return False
    arr = _json_array(text)
    if arr is not None and (not arr or any(
            isinstance(d, dict) and d.get("file") and d.get("call") for d in arr)):
        return False  # a parseable JSON array (empty, or real findings) — a result, not a refusal
    low = text.lower()
    return any(m in low for m in _REFUSAL_MARKERS)


def _finder_agent(model: str, timeout: int):
    """Agentic backend via the local claude CLI with READ-ONLY tools, CWD scoped to the target repo.

    FAIL-LOUD (mirrors ai_assist.claude_agent): the executable is resolved via shutil.which (so `claude.cmd`
    on Windows actually launches) and every failure raises AIAgentError with a human-readable reason — never
    a silent "". The old `except Exception: return ""` made a broken/absent backend look like "AI ran and
    found nothing", which is the exact silent-zero antipattern the finder must not have: nothing found and
    backend-broken are different truths and the operator must be told which one occurred. A model
    content-refusal returned on STDOUT with exit 0 is likewise raised (see _is_refusal), not swallowed."""
    def run(prompt: str, cwd: str) -> str:
        exe = shutil.which("claude")
        if not exe:
            raise AIAgentError("claude CLI not found on PATH — install it, or pass a custom finder agent")
        if ai_stream.feed_enabled():
            # TTY ONLY: divert to the DISPLAY-ONLY streaming layer — a live "→ Read/Grep …" feed + elapsed
            # clock on STDERR (via `claude --output-format stream-json --verbose`, else a spinner heartbeat)
            # so the finder never looks hung. It returns the SAME (stdout, returncode, stderr) triple
            # subprocess.run does — the accumulated final `result` text is byte-identical to `claude -p` —
            # so the fail-loud guards below are unchanged. stdout / the JSON artefacts are never touched.
            try:
                out, returncode, stderr = ai_stream.run_claude(
                    exe, prompt, model=model, cwd=cwd, timeout=timeout,
                    allowed_tools="Read,Grep,Glob",
                    banner=f"▶ AI finder · {model or 'default'} · reading across the repo…",
                    hb_label=f"AI finder · {model or 'default'}", prefer_stream=True)
            except subprocess.TimeoutExpired:
                raise AIAgentError(f"claude finder CLI timed out after {timeout}s")
            except AIAgentError:
                raise
            except Exception as e:
                raise AIAgentError(f"claude finder CLI failed to launch: {e.__class__.__name__}: {e}")
        else:
            # NON-TTY / piped / CI: the ORIGINAL blocking call, byte-identical to the pre-change path (this
            # is the code path tests and CI exercise). No progress is emitted anywhere.
            cmd = [exe, "-p", prompt, "--model", model, "--allowedTools", "Read,Grep,Glob"]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                                      errors="replace", timeout=timeout, cwd=cwd)
            except subprocess.TimeoutExpired:
                raise AIAgentError(f"claude finder CLI timed out after {timeout}s")
            except Exception as e:
                raise AIAgentError(f"claude finder CLI failed to launch: {e.__class__.__name__}: {e}")
            out, returncode, stderr = (proc.stdout or ""), proc.returncode, (proc.stderr or "")
        # FIX 2 (+ hardening): a nonzero exit is a failure UNLESS stdout IS a top-level JSON array. Previously
        # only an EMPTY stdout raised, so a nonzero exit carrying non-empty, non-JSON, non-refusal prose fell
        # through _parse -> [] -> status "ok" (a silent zero). Using the *embedded*-span check still let a JSON
        # error payload ({"...":[]}) at exit!=0 masquerade as an empty result, so the guard now requires a
        # top-level array: an overload/rate-limit error object fails loud; a genuine findings array still returns.
        if returncode != 0 and _is_toplevel_json_array(out) is None:
            tail = (stderr or out or "").strip().splitlines()
            detail = tail[-1][:160] if tail else "no output"
            raise AIAgentError(f"claude finder CLI exited {returncode}: {detail}")
        if _is_refusal(out):
            reason = out.strip().splitlines()[0][:160] if out.strip() else "no output"
            raise AIAgentError(
                f"claude finder backend '{model}' refused the security-auditor prompt "
                f"(content-policy refusal, exit {returncode}): {reason}")
        return out
    return run


def _parse(raw: str) -> List[dict]:
    data = _json_array(raw)
    if data is None:
        return []
    out = []
    for d in data:
        if isinstance(d, dict) and d.get("file") and d.get("call"):
            out.append(d)
    return out


def find(repo_root, static_surfaces=None, model: Optional[str] = None, timeout: int = 600,
         agent=None) -> dict:
    """Run the whole-repo agentic finder + verify. Returns verified findings + the fabrication rate.
    model defaults to HERMES_SHIELD_FINDER_MODEL or 'sonnet' (the seam the autoresearch loop tunes)."""
    import os
    root = Path(repo_root)
    # Default finder model: `sonnet` (Claude Sonnet). The security-auditor _SYSTEM prompt is a legitimate
    # DEFENSIVE task, but the `claude-fable-5` default deterministically AUP-refused it on exit 0 — silently
    # yielding 0 findings. Sonnet accepts the identical prompt and proposes+verifies findings. Override via
    # HERMES_SHIELD_FINDER_MODEL (the seam the autoresearch loop tunes).
    model = model or os.getenv("HERMES_SHIELD_FINDER_MODEL") or "sonnet"
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
