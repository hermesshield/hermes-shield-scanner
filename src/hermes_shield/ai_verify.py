"""
ai_verify.py (S7.3) — repo-scoped deterministic verification of AI-finder findings. NO LLM.

The whole-repo Fable-5 finder emits findings that reference real file paths across the repo (unlike the old
per-file `ai_assist.analyze_source`, which only saw one string). This verifies each finding against the
ACTUAL file on disk — parse it, confirm a real `ast.Call` whose callee matches the model's claim, apply the
battle-tested safe-list / mislabel filters — reusing `ai_assist._ast_verify` so there is ONE gate, not two.

This is the "dispose" half of "AI proposes, deterministic disposes": a finding with no real call node at the
cited callee is DISCARDED and counted toward the fabrication rate (the integrity-auditor's mandatory number).
A stronger finder yields more recall; it can NEVER fabricate past this gate.
"""
from __future__ import annotations
from pathlib import Path
from typing import Dict, List

from . import ai_assist


def verify_findings(repo_root, findings: List[dict]) -> List[dict]:
    """findings: [{file, line, call, capability, ...}] with real repo-relative paths. Returns the
    AST-verified survivors (line corrected to the real call, tier = corroborated|ai_suspected), reading
    each file once. An unreadable/unparseable file or an unmatched callee -> the finding is dropped."""
    root = Path(repo_root)
    by_file: Dict[str, list] = {}
    for f in findings:
        by_file.setdefault(f.get("file"), []).append(f)
    out: List[dict] = []
    for rel, ff in by_file.items():
        if not rel:
            continue
        try:
            src = (root / rel).read_text(encoding="utf-8")
        except Exception:
            continue                                  # unreadable -> cannot verify -> conservative drop
        for v in ai_assist._ast_verify(ff, src):      # the same tested gate as the per-file path
            v["file"] = rel
            out.append(v)
    return out


def fabrication_rate(n_proposed: int, n_verified: int) -> float:
    """The fabrication rate = fraction of proposed findings with no real call node at the cited callee.
    Published beside every AI recall number (integrity rule: a stronger, more verbose model may fabricate
    more, so this must be tracked precisely)."""
    return (n_proposed - n_verified) / n_proposed if n_proposed else 0.0
