"""
repo_map.py (S7.2) — deterministic AST repo-map + cross-file symbol index. NO LLM.

The orientation artifact the AI-first finder uses to reason ACROSS files WITHOUT ingesting the whole repo
(the way the adjudicator does: orient from a cheap map, then pull only the interesting files). Also reused
by the verifier and the absorb step. Read-only; stdlib + our parse_imports only.

For each file: imports, classes (name + bases, flagging agent-plumbing bases like *Tool/BaseTool/Executor/
Agent/Chain/Runnable), functions, and a one-line danger hint. Global: symbol -> where defined + which files
reference it (so a `tool.invoke` in file A can be tied to the tool class defined in file B). Ranks
agent-plumbing hot-spots first.
"""
from __future__ import annotations
import ast
import re
from pathlib import Path
from typing import Dict, List, Optional

from . import module_index as MI

# base classes whose subclasses are LLM-invokable tools/agents (the agent-plumbing static misses)
_TOOL_LIKE_BASES = ("BaseTool", "Tool", "Executor", "Agent", "Chain", "Runnable", "StructuredTool")
# cheap danger hints (reuse the intent of ai_tier's risk/plumbing hints; deterministic regex)
_DANGER_HINT = re.compile(
    r"\b(subprocess|os\.system|popen|\beval\(|\bexec\(|pickle|yaml\.load|torch\.load|importlib|"
    r"import_module|__import__|getattr\s*\([^)]*,|\.invoke\(|\.run\(|call_tool|register_tool|"
    r"execute_task|send_message|\.post\(|requests\.|httpx\.|\.remember|\.add_texts|\.upsert\(|"
    r"\.delete\(|open\([^)]*['\"][wa])", re.I)


def _base_names(node: ast.ClassDef) -> List[str]:
    out = []
    for b in node.bases:
        if isinstance(b, ast.Name):
            out.append(b.id)
        elif isinstance(b, ast.Attribute):
            out.append(b.attr)
    return out


def _tool_like(bases: List[str]) -> bool:
    # SUFFIX match, not substring: 'LangChainException' must NOT count as a Chain (it ends 'Exception').
    return any(b.endswith(("Tool", "Executor", "Agent", "Chain", "Runnable")) for b in bases)


def build_repo_map(root: Path, rel_paths: Optional[List[str]] = None) -> dict:
    """Return {files, symbol_defs, symbol_refs, tool_like_classes, hot_files}. Deterministic."""
    root = Path(root)
    if rel_paths is None:
        from .cross_module import _all_py_rel
        rel_paths = _all_py_rel(root)
    files: Dict[str, dict] = {}
    symbol_defs: Dict[str, List[str]] = {}          # symbol -> [files defining it]
    symbol_refs: Dict[str, set] = {}                # symbol -> {files referencing it by bare name}
    tool_like: List[dict] = []

    for rel in rel_paths:
        try:
            src = (root / rel).read_text(encoding="utf-8")
            tree = ast.parse(src)
        except Exception:
            continue
        imports = list(MI.parse_imports(tree).keys())
        classes, funcs, refs = [], [], set()
        for n in ast.walk(tree):
            if isinstance(n, ast.ClassDef):
                bases = _base_names(n)
                tl = _tool_like(bases)
                classes.append({"name": n.name, "bases": bases, "tool_like": tl, "line": n.lineno})
                symbol_defs.setdefault(n.name, []).append(rel)
                if tl:
                    tool_like.append({"class": n.name, "file": rel, "line": n.lineno, "bases": bases})
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                funcs.append(n.name)
                symbol_defs.setdefault(n.name, []).append(rel)
            elif isinstance(n, ast.Name):
                refs.add(n.id)
            elif isinstance(n, ast.Attribute):
                refs.add(n.attr)
        for r in refs:
            symbol_refs.setdefault(r, set()).add(rel)
        hint = bool(_DANGER_HINT.search(src))
        files[rel] = {"imports": imports, "classes": classes, "funcs": funcs, "danger_hint": hint,
                      "tool_like_classes": [c["name"] for c in classes if c["tool_like"]]}

    # hot files first: tool-like classes, then danger-hint files, then the rest (finder targeting)
    def _score(rel):
        f = files[rel]
        return (2 if f["tool_like_classes"] else 0) + (1 if f["danger_hint"] else 0)
    hot_files = sorted(files, key=_score, reverse=True)
    return {"files": files, "symbol_defs": symbol_defs,
            "symbol_refs": {k: sorted(v) for k, v in symbol_refs.items()},
            "tool_like_classes": tool_like, "hot_files": hot_files}


def render_compact(repo_map: dict, max_files: int = 400) -> str:
    """A compact text map to SEED the finder's orientation (1 line/file, tool-like classes highlighted)."""
    lines = ["# REPO MAP (deterministic). Agent-plumbing (tool-like) classes are the highest-value targets."]
    tl = repo_map["tool_like_classes"]
    if tl:
        lines.append(f"## Tool/Agent-like classes ({len(tl)}) — invocations of these are agent-plumbing:")
        for c in tl[:80]:
            lines.append(f"  {c['file']}:{c['line']}  class {c['class']}({', '.join(c['bases'])})")
    lines.append("## Files (hot first: * = tool-like, ! = danger hint):")
    for rel in repo_map["hot_files"][:max_files]:
        f = repo_map["files"][rel]
        flag = ("*" if f["tool_like_classes"] else " ") + ("!" if f["danger_hint"] else " ")
        lines.append(f"  {flag} {rel}  ({len(f['classes'])}c/{len(f['funcs'])}f)")
    return "\n".join(lines)
