"""
llm_eval_detector.py (S8.60) — FOCUSED, high-precision detector for the ONE proven class:
`eval()` / `exec()` on a value derived from the LLM's OWN OUTPUT → prompt-injection RCE.
(Class documented by Microsoft May-2026 "prompts become shells". NOTE: CVE-2026-26030 is a
CROSS-FUNCTION instance we do NOT detect - this detector is intra-procedural.)

Why a separate detector: the general grounded scanner buries this class (it top-ranked typed-config eval FPs
while marking the real LLM-output evals "needs call graph"). This detector targets the two proven archetypes
directly — (A) agents that eval the model's task/JSON output, (B) code-as-action agents that eval/exec the
model's generated code — with a per-function backward provenance trace, so it finds the real ones cleanly.

It intentionally does NOT flag eval on typed/config/DB values (not LLM output). HONEST LIMITS (do not
overclaim): it is INTRA-PROCEDURAL (single-function provenance) so cross-function flows are MISSED (e.g. the
CVE-2026-26030 Semantic Kernel shape), and it does NOT detect sandboxing - a human must judge sandbox/gating.
It reports candidates + confidence, NEVER "proven".
"""
from __future__ import annotations
import ast

_EXEC_BUILTINS = {"eval", "exec"}
_LLM_OUTPUT_ATTRS = {"content", "text", "message", "output_text", "completion", "response"}
_LLM_CALL_METHODS = {"invoke", "chat", "complete", "completion", "generate", "predict", "create", "acreate", "run"}
# DEFINITIVE names — the value IS the model's output; stay at medium even with no in-function LLM call.
_LLM_VAR_STRONG = ("assistant_reply", "assistant_message", "llm_output", "llm_response", "model_output",
                   "generated_code", "ai_message", "response_content", "raw_response")
# WEAKER hints — need an in-function LLM call to stay medium, else low.
_LLM_VAR_WEAK = ("completion", "assistant", "reply", "code", "response", "answer")
_LLM_VAR_HINTS = _LLM_VAR_STRONG + _LLM_VAR_WEAK


def _llm_output_expr(node):
    """(confidence, why) if this expression is an LLM-output source, else (None, None)."""
    # <...>.invoke(prompt).content  /  .chat(...).text  — .attr on an LLM call
    if isinstance(node, ast.Attribute) and node.attr in _LLM_OUTPUT_ATTRS:
        if isinstance(node.value, ast.Call):
            fn = node.value.func
            if isinstance(fn, ast.Attribute) and fn.attr in _LLM_CALL_METHODS:
                return "high", f"llm_call().{node.attr}"
            if isinstance(fn, ast.Name) and fn.id in _LLM_CALL_METHODS:
                return "high", f"{fn.id}().{node.attr}"
        return "medium", f".{node.attr}"
    # response['content'] / response["content"]
    if isinstance(node, ast.Subscript):
        base = node.value
        key = node.slice
        kval = key.value if isinstance(key, ast.Constant) else None
        if isinstance(base, ast.Name) and any(h in base.id.lower() for h in ("response", "resp", "completion", "message")) \
                and kval in ("content", "text", "message"):
            return "high", f"{base.id}['{kval}']"
    return None, None


def _name_hint(name):
    n = (name or "").lower()
    for h in _LLM_VAR_HINTS:
        if h == n or n == h:
            return "medium", f"var '{name}'"
    return None, None


def _provenance(node, assigns, depth=0):
    """Recursively decide if `node` is LLM-output-derived. Handles the arg being an LLM-output expr, a Name
    traced to its assignment, a cleaner-call wrapping the value (eval(extract_json(assistant_reply))), or a
    hint-named param/attr."""
    if depth > 5 or node is None:
        return None, None
    conf, why = _llm_output_expr(node)
    if conf:
        return conf, why
    if isinstance(node, ast.Name):
        rhs = assigns.get(node.id)
        if rhs is not None:
            c, w = _provenance(rhs, assigns, depth + 1)
            if c:
                return c, w
        return _name_hint(node.id)
    if isinstance(node, ast.Call):                       # cleaner(X)/strip(X) — look inside the wrapper's args
        for a in node.args:
            c, w = _provenance(a, assigns, depth + 1)
            if c:
                return c, w
    if isinstance(node, ast.Attribute) and node.attr in _LLM_OUTPUT_ATTRS:
        return "medium", f".{node.attr}"
    return None, None


def _detect_in_function(fn):
    """Return findings for eval/exec calls in one function whose arg is LLM-output-derived."""
    assigns = {}
    for n in ast.walk(fn):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    assigns[t.id] = n.value
    has_llm_call = any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in _LLM_CALL_METHODS
        for n in ast.walk(fn))

    findings = []
    for n in ast.walk(fn):
        if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in _EXEC_BUILTINS):
            continue
        if not n.args:
            continue
        conf, why = _provenance(n.args[0], assigns)
        if conf:
            # a weak var-hint with no LLM call anywhere in the function → low; strong names stay medium.
            if (conf == "medium" and not has_llm_call and why and why.startswith("var ")
                    and not any(s in why for s in _LLM_VAR_STRONG)):
                conf = "low"
            findings.append({"line": n.lineno, "sink": n.func.id, "confidence": conf, "provenance": why})
    return findings


def detect(text: str):
    """Return list of {line, sink, confidence, provenance} for eval/exec on LLM-output-derived values."""
    try:
        tree = ast.parse(text)
    except Exception:
        return []
    out = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.extend(_detect_in_function(node))
    return out
