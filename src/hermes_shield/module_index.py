"""
Hermes Shield MVP — static module/import index + guard-identity resolution (P2.9C).

STATIC ONLY: parses ASTs, never imports/executes target code. Builds a dotted-module -> file map and,
per file, an import map so a guard call can be resolved to its SOURCE. This is what lets the scanner
say "this guard is really the kill switch imported from shield_kill_switch" vs
"this is an unrelated method that merely shares a name" (fixes ADV04). No secrets.
"""
from __future__ import annotations
import ast
from pathlib import Path
from typing import Dict, Optional

# P2.9D: guard SOURCES + symbols are now config-driven (config/guard_primitives.json), with the
# previous hardcoded set as the fail-safe default. Loaded once, statically.
from .config_loader import load_guard_config  # noqa: E402

_MODULES, GUARD_SYMBOLS, _SYMBOL_ID = load_guard_config()
KNOWN_GUARD_MODULES = tuple(sorted(_MODULES))
# base layers, so user-declared guards (onboarding) can be set/reset without leaking across scans
_BASE_MODULES = set(_MODULES)
_BASE_SYMBOLS = dict(GUARD_SYMBOLS)


def set_user_guards(modules, symbols, trusted=False):
    """Guard-onboarding: recognise a TARGET repo's own control functions (declared in its
    .hermes-shield.json). Replaces the previous user layer (does not accumulate) so scans stay isolated.

    audit finding #3 (CWE-501, target self-attestation): the target repo is UNTRUSTED. A repo-local
    declaration must NOT, on its own, influence guard credit and downgrade the target's own unguarded
    critical sinks. So by default (`trusted=False`) the target's declared guard modules/symbols are IGNORED
    entirely — guard resolution is byte-identical to a scan with no `.hermes-shield.json`, so an unguarded
    critical sink stays unguarded. Only when the OPERATOR opts in (`trusted=True`, decided OUTSIDE the
    target) are the declarations honoured as critical `user_declared_gate` guards. Static; no execution."""
    global _MODULES, KNOWN_GUARD_MODULES, GUARD_SYMBOLS
    GUARD_SYMBOLS = dict(_BASE_SYMBOLS)
    if trusted:
        for s in (symbols or []):
            GUARD_SYMBOLS[s] = "user_declared_gate"
        _MODULES = set(_BASE_MODULES) | set(modules or [])
    else:
        # untrusted target declarations have ZERO effect on guard resolution/verdicts (no registration).
        _MODULES = set(_BASE_MODULES)
    KNOWN_GUARD_MODULES = tuple(sorted(_MODULES))


def configured_guard_id(symbol: str):
    """The configured guard-primitive id for a symbol (e.g. 'kill_switch'), or None."""
    return _SYMBOL_ID.get(symbol)

# guard-identity resolution outcomes
RESOLVED_IMPORT = "resolved_import"
LOCAL_DEFINITION = "local_definition"
CERTIFIED_GATEWAY = "certified_gateway"
CONFIGURED_GUARD = "configured_guard"
UNRESOLVED_NAME = "unresolved_name_match"
REJECTED_COLLISION = "rejected_name_collision"
STRONG = {RESOLVED_IMPORT, LOCAL_DEFINITION, CERTIFIED_GATEWAY, CONFIGURED_GUARD}

# S6.1 guard criticality (cyber-lead spec): a CRITICAL guard can, on its own, DENY the live action and
# fails closed (kill-switch, final action gate, human/hash approval). CONTENT guards defend the content
# (fence) but not the action authority. Everything else is weak/theatre (leak-tells, caps, length). Only
# CRITICAL guards satisfy guard-attribution for a live-action sink; over-crediting is the dangerous failure.
# R1 (cyber-lead): kept to DECISION-shaped gates only. approval_hash_gate/strict_hash resolve from
# hashing/getter symbols (hash_file, get_approved) that are not themselves a deny-decision, so crediting
# them critical could drop a tainted sink 0->3 (the over-credit direction). Real human-approval is enforced
# by final_action_gate's requires_human check, which is already critical. So they are NOT in the critical set.
CRITICAL_GUARD_KINDS = {"kill_switch", "final_action_gate", "user_declared_gate"}


def guard_class(guard_kind: Optional[str], capability: str = "") -> str:
    """Classify a resolved guard KIND for a given sink capability: 'critical' | 'content' | 'weak'.
    csrf_token is critical only for dashboard_mutation (it gates the dashboard POST, nothing else)."""
    if guard_kind == "csrf_token":
        return "critical" if capability == "dashboard_mutation" else "weak"
    if guard_kind in CRITICAL_GUARD_KINDS:
        return "critical"
    if guard_kind == "untrusted_fence":
        return "content"
    return "weak"


def _is_guard_module(module: Optional[str]) -> bool:
    if not module:
        return False
    tail = module.split(".")[-1]
    return tail in KNOWN_GUARD_MODULES or any(m in module for m in KNOWN_GUARD_MODULES)


def parse_imports(tree: ast.AST) -> Dict[str, dict]:
    """name-in-file -> {kind, module, orig, guard_module}. Static; handles import/from/alias/relative."""
    out: Dict[str, dict] = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                local = a.asname or a.name.split(".")[0]
                out[local] = {"kind": "import", "module": a.name, "orig": a.name,
                              "guard_module": _is_guard_module(a.name)}
        elif isinstance(n, ast.ImportFrom):
            module = n.module or ""  # relative imports have module possibly None + level
            for a in n.names:
                local = a.asname or a.name
                out[local] = {"kind": "from", "module": module, "orig": a.name,
                              "level": n.level, "guard_module": _is_guard_module(module),
                              "is_guard_symbol": a.name in GUARD_SYMBOLS}
    return out


def resolve_guard_identity(call_name: str, is_method: bool, imports: Dict[str, dict],
                           local_defs: set) -> dict:
    """Classify a guard-candidate call. Only STRONG identities count for a protection proof."""
    # P2.9C-REVIEW fix: ALIASED guard import (`from ...kill_switch import assert_live_action_allowed
    # as _ks`) — resolve via the import's ORIGINAL name. P2.9D fix: STRONG requires the source to be a
    # recognised GUARD MODULE (guard_module=True). A guard NAME from a non-guard module (wrong-module
    # collision) is NOT strong.
    imp = imports.get(call_name)
    if imp and imp.get("is_guard_symbol") and imp.get("guard_module") and imp.get("orig") in GUARD_SYMBOLS:
        return {"identity": RESOLVED_IMPORT, "kind": GUARD_SYMBOLS.get(imp.get("orig")), "strong": True,
                "reason": f"aliased import of {imp.get('orig')} from {imp.get('module')}"}
    kind = GUARD_SYMBOLS.get(call_name)
    if kind is None:
        return {"identity": REJECTED_COLLISION, "kind": None, "strong": False,
                "reason": "not a recognised guard name"}
    # imported symbol from a recognised GUARD MODULE -> strong (module, not just name)
    if imp and imp.get("guard_module"):
        return {"identity": RESOLVED_IMPORT, "kind": kind, "strong": True,
                "reason": f"imported from {imp.get('module')}"}
    # a guard NAME imported from a NON-guard module -> wrong-module collision, weak
    if imp:
        return {"identity": UNRESOLVED_NAME, "kind": kind, "strong": False,
                "reason": f"guard name from non-guard module {imp.get('module')}"}
    # dotted module.func where the module is an imported guard module
    if "." in call_name:
        mod = call_name.split(".")[0]
        if imports.get(mod, {}).get("guard_module"):
            return {"identity": RESOLVED_IMPORT, "kind": kind, "strong": True,
                    "reason": f"guard module {mod}"}
    # method call on an unknown receiver (self.x / obj.x) with a colliding name -> rejected (ADV04)
    if is_method:
        return {"identity": REJECTED_COLLISION, "kind": kind, "strong": False,
                "reason": "method on unresolved receiver; name collision"}
    # a locally-defined function of that name (a wrapper) -> local definition, medium (weak-strong)
    if call_name in local_defs:
        return {"identity": LOCAL_DEFINITION, "kind": kind, "strong": True,
                "reason": "local guard definition in file"}
    # bare guard name but not imported/resolved -> unresolved (weak)
    return {"identity": UNRESOLVED_NAME, "kind": kind, "strong": False,
            "reason": "guard name not resolved to a source"}


def build_index(root: Path, skip_dirs) -> Dict[str, str]:
    """dotted-module -> file path, for local imports resolution (static)."""
    index: Dict[str, str] = {}
    for p in root.rglob("*.py"):
        if set(p.parts) & skip_dirs:
            continue
        try:
            rel = p.relative_to(root)
        except ValueError:
            continue
        dotted = ".".join(rel.with_suffix("").parts)
        index[dotted] = str(p)
    return index
