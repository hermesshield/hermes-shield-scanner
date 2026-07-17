"""
Hermes Shield MVP — static config loader (P2.9D). Loads guard-primitive identities + entrypoint maps
from scanner-owned JSON. STATIC ONLY: never imports/executes the referenced modules, never reads
secrets. Invalid/missing config fails SAFE (falls back to the built-in defaults; entrypoints empty).
"""
from __future__ import annotations
import json
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Set, Tuple

_CFG_DIR = Path(__file__).resolve().parent / "config"

# built-in defaults (used if config missing/invalid) — matches the pre-P2.9D hardcoded set
_DEFAULT_MODULES = ("shield_kill_switch", "hermes_global_kill_switch", "final_action_gate",
                    "hermes_untrusted", "hash_ledger", "dashboard_auth")
_DEFAULT_SYMBOLS = {
    "assert_live_action_allowed": "kill_switch", "check_live_action_allowed": "kill_switch",
    "live_actions_blocked": "kill_switch", "allow_action": "final_action_gate",
    "assert_action_allowed": "final_action_gate", "require_final_action_approval": "final_action_gate",
    "is_dashboard_post_allowed": "csrf_token", "make_untrusted_content": "untrusted_fence",
    "wrap_for_action_prompt": "untrusted_fence", "screen_source": "untrusted_fence",
    "record_approved": "strict_hash", "get_approved": "strict_hash",
}


@lru_cache(maxsize=1)
def load_guard_config() -> Tuple[Set[str], Dict[str, str], Dict[str, str]]:
    """Return (guard_modules, symbol->guard_type, symbol->configured_id). Fail-safe to defaults."""
    modules: Set[str] = set(_DEFAULT_MODULES)
    symbols: Dict[str, str] = dict(_DEFAULT_SYMBOLS)
    symbol_id: Dict[str, str] = {}
    try:
        data = json.loads((_CFG_DIR / "guard_primitives.json").read_text(encoding="utf-8"))
        prims = data.get("guard_primitives", [])
        if not isinstance(prims, list):
            raise ValueError("guard_primitives must be a list")
        for p in prims:
            if not isinstance(p, dict) or p.get("strength") != "strong":
                continue
            gid = p.get("id", "")
            gtype = p.get("guard_type", "unknown")
            for m in p.get("modules", []):
                if isinstance(m, str):
                    modules.add(m)
            for s in p.get("symbols", []):
                if isinstance(s, str):
                    symbols[s] = gtype
                    symbol_id[s] = gid
    except Exception:
        # invalid config -> keep built-in defaults (fail safe)
        pass
    return modules, symbols, symbol_id


@lru_cache(maxsize=1)
def load_entrypoints() -> Tuple[List[dict], Dict[Tuple[str, str], dict]]:
    """Return (entrypoints, helper_policy_map keyed by (module_tail, symbol)). Fail-safe to empty."""
    entrypoints: List[dict] = []
    helpers: Dict[Tuple[str, str], dict] = {}
    try:
        data = json.loads((_CFG_DIR / "entrypoints.json").read_text(encoding="utf-8"))
        for e in data.get("entrypoints", []):
            if isinstance(e, dict) and e.get("module") and e.get("symbol"):
                entrypoints.append(e)
        for h in data.get("helpers", []):
            if isinstance(h, dict) and h.get("module") and h.get("symbol"):
                key = (str(h["module"]).split(".")[-1], str(h["symbol"]))
                helpers[key] = h
    except Exception:
        pass
    return entrypoints, helpers


def load_target_guards(root):
    """Guard-onboarding: read a TARGET repo's own control declaration from <root>/.hermes-shield.json
    (keys: guard_modules[], guard_symbols[]). Fail-safe -> ([],[]) if absent/invalid. No execution."""
    import json as _json
    from pathlib import Path as _Path
    try:
        cfg = _Path(root) / ".hermes-shield.json"
        if not cfg.is_file():
            return [], []
        d = _json.loads(cfg.read_text(encoding="utf-8"))
        return list(d.get("guard_modules", []) or []), list(d.get("guard_symbols", []) or [])
    except Exception:
        return [], []
