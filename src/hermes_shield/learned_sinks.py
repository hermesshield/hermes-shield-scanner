"""
learned_sinks.py (S8) — the COMPOUNDING memory of the scanner.

When the AI finder confirms a NOVEL dangerous sink the static scanner missed, its distinctive method name is
absorbed here as a permanent static rule. Every future scan then catches that threat for free, instantly,
deterministically — the expensive AI find becomes free static knowledge. This is what makes the scanner
compound: recall rises and cost falls over time, automatically.

Guarded absorb: only DISTINCTIVE names are learnable (common names like run/send/get would cause a
false-positive explosion), and every candidate is provenance-stamped so we can audit and revert.
"""
from __future__ import annotations
import json
import re
from pathlib import Path

_STORE = Path(__file__).parent / "learned_sinks.json"

# names too common/generic to absorb safely — absorbing these would fire everywhere (FP explosion).
_TOO_COMMON = {
    "run", "send", "get", "post", "put", "add", "set", "call", "do", "make", "write", "read", "save",
    "load", "open", "close", "start", "stop", "exec", "apply", "update", "delete", "create", "invoke",
    "process", "handle", "execute", "fetch", "request", "push", "pull", "sync", "emit", "publish",
}


def load() -> dict:
    if _STORE.exists():
        try:
            return json.loads(_STORE.read_text(encoding="utf-8"))
        except Exception:
            return {"sinks": {}}
    return {"sinks": {}}


def learned_name_sinks() -> dict:
    """{method_name: capability} — merged into the static _EXTRA_NAME_SINKS check on every scan."""
    return {k: v["capability"] for k, v in load().get("sinks", {}).items()}


def is_distinctive(name: str) -> bool:
    """A name is safe to absorb only if it is specific enough not to fire everywhere."""
    if not name or name in _TOO_COMMON:
        return False
    if len(name) < 6:                                   # short names are usually generic
        return False
    # distinctive = multi-word (snake/camel) OR a clear compound action verb
    multiword = "_" in name or bool(re.search(r"[a-z][A-Z]", name))
    action = bool(re.search(r"(exec|command|shell|eval|spawn|deploy|delete|destroy|drop|wipe|"
                            r"transfer|payout|withdraw|upload|exfil|dispatch|serialize|deserialize|"
                            r"pickle|render_template|call_tool|run_code|system)", name, re.I))
    return multiword or action


def add(name: str, capability: str, provenance: dict) -> bool:
    """Absorb a learned sink. Returns True if added, False if rejected (not distinctive / already known)."""
    if not is_distinctive(name):
        return False
    d = load()
    sinks = d.setdefault("sinks", {})
    if name in sinks:
        return False
    sinks[name] = {"capability": capability, "provenance": provenance}
    _STORE.write_text(json.dumps(d, indent=1), encoding="utf-8")
    return True


def revert(name: str) -> bool:
    d = load()
    if name in d.get("sinks", {}):
        del d["sinks"][name]
        _STORE.write_text(json.dumps(d, indent=1), encoding="utf-8")
        return True
    # also allow reverting a structural rule by id
    rules = d.get("structural", [])
    keep = [r for r in rules if r.get("id") != name]
    if len(keep) != len(rules):
        d["structural"] = keep
        _STORE.write_text(json.dumps(d, indent=1), encoding="utf-8")
        return True
    return False


# ── S8 upgrade #1: STRUCTURAL rules. Match on the RESOLVED MODULE (subprocess), never the verb string, so
# check_call generalises to the subprocess family (run_shell/exec_cmd/spawn) but never to "any word with call".
# Hard-danger modules have ~no benign verbs -> module_wide (any non-read/ctor verb). Others -> verb_set (exact
# verb, module-scoped). Mixed modules (os/redis) are NOT absorbed here (they need taint gating; deferred).
_HARD_DANGER_MODULES = {"subprocess", "paramiko", "fabric", "pexpect", "telnetlib", "docker", "ptyprocess"}
_MODULE_WIDE_DENYLIST = {"os", "sys", "builtins", "pathlib", "shutil", "io", "functools", "re", "json",
                         "collections", "itertools", "typing", "logging", "math", "datetime"}
_STRUCT_CAP = 200


def structural_rules() -> list:
    return load().get("structural", [])


def add_structural(sig: dict):
    """Absorb a structural rule. sig = {capability, module_root, verb, provenance}. Returns rule id or None.
    module_root MUST be a resolved import module (never a local var). Safe subset: hard-danger module_wide or
    verb_set; mixed/denylisted modules are rejected (deferred to the taint-gated tier)."""
    mr = (sig.get("module_root") or "").strip()
    verb = (sig.get("verb") or "").strip()
    cap = sig.get("capability")
    if not mr or not cap or mr in _MODULE_WIDE_DENYLIST:
        return None
    hard = mr in _HARD_DANGER_MODULES
    if not hard and not is_distinctive(verb):     # non-hard module -> need a distinctive verb for verb_set
        return None
    d = load()
    rules = d.setdefault("structural", [])
    if len(rules) >= _STRUCT_CAP:
        return None
    for r in rules:                                # subsumption: extend an existing rule's verb set
        if r["module_root"] == mr and r["capability"] == cap:
            if verb and verb not in r["verbs"]:
                r["verbs"].append(verb)
            _STORE.write_text(json.dumps(d, indent=1), encoding="utf-8")
            return r["id"]
    rid = f"{mr}:{cap}"
    rules.append({"id": rid, "capability": cap, "module_root": mr,
                  "verbs": [verb] if verb else [], "generality": "module_wide" if hard else "verb_set",
                  "hard_danger_module": hard, "provenance": sig.get("provenance", {})})
    _STORE.write_text(json.dumps(d, indent=1), encoding="utf-8")
    return rid


def match_structural(module_root: str, verb: str, guard_ok: bool):
    """Return the capability if a structural rule fires for this resolved call, else None. guard_ok = the verb
    passes the read-prefix/constructor guard (only relevant for module_wide)."""
    if not module_root:
        return None
    for r in structural_rules():
        if r["module_root"] != module_root:
            continue
        if r["generality"] == "verb_set":
            if verb in r["verbs"]:
                return r["capability"]
        elif r["generality"] == "module_wide" and guard_ok:
            return r["capability"]
    return None
