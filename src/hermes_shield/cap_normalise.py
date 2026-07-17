"""
cap_normalise.py (S8.83) — conservative normalisation of AI-tier free-text capabilities to the engine's
CANONICAL underscore capability vocabulary, so an AI-found surface can actually be RATED by the same
gates as a static surface (guard_attribution keys on PAT.CRITICAL_CAPS; install_report keys on
_RCE_CAPS/_ACT_CAPS — both underscore). Without this, a hyphenated `tool-invoke` / `code-execution`
never matches, so a reachable AI surface can never be promoted and never counted. This is GAP-2.

SOUND-LEANING / NO FORCE-FIT: a free-text cap is mapped to a canonical one ONLY when it carries a CLEAR,
unambiguous canonical signal. Caps with no clear canonical meaning under our threat model — db-write,
network-fetch (inbound/SSRF-review, NOT an egress write), dynamic-dispatch, dynamic-import, sql-execution,
approval-*, money-transfer, state/memory/store-write — are LEFT non-canonical (returned unchanged). Leaving
them out UNDER-marks (they simply are not rated) which is the safe error; force-fitting them would inflate
the install-liability/critical counts (over-claiming), the fatal error for a cyber report.

Mapping is a first-match ORDERED rule list over the lower-cased cap string. Order encodes precedence
(most specific / most severe canonical signal first). Pure classifier — no I/O, no network.
"""
from __future__ import annotations
import re

# canonical targets (must match patterns.CRITICAL_CAPS / install_report._RCE_CAPS|_ACT_CAPS spelling)
CANONICAL = {
    "code_exec", "subprocess_exec", "deserialize", "ssti", "secret_exfil",
    "external_write", "file_write", "file_delete", "tool_invoke", "publish_write",
}

# Ordered (regex-on-lowercased-cap -> canonical). FIRST match wins. Each rule is deliberately narrow.
_RULES = [
    # --- secrets / exfiltration (data breach) : an explicit secret/credential/exfil token ---
    ("secret_exfil", re.compile(r"\b(secret|credential|exfil|exfiltrat)\w*", re.I)),
    # --- deserialize (RCE) : pickle/marshal/yaml.load/deserialize ---
    ("deserialize", re.compile(r"deserial|unpickl|\bpickle\b|\bmarshal\b|yaml\.?load", re.I)),
    # --- server-side template injection (RCE) ---
    ("ssti", re.compile(r"\bssti\b|template.?inject|render_template_string|from_string|jinja", re.I)),
    # --- subprocess / shell / OS command (RCE) : an explicit shell/subprocess/command token ---
    ("subprocess_exec", re.compile(r"subprocess|shell[- ]?exec|\bshell\b|os\.system|exec[- ]?command|command[- ]?exec", re.I)),
    # --- tool / agent invocation & delegation : the agent-plumbing sink. Requires a TOOL or AGENT context
    #     word so a bare "invoke"/"callback"/"dispatch" (dynamic-dispatch — LEFT non-canonical) never matches. ---
    ("tool_invoke", re.compile(r"\btool\b.*(invoke|invocat|execut|action|dispatch|call|run)|"
                               r"(invoke|invocat|execut|delegat|spawn|run|start|dispatch|session).*\btool\b|"
                               r"\bagent\b.*(invoke|invocat|execut|delegat|spawn|run|session|task|input|action)|"
                               r"(invoke|invocat|execut|delegat|spawn|run|session|task|action).*\bagent\b|"
                               r"\bdelegat\w*", re.I)),
    # --- code execution / eval / compile (RCE). AFTER subprocess+tool/agent so "agent-execution" and
    #     "shell-exec" are already claimed; a raw exec/eval/code-exec/execute-code that survives is code_exec.
    #     S8.85 FORCE-FIT FIX: bare `\bexecute\b` / `\bcompile\b` REMOVED — they wrongly promoted data-plane
    #     phrases ("execute sql|query|workflow|statement", "compile template|regex|report") to RCE. Only a
    #     GENUINE code-execution token promotes: exec/eval/code-exec/execute-code/expression-eval, and
    #     compile ONLY when bound to code (`compile-code`/`code-compilation`). A bare execute/compile is
    #     ambiguous -> LEFT non-canonical (the docstring's own promise: under-mark, never over-claim). ---
    ("code_exec", re.compile(r"code[- ]?exec|exec[- ]?code|execute[- ]?code|code[- ]?generation.*exec|"
                             r"\beval\b|expression[- ]?eval|compile[- ]?code|code[- ]?compil|"
                             r"\bexec\b|enable[- ]?code[- ]?exec", re.I)),
    # --- file delete (BEFORE file-write so "file write/delete" resolves to the destructive one) ---
    ("file_delete", re.compile(r"file.?delet|\bdelete\b.*file|file.*\bdelete\b", re.I)),
    # --- file write ---
    ("file_write", re.compile(r"file.?write|write.?file|\bblob[- ]?write\b|write.?blob", re.I)),
    # --- publish (ready/approved/outbound publish write) ---
    ("publish_write", re.compile(r"\bpublish\b", re.I)),
    # --- external / network egress WRITE : send/post/upload/network-send/cloud-write/external-write.
    #     network-FETCH / network-request / network-dns are NOT here (inbound/SSRF-review -> left). ---
    ("external_write", re.compile(r"external[- ]?write|network[- ]?send|network[- ]?write|"
                                  r"cloud[- ]?write|cloud[- ]?deploy|\bupload\b|\bpost\b|"
                                  r"send[- ]?message|message[- ]?send|\bsend\b(?![- ]?message)|"
                                  r"\bemail\b|\bpublish\b", re.I)),
]


def normalise_capability(cap: str):
    """Return (canonical_cap, mapped: bool). mapped=False -> cap left non-canonical (returned unchanged)."""
    if not cap:
        return cap, False
    c = str(cap).strip()
    low = c.lower()
    # already canonical (underscore) -> keep, not a "mapping"
    if c in CANONICAL:
        return c, False
    for canon, rx in _RULES:
        if rx.search(low):
            return canon, True
    return c, False


def apply_to_surfaces(surfaces) -> dict:
    """Normalise the capability of AI-tier surfaces (detection_source != 'static') IN PLACE.
    Static surfaces are never touched. Returns honesty stats: per-original-cap mapped/left counts."""
    mapped = {}      # original_cap -> canonical
    left = {}        # original_cap -> count (non-canonical, unchanged)
    n_mapped = n_left = n_already = 0
    for s in surfaces:
        if getattr(s, "detection_source", "static") == "static":
            continue
        orig = s.capability
        canon, did = normalise_capability(orig)
        if did:
            s.capability = canon
            mapped[orig] = canon
            n_mapped += 1
        elif orig in CANONICAL:
            n_already += 1           # already canonical (e.g. 'deserialize') — will be rated as-is
        else:
            left[orig] = left.get(orig, 0) + 1
            n_left += 1
    return {"ai_caps_mapped": n_mapped, "ai_caps_already_canonical": n_already,
            "ai_caps_left_non_canonical": n_left,
            "mapped_examples": mapped, "left_examples": left}
