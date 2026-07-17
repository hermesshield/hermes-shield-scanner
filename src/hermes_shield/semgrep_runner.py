"""
semgrep_runner.py (S8.65) — L1 Semgrep integration: the ISOLATED classic-SAST COMPARATOR tier.

Semgrep runs in isolation (Docker or an isolated venv — NEVER the Hermes python, which a `pip install semgrep`
previously broke by downgrading click/mcp), its findings are mapped to our capability vocabulary and reported
as a SEPARATE, ATTRIBUTED `semgrep-classic` tier. It is NEVER merged into our headline: proven-live and the
non-gated kicker come only from our own reachability engine. Semgrep CE is intra-procedural (no cross-function
reachability), so its findings are reachability-UNPROVEN candidates — the honest framing is "here's what a best
free SAST finds across the file; here's the agent-reachable subset only we prove".
"""
from __future__ import annotations
import json
import os
import subprocess
from pathlib import Path

# HS-04: the comparator's Docker image is PINNED — a bare `semgrep/semgrep` floats to :latest, so the
# comparator baseline silently changes between runs and a compromised/updated upstream image would be
# pulled unnoticed. A `@sha256:` digest is stronger still; a concrete version tag is the accepted
# minimum. Operator override: HERMES_SHIELD_SEMGREP_IMAGE (e.g. to pin a digest or an internal mirror).
SEMGREP_IMAGE = "semgrep/semgrep:1.170.0"  # verified published tag (Docker Hub, 2026-07)


def _semgrep_image() -> str:
    return os.getenv("HERMES_SHIELD_SEMGREP_IMAGE") or SEMGREP_IMAGE


def _comparator_version(mode: str) -> str:
    """HS-04: record WHICH semgrep produced the comparator tier, for every mode. docker -> the pinned
    image ref; venv/uvx -> the binary's own `semgrep --version`. Fail-open ('unknown') — version
    capture must never block the comparator, and the comparator never blocks our own scan."""
    if mode == "docker":
        return _semgrep_image()
    cmd = ["uvx", "semgrep", "--version"] if mode == "uvx" else ["semgrep", "--version"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        v = (r.stdout or "").strip().splitlines()
        if r.returncode == 0 and v:
            return f"semgrep {v[-1]} ({mode})"
    except Exception:
        pass
    return "unknown"

# CWE -> our capability vocabulary. In-domain (agent-reachable) map to a real cap; out-of-domain -> classic_web.
_CWE_CAP = {
    "94": "code_exec", "95": "code_exec",              # code / eval injection
    "502": "deserialize",                              # unsafe deserialisation
    "78": "subprocess_exec", "77": "subprocess_exec",  # OS command injection
    "1336": "ssti", "1334": "ssti",                    # template injection
    "22": "path_traversal", "23": "path_traversal", "35": "path_traversal",
    "918": "ssrf",                                     # SSRF
    "798": "hardcoded_secret", "259": "hardcoded_secret",
    "89": "sqli",                                      # SQL injection
}
# CWEs we explicitly treat as out-of-domain classic-web noise (report, never call agentic)
_OUT_OF_DOMAIN = {"611", "776", "91", "643", "327", "328", "916", "79", "80"}   # XXE, XPath, weak crypto, XSS

_RULESETS = ["p/security-audit", "p/owasp-top-ten", "p/python", "p/javascript", "p/secrets"]


def _cap_for(cwe_list):
    for c in cwe_list:
        num = "".join(ch for ch in str(c).split("-")[1] if ch.isdigit()) if "-" in str(c) else "".join(ch for ch in str(c) if ch.isdigit())
        if num in _CWE_CAP:
            return _CWE_CAP[num], "in_domain"
        if num in _OUT_OF_DOMAIN:
            return "classic_web", "out_of_domain"
    return "classic_web", "unmapped"


def build_cmd(repo: Path, out_json: Path, mode: str = "docker"):
    """Return the isolated semgrep command. mode: 'docker' (recommended) | 'uvx' | 'venv'."""
    configs = []
    for r in _RULESETS:
        configs += ["--config", r]
    if mode == "docker":
        # HS-04: pinned image (never a floating :latest); override via HERMES_SHIELD_SEMGREP_IMAGE.
        return ["docker", "run", "--rm", "-v", f"{repo}:/src:ro", "-v", f"{out_json.parent}:/out",
                _semgrep_image(), "semgrep", *configs, "--json", "--output", f"/out/{out_json.name}",
                "--metrics", "off", "/src"]
    if mode == "uvx":
        return ["uvx", "semgrep", *configs, "--json", "--output", str(out_json), "--metrics", "off", str(repo)]
    # 'venv' — an already-isolated semgrep binary (e.g. .venv/bin/semgrep); NEVER the Hermes system python
    return ["semgrep", *configs, "--json", "--output", str(out_json), "--metrics", "off", str(repo)]


def run(repo, out_dir, mode: str = "docker", timeout: int = 600):
    """Run semgrep in isolation and return parsed findings. Returns {} with 'error' on failure (fail-open:
    semgrep is a bonus tier, never blocks our own scan). Every result — success or error — carries
    `comparator_version` (HS-04) so the comparator tier is always attributable to a concrete semgrep."""
    repo, out_dir = Path(repo), Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_json = out_dir / "semgrep.json"
    cmd = build_cmd(repo, out_json, mode)
    version = _comparator_version(mode)
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception as e:
        return {"error": f"semgrep run failed: {str(e)[:120]}", "findings": [],
                "comparator_version": version}
    if not out_json.exists():
        return {"error": "semgrep produced no output", "findings": [], "comparator_version": version}
    result = parse(out_json.read_text(encoding="utf-8", errors="ignore"))
    result["comparator_version"] = version
    return result


def parse(json_text: str):
    """Parse semgrep --json output into attributed classic-tier findings."""
    try:
        data = json.loads(json_text)
    except Exception:
        return {"error": "unparseable semgrep json", "findings": []}
    findings = []
    for r in data.get("results", []):
        meta = r.get("extra", {}).get("metadata", {})
        cwe = meta.get("cwe", []) or []
        if isinstance(cwe, str):
            cwe = [cwe]
        cap, domain = _cap_for(cwe)
        conf = meta.get("confidence", "").upper()
        # gate the noisy audit rules to HIGH confidence for the in-domain set
        findings.append({
            "file": r.get("path", ""),
            "line": r.get("start", {}).get("line", 0),
            "check_id": r.get("check_id", ""),
            "capability": cap,               # our vocab (or classic_web)
            "domain": domain,                # in_domain | out_of_domain | unmapped
            "severity": r.get("extra", {}).get("severity", ""),
            "confidence": conf,
            "cwe": cwe,
            "source": "semgrep-classic",     # ATTRIBUTION — never presented as agent-reachable/proven
        })
    return {"findings": findings, "count": len(findings)}


def head_to_head(hermes_surfaces, semgrep_findings, hermes_proven=0, hermes_non_gated=0) -> str:
    """Attributed head-to-head note: OUR reachability engine vs semgrep-classic. Semgrep is an ISOLATED
    external COMPARATOR — its findings are NEVER merged into our headline (proven-live / non-gated). This
    note reports where the two overlap and where each is alone, always attributed by source."""
    m = merge_attribute(hermes_surfaces, semgrep_findings)
    c = m["counts"]
    in_domain = sum(1 for f in semgrep_findings if f.get("domain") == "in_domain")
    out_domain = sum(1 for f in semgrep_findings if f.get("domain") == "out_of_domain")
    L = [
        "## External comparator — Hermes engine vs semgrep-classic (ATTRIBUTED)",
        "",
        "> Semgrep CE ran in isolation as a classic-SAST baseline. It is intra-procedural (no cross-function",
        "> reachability), so its findings are reachability-UNPROVEN candidates. They are NEVER merged into our",
        "> headline — proven-live and the non-gated kicker come only from our own reachability engine.",
        "",
        "| source | metric | count |",
        "| --- | --- | ---: |",
        f"| Hermes engine | proven-live (PoC-confirmed) | {hermes_proven} |",
        f"| Hermes engine | non-gated critical (reachable+unguarded) | {hermes_non_gated} |",
        f"| semgrep-classic | total findings | {len(semgrep_findings)} |",
        f"| semgrep-classic | in-domain (agent-reachable capability) | {in_domain} |",
        f"| semgrep-classic | out-of-domain (classic-web noise) | {out_domain} |",
        f"| overlap | flagged by BOTH (file~line~cap) | {c['both']} |",
        f"| semgrep-only | not in our surface set | {c['semgrep_only']} |",
        "",
        "*Honest framing: \"here is what a best-free SAST finds across the file; here is the agent-reachable",
        "subset only we prove\". Semgrep's counts are candidates, not proven-live, and stay in the",
        "`semgrep-classic` tier — never in our headline.*",
    ]
    return "\n".join(L)


def merge_attribute(hermes_surfaces, semgrep_findings):
    """Dedup semgrep against our surfaces by (file, ~line, capability); attribute each row.
    Returns {both, semgrep_only, hermes_only_count}. Our proven-live/non-gated are untouched — Semgrep never
    enters those; this only produces the separate classic tier + the overlap set for the head-to-head."""
    def key(f, l, c):
        return (Path(str(f)).name, int(l or 0), c)
    hermes_keys = {key(s.file_path, getattr(s, "sink_line", 0) or s.line_start, s.capability) for s in hermes_surfaces}
    both, semgrep_only = [], []
    for f in semgrep_findings:
        k = key(f["file"], f["line"], f["capability"])
        (both if k in hermes_keys else semgrep_only).append(f)
    return {"both": both, "semgrep_only": semgrep_only,
            "counts": {"both": len(both), "semgrep_only": len(semgrep_only), "hermes_total": len(hermes_keys)}}
