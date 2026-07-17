"""
install_report.py (S8.57) — the two-number report. For any scanned repo, separate:

  1. PROVEN-LIVE (critical)  — a dangerous sink that is reachable + unguarded IN THIS REPO right now
                               (grounded-critical). A human-traced + PoC-validated subset is the real headline.
  2. INSTALL-LIABILITY       — a dangerous capability (code_exec / deserialize / shell) that is NOT reachable
                               from THIS repo's own entrypoints, so it is inert here — BUT it becomes a live
                               attack surface the moment a new user installs/wires the tool into an agent that
                               feeds it untrusted input. The risk you INHERIT on install.
  3. TOTAL action-surfaces found.
  4. % of the repo scanned (coverage — honesty about what we did NOT see).

This is honest tiering, not inflation: install-liability is explicitly labelled "inert here, live on install",
never "exploitable in this repo".
"""
from __future__ import annotations
from pathlib import Path

# capabilities that become REMOTE CODE EXECUTION when an untrusted input is wired to them
_RCE_CAPS = {"code_exec", "deserialize", "subprocess_exec", "ssti"}
# broader dangerous-action capabilities (write/act) — inherited too, lower severity
_ACT_CAPS = {"external_write", "file_write", "file_delete", "tool_invoke", "publish_write", "secret_exfil"}


# ---- OWASP Risk Rating (Severity x Likelihood -> Low/Med/High). Refs: OWASP Risk Rating Methodology;
# NIST SP 800-30 Rev.1 (5-level qualitative scales + Risk-Level Matrix); ISO/IEC 27005. (S8.66) ----
_SEVERITY = {
    "code_exec": 5, "ssti": 5, "deserialize": 5, "subprocess_exec": 5,   # RCE
    "secret-exfil": 4, "secret_exfil": 4,                                 # data breach
    "external_write": 3, "file_write": 3, "file_delete": 3, "tool_invoke": 3, "publish_write": 3,
    "queue_mutation": 2,
}
_RATING_ORDER = {"Low": 0, "Med": 1, "High": 2}


def risk_rating(capability, reachable, gated, poc, language="python", external_write_egress=False):
    """Severity(1-5) x Likelihood(1-5) -> index -> Low/Med/High, with honesty guardrails."""
    sev = 4 if (capability == "external_write" and external_write_egress) else _SEVERITY.get(capability, 3)
    guard_unknown = str(language).lower() not in ("python", "py")
    if not reachable:                 # install-liability — inert here
        lik = 1
    elif guard_unknown:               # TS/C# — guard model can't reason
        lik = 3
    elif gated:                       # a validated guard protects the sink
        lik = 2
    elif poc:                         # PROVEN-LIVE — human-traced + PoC
        lik = 5
    else:                             # candidate / non-gated, unproven
        lik = 4
    index = sev * lik
    rating = "High" if index >= 15 else ("Med" if index >= 8 else "Low")
    # G1: install-liability (not reachable here) capped at Med — inert, "live on install" not "exploitable here".
    if not reachable and _RATING_ORDER[rating] > _RATING_ORDER["Med"]:
        rating = "Med"
    return {"severity": sev, "likelihood": lik, "index": index, "rating": rating, "guard_unknown": guard_unknown}


# ---- INSTALL-LIABILITY rating (S8.86). The proven-live headline rates what is reachable+unguarded HERE.
# Install-liability is the RCE-class surface you INHERIT on install: inert in this repo, live the moment a
# downloader wires untrusted input to it. It was COUNTED but never RATED — the public dashboard shows a
# Low/Med/High on the inherited, the tool did not. This closes that coherence gap.
#
# Method (mirrors hermes_shield_site/app/public-scans): severity x AS-INSTALLED likelihood.
#   - AS-INSTALLED likelihood = 2 (moderate): a downloader must ACTIVELY wire untrusted input to the sink;
#     it is not reachable here, so likelihood is neither 1 (dead) nor 5 (proven-live) — it is "live on install".
#   - Per-surface rating is CAPPED AT MED — the sink is not reachable in THIS repo (inert here). SOUND-LEANING:
#     no single inherited surface is ever badged High off a static count.
#   - AGGREGATE band by RCE-class surface COUNT: Low <=16, Med 17-99, High >=100. The High band is an
#     aggregate-count SIGNAL (a large inherited attack surface), NOT a per-surface "exploitable here" verdict.
_AS_INSTALLED_LIK = 2
_INSTALL_BAND_MED_MIN = 17
_INSTALL_BAND_HIGH_MIN = 100


def _install_band(count: int) -> str:
    return ("High" if count >= _INSTALL_BAND_HIGH_MIN
            else "Med" if count >= _INSTALL_BAND_MED_MIN else "Low")


def install_liability_rating(surfaces) -> dict:
    """Rate the INHERITED (install-liability) RCE-class surfaces. `surfaces` = the install-liability list
    (RCE-class, not reachable-here). Returns the aggregate band + per-surface tallies. Per-surface is capped
    at Med (inert here); the aggregate High band is a count-signal only. See the module note above."""
    count = len(surfaces)
    per = {"High": 0, "Med": 0, "Low": 0}
    for s in surfaces:
        sev = _SEVERITY.get(getattr(s, "capability", ""), 5)   # RCE-class -> 5
        index = sev * _AS_INSTALLED_LIK
        rating = "High" if index >= 15 else ("Med" if index >= 8 else "Low")
        if _RATING_ORDER[rating] > _RATING_ORDER["Med"]:       # G1: inert here -> never above Med per-surface
            rating = "Med"
        per[rating] += 1
    return {
        "count": count,
        "band": _install_band(count),
        "as_installed_likelihood": _AS_INSTALLED_LIK,
        "per_surface": per,                # every RCE-class inherited surface rates Med (sev5 x lik2, capped)
        "bands": {"Low": "<=16", "Med": "17-99", "High": ">=100"},
        "method": "severity x as-installed-likelihood(2); per-surface capped at Med; aggregate band by RCE-class count",
        "note": "inert here, live on install — the High band is an aggregate-count signal, never a per-surface reachable-here verdict",
    }


def _coverage_pct(root: Path, files_scanned: int) -> float:
    """Coverage = scanned source files / scannable source files present.

    The denominator MUST use the SAME skip rules the scanner walks (patterns.SKIP_DIRS: .venv, build/dist
    artefacts under those, node_modules, site-packages, vendored code, ...). Counting files the scan
    deliberately skips would understate coverage (the old bug: a bare rglob("*.py") folded in .venv /
    site-packages, so a fully-scanned repo read as ~18% covered). We reuse repo_scanner's own iterators so
    the numerator and denominator can never drift, and count every language the scan actually walks
    (Python + TS/JS + C#) to match `files_scanned`."""
    from . import repo_scanner as _RS
    total = sum(1 for _ in _RS._iter_py(root))
    total += sum(1 for _ in _RS._iter_lang(root, ("*.ts", "*.tsx", "*.mts", "*.cts", "*.js", "*.mjs")))
    total += sum(1 for _ in _RS._iter_lang(root, ("*.cs",)))
    if total == 0:
        return 0.0
    return round(100.0 * min(files_scanned, total) / total, 1)


def build_report(root, scan, validated=None) -> dict:
    """validated = set of (file_substr, line) that a HUMAN traced + a harmless PoC confirmed. Only these are
    PROVEN-LIVE. The scanner's raw grounded-critical are CANDIDATES (may include false positives) — never
    presented as proven."""
    root = Path(root)
    validated = validated or set()
    # DETERMINISTIC HEADLINE = STATIC ONLY. Every count below (grounded_crit, candidate_crit, non_gated,
    # install_liab, vulnerable, candidate_high, proven_live, total) drives the RED/AMBER banner + the
    # "reachable in-repo" number, so it must be built from deterministic (detection_source == "static")
    # surfaces alone. AI-suspected surfaces are advisory (model GUESSES) and appear only in the dedicated
    # AI-suspected review section — never here. On an AI-off scan this filter is a no-op (byte-identical).
    surfaces = [s for s in scan.get("surfaces", [])
                if getattr(s, "context", "prod") == "prod"
                and getattr(s, "detection_source", "static") == "static"]
    total = len(surfaces)
    grounded_crit = [s for s in surfaces if getattr(s, "verdict", "") == "UNGUARDED_CRITICAL_LIVE_SINK"]

    def _is_validated(s):
        ln = getattr(s, "sink_line", 0) or s.line_start
        return any(fs in s.file_path and ln == vl for fs, vl in validated)

    # 1. CANDIDATE-CRITICAL: scanner grounded-critical RCE-class — flagged, UNVALIDATED (some are FPs).
    candidate_crit = [s for s in grounded_crit if s.capability in _RCE_CAPS]
    # 1b. PROVEN-LIVE: only the human-traced + PoC-confirmed subset. Empty unless a validated set is supplied.
    proven_live = [s for s in surfaces if s.capability in _RCE_CAPS and _is_validated(s)]
    # 2. INSTALL-LIABILITY: RCE-class sinks present but NOT grounded-critical (inert here, live on install).
    install_liab = [s for s in surfaces if s.capability in _RCE_CAPS and s not in candidate_crit and not _is_validated(s)]
    # broader inherited action capabilities (write/act) not proven-live
    act_liab = [s for s in surfaces if s.capability in _ACT_CAPS and getattr(s, "verdict", "") != "UNGUARDED_CRITICAL_LIVE_SINK"]

    coverage = _coverage_pct(root, scan.get("files_scanned", 0))

    # ---- OWASP risk rating -> the HEADLINE comes from PROVEN-LIVE ONLY (team ruling: a candidate must never
    # drive a severity badge). Candidate-High is counted SEPARATELY, shown un-badged as "needs validation". ----
    proven_counts = {"High": 0, "Med": 0, "Low": 0}
    candidate_high = 0
    for s in surfaces:
        if s.capability in (_RCE_CAPS | _ACT_CAPS):
            poc = _is_validated(s)
            lang = getattr(s, "language", "python")
            if poc:
                # a PoC-proven finding IS proven reachable + unguarded (we ran it) -> likelihood 5, even if the
                # static scanner buried it as non-reachable. This is the empirical evidence overriding the static.
                r = risk_rating(s.capability, True, False, True, lang)
                proven_counts[r["rating"]] += 1
            else:
                gated_flag = getattr(s, "verdict", "") != "UNGUARDED_CRITICAL_LIVE_SINK" and getattr(s, "tainted_reachable", False)
                r = risk_rating(s.capability, getattr(s, "tainted_reachable", False), gated_flag, False, lang)
                if r["rating"] == "High":
                    candidate_high += 1
    # headline rating from PROVEN evidence only; "None" when nothing is PoC-confirmed (never "High" off candidates)
    overall = ("High" if proven_counts["High"] else "Med" if proven_counts["Med"]
               else "Low" if proven_counts["Low"] else "None (no proven-live)")
    risk_counts = proven_counts   # back-compat name; these are now PROVEN-only

    # ---- kicker metrics: gated vs non-gated VULNERABLE surfaces ----
    _VULN_CAPS = _RCE_CAPS | _ACT_CAPS
    vulnerable = [s for s in surfaces if s.capability in _VULN_CAPS]
    # NON-GATED vulnerable = reachable + unguarded (the live-threat kicker)
    non_gated = [s for s in vulnerable if getattr(s, "verdict", "") == "UNGUARDED_CRITICAL_LIVE_SINK"]
    # GATED vulnerable = reachable dangerous sink that a guard/mitigation downgraded (present but protected)
    gated = [s for s in vulnerable if getattr(s, "tainted_reachable", False)
             and getattr(s, "verdict", "") != "UNGUARDED_CRITICAL_LIVE_SINK"]
    # language mix + the honesty caveat (guard model is Python-only)
    langs = {}
    for s in surfaces:
        langs[getattr(s, "language", "python")] = langs.get(getattr(s, "language", "python"), 0) + 1
    non_python = sum(v for k, v in langs.items() if k != "python")

    def _row(s):
        return {"file": s.file_path, "line": getattr(s, "sink_line", 0) or s.line_start,
                "capability": s.capability, "verdict": getattr(s, "verdict", "")}

    return {
        "repo": root.name,
        # --- OWASP risk rating: headline from PROVEN-LIVE only; candidates counted, never badged ---
        "overall_rating": overall,                 # driven by PoC-proven findings ONLY
        "risk_ratings": risk_counts,               # PROVEN-only High/Med/Low
        "candidate_high": candidate_high,          # high-risk CANDIDATES (unvalidated, may include FPs) - needs validation
        # --- the locked metric model  ---
        "files_scanned": scan.get("files_scanned", 0),
        "coverage_pct": coverage,
        "total_action_surfaces": total,
        "vulnerable_surfaces": len(vulnerable),
        "non_gated_vulnerable": len(non_gated),          # KICKER: live threat, no guard
        "gated_vulnerable": len(gated),                  # present but a guard/mitigation protects it
        "proven_live_poc": len(proven_live),             # human-traced + PoC-confirmed subset (never the raw count)
        "install_liability_rce": len(install_liab),      # inert here, live on install
        "install_liability_rating": install_liability_rating(install_liab),   # OWASP band on the INHERITED (S8.86)
        "language_mix": langs,
        "guard_model_note": ("python-only" if non_python else "python"),   # gated/non-gated only trustworthy for python
        # --- detail lists ---
        "proven_live": {"count": len(proven_live), "items": [_row(s) for s in proven_live]},
        "candidate_critical": {"count": len(candidate_crit), "items": [_row(s) for s in candidate_crit]},
        "non_gated_items": [_row(s) for s in non_gated[:50]],
    }


def render(report: dict) -> str:
    r = report
    rc = r["risk_ratings"]
    L = []
    L.append(f"# Hermes Shield — action-surface report: {r['repo']}")
    L.append("")
    L.append(f"## OVERALL RISK: {r['overall_rating']}   (OWASP Severity x Likelihood — PROVEN-LIVE only)")
    L.append(f"- **Proven-live rated** — High:{rc['High']} · Med:{rc['Med']} · Low:{rc['Low']}")
    L.append(f"- **⚠ {r['candidate_high']} high-risk CANDIDATES** — unvalidated, may include false positives; need a human trace + PoC before they count. NOT a severity verdict.")
    L.append(f"- **Repo scanned:** {r['coverage_pct']}% ({r['files_scanned']} files) · guard model: {r['guard_model_note']}")
    L.append(f"- **Total action-surfaces:** {r['total_action_surfaces']} · **vulnerable:** {r['vulnerable_surfaces']}")
    L.append(f"- **Non-gated (live threat):** {r['non_gated_vulnerable']} · **Gated (protected):** {r['gated_vulnerable']}")
    L.append("")
    L.append(f"## 🔴 PROVEN-LIVE (human-traced + PoC-confirmed): {r['proven_live']['count']}")
    L.append("Reachable + unguarded HERE now AND empirically proven — we ran the sink with a benign payload.")
    for it in r["proven_live"]["items"]:
        L.append(f"  - {it['file']}:{it['line']} [{it['capability']}]  ✓ PoC")
    L.append("")
    L.append(f"## 🟡 CANDIDATE-CRITICAL (scanner-flagged, UNVALIDATED): {r['candidate_critical']['count']}")
    L.append("Grounded-critical per the static scanner but NOT yet human/PoC-confirmed — some are false positives.")
    L.append("Never sent to anyone until a human traces + a PoC confirms each one.")
    L.append("")
    ilr = r.get("install_liability_rating", {})
    band = ilr.get("band", "Low")
    L.append(f"## 🟠 INSTALL-LIABILITY (RCE-class): {r['install_liability_rce']}  ·  inherited rating: {band}")
    L.append("Inert in THIS repo (no local entrypoint reaches them) — but a live attack surface the moment a new")
    L.append("user installs/wires this tool into an agent that feeds it untrusted input. The risk you INHERIT.")
    L.append(f"- **Inherited rating: {band}** — OWASP severity×likelihood at an as-installed likelihood "
             f"({ilr.get('as_installed_likelihood', 2)}); per-surface capped at Med (inert here). The "
             f"High band (≥100) is an aggregate-count signal of a large inherited attack surface, NOT a "
             f"per-surface 'exploitable here' verdict. Bands: Low ≤16 · Med 17-99 · High ≥100.")
    return "\n".join(L)
