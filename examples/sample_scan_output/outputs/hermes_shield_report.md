# Hermes Shield — action-surface report: vulnerable_agent

## OVERALL RISK: None (no proven-live)   (OWASP Severity x Likelihood — PROVEN-LIVE only)
- **Proven-live rated** — High:0 · Med:0 · Low:0
- **⚠ 1 high-risk CANDIDATES** — unvalidated, may include false positives; need a human trace + PoC before they count. NOT a severity verdict.
- **Repo scanned:** 100.0% (2 files) · guard model: python
- **Total action-surfaces:** 4 · **vulnerable:** 3
- **Non-gated (live threat):** 1 · **Gated (protected):** 0
- **Reachable actions — review (amber):** 0 — reachable + unguarded reversible/social actions (post/reply/like); lower blast-radius than the red band.
- **Fixed-destination sends — review (amber):** 0 — reachable + unguarded messaging/external sends to a proven fixed (config/constant) destination; tainted content, not exfil, but never a clean bill.

## 🔴 PROVEN-LIVE (human-traced + PoC-confirmed): 0
Reachable + unguarded HERE now AND empirically proven — we ran the sink with a benign payload.

## 🟡 CANDIDATE-CRITICAL (scanner-flagged, UNVALIDATED): 1
Grounded-critical per the static scanner but NOT yet human/PoC-confirmed — some are false positives.
Never sent to anyone until a human traces + a PoC confirms each one.

## 🟠 REACHABILITY UNKNOWN — verify manually: 1
These RCE-class sinks are **NOT proven inert** in this repo. We could not trace an in-repo
caller, but an untrusted ingress (e.g. an HTTP route) is present and dynamic/cross-module dispatch could not be resolved, so an untrusted request may reach them along a path the static tracer
could not follow. This is **reachability not proven — verify manually**, NOT 'inert here /
not reachable'. A sink reachable from an untrusted route is live here, not install-liability.
  - tools.py:5 [subprocess_exec]  — trace from the ingress + PoC to confirm

## 🟠 INSTALL-LIABILITY (RCE-class): 0
Proven inert in THIS repo (no local entrypoint AND no untrusted ingress/unresolved dispatch reaches
them) — but a live attack surface the moment a new user installs/wires this tool into an agent that
feeds it untrusted input. The risk you INHERIT. (Sinks we could not prove inert are listed above
under REACHABILITY UNKNOWN, not here.)