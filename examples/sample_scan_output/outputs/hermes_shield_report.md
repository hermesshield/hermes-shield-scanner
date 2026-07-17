# Hermes Shield — action-surface report: vulnerable_agent

## OVERALL RISK: None (no proven-live)   (OWASP Severity x Likelihood — PROVEN-LIVE only)
- **Proven-live rated** — High:0 · Med:0 · Low:0
- **⚠ 0 high-risk CANDIDATES** — unvalidated, may include false positives; need a human trace + PoC before they count. NOT a severity verdict.
- **Repo scanned:** 100.0% (2 files) · guard model: python
- **Total action-surfaces:** 4 · **vulnerable:** 3
- **Non-gated (live threat):** 0 · **Gated (protected):** 0

## 🔴 PROVEN-LIVE (human-traced + PoC-confirmed): 0
Reachable + unguarded HERE now AND empirically proven — we ran the sink with a benign payload.

## 🟡 CANDIDATE-CRITICAL (scanner-flagged, UNVALIDATED): 0
Grounded-critical per the static scanner but NOT yet human/PoC-confirmed — some are false positives.
Never sent to anyone until a human traces + a PoC confirms each one.

## 🟠 INSTALL-LIABILITY (RCE-class): 2  ·  inherited rating: Low
Inert in THIS repo (no local entrypoint reaches them) — but a live attack surface the moment a new
user installs/wires this tool into an agent that feeds it untrusted input. The risk you INHERIT.
- **Inherited rating: Low** — OWASP severity×likelihood at an as-installed likelihood (2); per-surface capped at Med (inert here). The High band (≥100) is an aggregate-count signal of a large inherited attack surface, NOT a per-surface 'exploitable here' verdict. Bands: Low ≤16 · Med 17-99 · High ≥100.