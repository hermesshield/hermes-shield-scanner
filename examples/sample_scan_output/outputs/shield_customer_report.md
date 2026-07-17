# Hermes Shield — Discovery & Coverage Report
**Repo:** `vulnerable_agent`  ·  **Files scanned:** 2

> Read-only static analysis. Maps to OWASP LLM06 (Excessive Agency). It reports the dangerous ACTIONS an
> AI agent could be tricked into, and whether a control is *written* before each — it does NOT prove a
> control runs/blocks/is deployed. Findings marked _AI_ are model-proposed and MUST be human-verified.

## Summary
- **Dangerous action-surfaces discovered:** 4
- **Have a control (present, unverified):** 0  (0% coverage)
- **NO control found — fix first:** 2
- **Gate looks FAKE (no-op / fail-open):** 0
- **AI-suspected surfaces (model-proposed, review):** 0
- **Install-liability (RCE-class inherited):** 2  ·  inherited rating: Low
- **Proven-live (PoC-confirmed) critical:** 0

## Honest scope — read this before you act
- **Install-liability = inert here, live on install.** The 2 inherited RCE-class surfaces are
  NOT reachable from this repo's own entrypoints today — they are inert here, live on install: they become a
  live attack surface the moment a downloader wires untrusted input into them. This is NOT a "vulnerability"
  in this repo and is never reported as one.
- **Proven-live = 0.** No critical finding here is PoC-confirmed — proven_live_poc=0 means
  **not demonstrated**, never "secure". A zero is the absence of a proof, not a clean bill of health.

## Discovered attack surfaces by capability
- **dashboard_mutation** — 1
- **code_exec** — 1
- **external_write** — 1
- **subprocess_exec** — 1

## 1. Actions with NO control — start here
- `app.py:7`  **code_exec**  (run)
- `tools.py:4`  **subprocess_exec**  (run_shell)

## 2. Gates that look FAKE — verify manually now
- (none)

## 3. Controls we could not prove reach the action
- (none)

## 4. Controls present but UNVERIFIED (polarity/reachability not machine-checked)
- (none)

## 5. AI-suspected surfaces — model-proposed, human MUST verify
> Found by the AI-assist tier (any coding agent) on files the static rules missed, each AST-verified as a
> real call. NOT counted in the coverage number above. Treat as leads to review, not confirmed findings.
- (none — AI tier off or nothing found)

---
*Honest-scope: "coverage / gap-finder", not a containment proof. Blind spots (dynamic dispatch, runtime
config, cross-process store, non-Python) are not covered and are documented in the threat model. Coverage
is only accurate once YOUR control functions are declared in the guard config.*
