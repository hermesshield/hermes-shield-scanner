# Hermes Shield — Excessive-Agency Report
<!-- SECTION 1 — COVER / IDENTITY -->
**Repo:** `vulnerable_agent`  ·  **Files scanned:** 2  ·  **Scanned:** 2026-07-20  ·  **Scanner:** v0.8.0
**Repo kind:** `app` (high confidence — runnable routes/webhooks present and no publish target — this runs its own entrypoints)

> Read-only static analysis — the target code is never executed and the deterministic core makes no network
> calls. Maps to **OWASP LLM06 (Excessive Agency)**: it reports the dangerous ACTIONS an AI agent could be
> tricked into, and whether a control is *written* before each — it does NOT prove a control runs/blocks/is
> deployed. Findings marked _AI_ are model-proposed and MUST be human-verified.

## 2. Executive summary
**4 actions mapped; 1 reachable-now; 1 need a human trace; install-liability N/A — nobody installs an app; 0 proven-live.**

**OWASP LLM06 verdict:** No full exploit demonstrated (proven-live 0), but 1 reachable with no control and 1 not proven safe — act now.

## 3. Severity-first scoreboard
| Metric | Count | Severity |
|---|---|---|
| dangerous actions your agent can take (mapped) | **4** | the map |
| already reachable by untrusted input (unguarded) | **1** | DANGEROUS — act now |
| needs a human trace — not proven safe | **1** | UNRESOLVED — verify |
| install-liability | N/A — nobody installs an app (its risk is what is reachable now, above) | N/A (app) |
| we made it fire (0 = untested, not a clean bill of health) | **0** | not tested (not a clean bill) |
| below-critical-line (review manually) | 0 | review |
| AI-suspected (advisory) | 0 | advisory — verify |

- **1 with NO control found** — reachable now by untrusted input with nothing in the way; each
  fix-plan item below carries its real tier (fix-first / reachable-action review / wiring-time).
- **install-liability = inert here, live on install** — a dangerous capability that is harmless in this repo
  but live the moment someone installs it and wires untrusted input to it. For an APP this is N/A: nobody installs an app.
- **proven-live = 0** — proven_live=0 means **not demonstrated**, never "secure". A zero is the
  absence of a proof, never a clean bill of health; it is **untested, not safe**.

## 4. Already reachable by untrusted input (unguarded) — start here
> An untrusted input can reach these dangerous actions with no control in the way, today. Fix these first.
> **Each fix is really two jobs: write a correct control, then prove it blocks.** The deterministic Repairer does both today on real repos — it applies the control as a reviewed diff, then re-runs the real attack and proves this sink flips from exploitable to blocked (RED→PROTECTED), re-verified by the same scanner (human-gated, never auto-fix). The AI-assist tier is in early access.
> → Early access: hermesshield.ai/repairer

- `app.py:9`  **code execution**  _(reachable now — fix first)_

## 5. Needs a human trace — not proven safe
> RCE-class sinks we could **not prove inert** — an untrusted ingress (e.g. an HTTP route) and/or dynamic
> dispatch the tracer could not resolve is present, so a request may reach them along a path we could not
> follow. This is **reachability not proven — verify manually**, never "not reachable". An analysis limit is
> not a safety fact.
- `tools.py:5`  **shell / subprocess**  _(needs a human trace — not proven safe)_

## 6. Fix plan — generated, not applied
> Fix-at-source controls for the findings that need one. Each is TWO steps: **Step 1** the control, **Step 2**
> the adversarial proof-test that shows it actually blocks.
> **The scanner plans these; it does not modify your code.**
>
> **A control applied is not a control proven — a plausible fix can still be bypassed; the only way to KNOW is to re-run the attack.**
>
> **4 sinks in this plan × (write a correct control + write a proof it blocks + re-verify closure).** The deterministic Repairer delivers each as a reviewed diff with the proof attached.
> The **deterministic Repairer does this today on real repos**: it applies the control as a reviewed diff,
> then **re-runs the real attack and proves the sink flips from exploitable to blocked (RED→PROTECTED),
> re-verified by the same scanner** — under a human gate, never auto-fix. The **AI-assist tier is in early
> access** (hermesshield.ai/repairer).

_**4 fix-cards** below de-noise the **4-row** machine inventory in `hermes_patch_plan.json` — grouped by the single control point each shares; every row is preserved in the JSON (the Repairer feed), nothing is dropped._

### FIX THESE FIRST — top 5 (ranked by leverage = sites-closed × severity)
1. **the dynamic-exec call site (replace eval/exec with a safe parse)** — one fix closes **1 site** (code_exec, severity 5; leverage 5).
2. **the subprocess launcher (shell=False + arg allowlist)** — one fix closes **1 site** (subprocess_exec, severity 5; leverage 5).
3. **the dashboard-mutation middleware (CSRF token + Origin allowlist)** — one fix closes **1 site** (dashboard_mutation, severity 3; leverage 3).
4. **the outbound-write boundary (destination allowlist)** — one fix closes **1 site** (external_write, severity 3; leverage 3).

### Fix cards — one card per control point (fix these first: top 5, above)
- **the dynamic-exec call site (replace eval/exec with a safe parse)** · fix now — no control present · one fix closes **1 site** (code_exec)
    - **The one control:** Replace eval/exec with ast.literal_eval (Python eval sandboxes are trivially escaped, so never rely on one); if dynamic code is genuinely required, allowlist the inputs and human-gate the call.
    - **Prove it blocks:** Add a test that drives code_exec with a hostile input and asserts the control blocks it (and that a benign input still passes).
    - **Covers:** `app.py:7`
- **the subprocess launcher (shell=False + arg allowlist)** · fix now — no control present · one fix closes **1 site** (subprocess_exec)
    - **The one control:** Run with shell=False and an argument allowlist; never interpolate model or user output into the command string.
    - **Prove it blocks:** Add a test that drives subprocess_exec with a hostile input and asserts the control blocks it (and that a benign input still passes).
    - **Covers:** `tools.py:4`
- **the dashboard-mutation middleware (CSRF token + Origin allowlist)** · review — certify, then gate · one fix closes **1 site** (dashboard_mutation)
    - **The one control:** Require a CSRF token plus an Origin allowlist on the dashboard mutation endpoint.
    - **Prove it blocks:** Add a test that drives dashboard_mutation with a hostile input and asserts the control blocks it (and that a benign input still passes).
    - **Covers:** `app.py:7`
- **the outbound-write boundary (destination allowlist)** · review — certify, then gate · one fix closes **1 site** (external_write)
    - **The one control:** Gate outbound writes behind a destination allowlist plus human approval; never send to a host derived from untrusted input.
    - **Prove it blocks:** Add a test that drives external_write with a hostile input and asserts the control blocks it (and that a benign input still passes).
    - **Covers:** `app.py:6`

<details><summary>Full per-site fix rows (every call site — rolled up, not capped)</summary>

- `app.py:9` · **code execution** · tier: reachable-in-repo · status: **PLANNED — not applied**
    - **Step 1 — apply the control:** Replace eval/exec with ast.literal_eval (Python eval sandboxes are trivially escaped, so never rely on one); if dynamic code is genuinely required, allowlist the inputs and human-gate the call.
    - **Step 2 — prove it's actually blocked:** a test that drives this sink with hostile input and asserts it's blocked (benign still passes). Add a test that drives code_exec with a hostile input and asserts the control blocks it (and that a benign input still passes).
- `tools.py:5` · **shell / subprocess** · tier: reachability unknown — verify, then gate · status: **PLANNED — not applied**
    - **Step 1 — apply the control:** Reachability not proven (untrusted ingress / unresolved dispatch present) — trace from the ingress first. Run with shell=False and an argument allowlist; never interpolate model or user output into the command string.
    - **Step 2 — prove it's actually blocked:** a test that drives this sink with hostile input and asserts it's blocked (benign still passes). Add a test that drives subprocess_exec with a hostile input and asserts the control blocks it (and that a benign input still passes).
- `app.py:6` · **outbound write** · tier: review — no control present; certify reachability & gate · status: **PLANNED — not applied**
    - **Step 1 — apply the control:** Gate outbound writes behind a destination allowlist plus human approval; never send to a host derived from untrusted input.
    - **Step 2 — prove it's actually blocked:** a test that drives this sink with hostile input and asserts it's blocked (benign still passes). Add a test that drives external_write with a hostile input and asserts the control blocks it (and that a benign input still passes).
- `app.py:7` · **dashboard write** · tier: review — no control present; certify reachability & gate · status: **PLANNED — not applied**
    - **Step 1 — apply the control:** Require a CSRF token plus an Origin allowlist on the dashboard mutation endpoint.
    - **Step 2 — prove it's actually blocked:** a test that drives this sink with hostile input and asserts it's blocked (benign still passes). Add a test that drives dashboard_mutation with a hostile input and asserts the control blocks it (and that a benign input still passes).

</details>

### Discovered attack surfaces by capability
- **dashboard_mutation** — 1
- **code_exec** — 1
- **external_write** — 1
- **subprocess_exec** — 1

### AI-suspected surfaces — advisory, human MUST verify
> Found by the optional AI-assist tier (any coding agent) on files the static rules missed, each AST-verified
> as a real call. **NOT counted** in the scoreboard above — advisory only. Treat as leads to review, not
> confirmed findings.
- (none — AI tier off or nothing found)

## 7. Methodology, scope & honest blind spots
Static excessive-agency analysis for OWASP LLM06: it assumes prompt-injection succeeds and maps what a
hijacked agent could then DO — the target is read in place, never executed. Severity is **reachability-rated**:
reachable-in-repo is live now; install-liability is inherited on wiring.

**Blind spots (not covered — a "no finding" is not a proof of safety):** dynamic dispatch, runtime config,
cross-process stores and non-Python surfaces are not reachability-reasoned. Source coverage (100.0% of scannable source)
is how much scannable source we actually read; **control coverage** (0% of critical sinks
with a declared guard) is only accurate once YOUR control functions are declared in the guard config.

---
*Honest-scope: "coverage / gap-finder", not a containment proof.*
