<div align="center">

<img src="https://raw.githubusercontent.com/hermesshield/hermes-shield-scanner/main/docs/assets/banner.png" alt="Hermes Shield — Protect every action your agent takes" width="100%" />

# Hermes Shield Scanner

**The actions firewall for AI agents — map and prove what a hijacked agent can actually do.**

[![CI](https://github.com/hermesshield/hermes-shield-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/hermesshield/hermes-shield-scanner/actions/workflows/ci.yml)
[![Python 3.10–3.13](https://img.shields.io/badge/python-3.10%E2%80%933.13-blue)](pyproject.toml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)
[![OWASP LLM06](https://img.shields.io/badge/OWASP%20LLM06-Excessive%20Agency-FA7D09)](https://genai.owasp.org/)
[![Runs 100% local](https://img.shields.io/badge/runs-100%25%20local-FF4301)](#-quickstart)

[**hermesshield.ai**](https://hermesshield.ai) · [Free scan](https://hermesshield.ai/free-scan) · [Methodology](https://hermesshield.ai/methodology) · [@hermesshield](https://x.com/hermesshield)

**Catches a real CVSS 9.8 CVE at the documented line · 12 frameworks / 361k+ stars audited · independently security-assessed, twice**

</div>

---

> **Assume the model will fail. The dangerous action still must not execute.**

Every serious team now filters prompts. Almost nobody governs **actions**. But prompt filters stop *text* — a hijacked agent still *acts*: it runs shell commands, executes code, writes files, sends data out, calls tools. That is where the damage happens.

**Hermes Shield sits downstream of the injection.** The Scanner is step one: it maps every dangerous action your agent's code can take, traces each one back to a real entry point, and **proves** which are reachable by untrusted input with no guard in the way. Not a suspicious variable name. A traced path.

> **Every agent has a blast radius. See yours in one scan.**

## `▸ the_problem`

The risk in AI systems has moved. It's no longer "the model said something bad" — it's **"the model did something unauthorised"**. OWASP calls it **LLM06: Excessive Agency**. One injected instruction, and your helpful agent is executing someone else's intent with *your* credentials, *your* filesystem, *your* network.

|  | Prompt firewall | **Hermes Shield** |
|---|---|---|
| **Asks** | "Is this prompt malicious?" | **"What can this agent actually DO?"** |
| **Layer** | Input text | **Action execution** |
| **When injection succeeds** | Already bypassed | **Still standing — governs the act itself** |
| **Evidence** | Heuristic score | **Traced path from entry point to sink** |

> Prompt filters stop text. Agents need action control.

And no — this is not "just static analysis". It is **deterministic static analysis + an optional AI-assisted recall tier + proved reachability**: entrypoint-grounded taint tracing over the whole-repo call graph, so a finding isn't a guess about what *might* be dangerous — it's a demonstrated route from *your* entry points to a live sink.

## `▸ see_it`

<div align="center">

<img src="https://raw.githubusercontent.com/hermesshield/hermes-shield-scanner/main/docs/assets/cli.png" alt="Hermes Shield Scanner running a live scan in the terminal" width="720" />

*The scan, live: sinks mapped, taint traced from real entry points, guards attributed — deterministic and fully local.*

<img src="https://raw.githubusercontent.com/hermesshield/hermes-shield-scanner/main/docs/assets/report.png" alt="The Hermes Shield customer report with its antivirus-style verdict banner" width="720" />

*The report: an antivirus-style verdict a non-technical reader gets in one glance, backed by evidence an auditor can verify line by line.*

</div>

## `▸ quickstart`

```bash
pip install hermes-shield-scanner

hermes-shield demo                       # a real red report in ~10 seconds
cd your-agent-repo
hermes-shield scan                       # scan your own agent
```

Your report lands at **`./shield-report/outputs/shield_customer_report.html`** — open it in a browser.

Zero-install, straight from the toolchain:

```bash
uvx hermes-shield-scanner scan .
```

**Requirements:** Python 3.10+. The core scanner is **stdlib-only** — no runtime dependencies, nothing phones home, and the scan is **read-only**: it never writes to your code and, by default, never executes it. Reports land in *your* directory; everything runs on your machine. *(The one opt-in exception is `--prove` — below — which fires a benign canary inside a network-denied sandbox to promote a candidate to PROVEN-LIVE. Consent-gated, off by default, Linux + bubblewrap.)*

**Languages:** Python gets the **full engine** — sinks, taint, guards, reachability. TypeScript/JavaScript and C# are **sink-mapping only** (blast radius, no reachability verdict) via `pip install "hermes-shield-scanner[multilang]"`; `--semgrep` adds ~30-language breadth.

More modes, one command each:

```bash
hermes-shield scan ./repo --semgrep      # + semgrep comparator (multi-language breadth)
hermes-shield scan ./repo --ai           # + AI-assist tier (novel-sink recall)
hermes-shield scan ./repo --all          # core + semgrep + ai together
hermes-shield scan ./repo --deps         # + scan the repo's own pinned dependencies
hermes-shield scan ./repo --prove        # + sandboxed self-attack: PROVE a candidate sink is live (consent-gated)
hermes-shield diff ./repo                # scan + compare against a saved baseline
```

`hermes-shield demo` scans a bundled, deliberately vulnerable toy agent (shipped inert, never executed) and produces the full report — including a guaranteed worst-case verdict — so you see exactly what a red result looks like before you point it at anything real. (`demo --prove` is the consent-gated exception: it runs the fixture inside the sandbox to show a real PROVEN-LIVE result.)

> **CI note — the exit code is `0` regardless of findings.** A RED report does not fail the process; the scan writes its verdict to the report and the JSON, it does not signal via the exit status. To gate a pipeline on findings, parse `shield-report/outputs/hermes_shield_report.json` (e.g. check the verdict / reachable-unguarded / proven-live counts). A dedicated `--fail-on` flag is a planned future enhancement, not available today.

## `▸ how_it_works` — Map → Trace → Prove

**1. Map.** A deterministic AST engine walks the whole repository and finds every dangerous action sink: shell execution, code execution, deserialisation, file writes, outbound network sends, LLM-chosen tool calls. Same input, same output, every run — an auditor can reproduce it.

**2. Trace.** It builds the whole-repo call graph and runs **entrypoint-grounded taint analysis**: does untrusted input — a web request, a document, a tool result, a model output — actually flow from a real entry point to that sink? Intra- and inter-procedural, across modules.

**3. Prove.** Every reachable sink is checked against the **guard quadrant** — reachable × guarded:

| | **Guarded** | **Unguarded** |
|---|---|---|
| **Reachable** | Rated, credit given for the guard | **`UNGUARDED_CRITICAL_LIVE_SINK`** — the worst verdict, reserved for this square alone |
| **Not reached** | Noted | Install-liability tier |

Only a sink that is **reachable AND unguarded** earns the critical verdict. A guard between entry point and sink is detected and credited — kill-switches, approval gates, untrusted-content fences, plus your own guard functions via a one-file `.hermes-shield.json` declaration (downgrade-only: a declared guard can lower a finding, its absence never hides one).

Findings are rated on the **OWASP LLM06** model — severity × likelihood, cross-referenced to **NIST 800-30** and **ISO 27005** — so the output slots straight into a real risk register.

**The optional tiers:**

- **`--ai`** — the recall booster. An LLM proposes *novel* sinks the static rules missed; every proposal is **AST-verified** before it's kept, and confirmed patterns become permanent static rules. **The scanner gets stricter over time.** AI findings live in a separate advisory tier — never counted in the deterministic headline. Uses your own local `claude` CLI; off by default.
- **`--semgrep`** — an isolated comparator tier (~30 languages) for breadth. Attributed separately, never merged into the core headline.
- **`--deps`** — the **install-inherited** scan. Fetches the repo's *own pinned* packages (wheels only — never installed, never executed) and scans them with the same engine. Catches the dangerous capability that lives in a dependency rather than your tree — what you inherit the moment you `pip install`. Off by default (it reaches the network).

## `▸ the_report`

The report is built to be read by two people at once: the founder who needs a verdict, and the engineer who needs the evidence.

**The verdict banner** — antivirus-style, one glance:

- 🔴 **Action needed** — a proven-live or reachable-unguarded finding exists. Fix first.
- 🟠 **Review before you ship** — install-liability present: inert here, live on install.
- 🔵 **No live threat proven** — clean run. Deliberately *never* worded "secure".

**The two tiers** — because "exploitable now" and "inherited on install" are different risks, and honest tooling refuses to blur them:

| Tier | Meaning |
|---|---|
| **Reachable-in-repo** | Live **now**, from your own entry points, unguarded. Fix first. |
| **Install-liability** | **Inert here, live on install.** A dangerous capability not reached from this repo's entry points — but the moment someone wires this code into an agent that feeds it untrusted input, they inherit it. You downloaded it; you inherited the risk. |

**PROVEN-LIVE** is the strictest tier of all: PoC-confirmed findings — either human-traced, or proved by the opt-in **`--prove`** lane, which fires a benign, unguessable canary at a candidate sink inside a network-denied sandbox (with a clean negative control) and only promotes it if the attack actually lands. It is the only tier that ever gets a severity badge, and promotion is one-way: a failed proof leaves a finding a *candidate*, never marks it safe. Raw scanner criticals are candidates — counted, never badged. If the proven-live set is empty, the report says so, plainly.

And the line we will never soften: **a clean result means "no path was proven" — never "secure".** Reachability analysis proves a sink *is* reachable; it cannot prove one *is not*. Most tools hide that asymmetry. We print it on the report, because a security tool that overstates its own certainty is part of the attack surface.

> **PROVE, DON'T GUESS.**

## `▸ prove_dont_guess` — proof it's real

- **It catches a real 9.8.** [CVE-2023-39662](https://nvd.nist.gov/vuln/detail/CVE-2023-39662) — the CVSS 9.8 remote-code-execution flaw in LlamaIndex's `PandasQueryEngine` — is flagged by the scanner **at the exact documented line, on the genuinely vulnerable release** (`llama-index` v0.7.13; patched upstream since). A detector proof against a third-party-documented CVE — not a benchmark we wrote for ourselves, and not a claim about current LlamaIndex.
- **12 open-source agent frameworks audited** — over **361,000 combined GitHub stars**, every repo pinned to a commit — mapping **8,509 action surfaces**: **474 proved reachable** from a real entry point by entrypoint-grounded taint tracing, and **520 install-liability capabilities** you'd inherit the moment you install (the two are distinct risks, counted separately). The per-framework counts and pinned commits are in **[BENCHMARKS.md](BENCHMARKS.md)**.
- **Independently security-assessed — twice.** A third-party firm assessed the scanner, then re-assessed the fixed build: the latest assessment confirmed **0 critical and 0 high** findings in the shipped deterministic core, and **every** finding it raised, at any severity, was remediated in the next release and locked in with the auditor's own regression tests. The tool that grades your attack surface has had its own graded — and published the loop.
- **Deterministic where it counts.** The core engine is reproducible byte-for-byte — an auditor can re-run the scan and get the same numbers. The honest caveats above aren't hedges; they're the reason the numbers can be trusted.

## `▸ the_ladder` — find it free · fix it · shield it

| | Product | What it does | Status |
|---|---|---|---|
| 🔍 | **Scanner** | **Discovery** — map, trace and prove your agent's action surface. This repo. | **Free · here now** |
| 🔧 | **Repairer** | Applies the fixes — diff-proposed, **human-approved, never auto-fix**, re-scanned to confirm. | **Paid · coming — [join early access](https://hermesshield.ai/register-interest)** |
| 🛡️ | **Shield** | Always-on runtime action firewall — **Kill Switch, Action Gates, Audit Trail** on every action the agent takes. | **Paid · private beta** |
| 🏛️ | **Enterprise** | Custom deployment, compliance mapping, dedicated support. | [Talk to us](mailto:hello@hermesshield.ai) |

The Scanner shows you the blast radius. The Repairer closes it. The Shield keeps it closed while the agent runs.

## `▸ contributing`

Found a bug or a sink we missed? **Open an issue** — a missed-detection report with a minimal repro is the most valuable thing you can send us. Vulnerabilities in the scanner itself go to [SECURITY.md](SECURITY.md), privately. And if a scan taught you something about your own agent, **star the repo** — it helps other builders find their blast radius too.

## `▸ links`

- **Website:** [hermesshield.ai](https://hermesshield.ai) · [Free scan](https://hermesshield.ai/free-scan) · [Methodology](https://hermesshield.ai/methodology) · [Scanner](https://hermesshield.ai/scanner)
- **X:** [@hermesshield](https://x.com/hermesshield) (company) · [@harleyfoote_](https://x.com/harleyfoote_) (founder) · [@fridayresearch_](https://x.com/fridayresearch_)
- **LinkedIn:** [Hermes Shield](https://www.linkedin.com/company/hermes-shield)
- **Email:** [hello@hermesshield.ai](mailto:hello@hermesshield.ai)

Deeper reading in this repo: [ARCHITECTURE.md](ARCHITECTURE.md) (full design + honest limitation list) · [FOR_AUDITORS.md](FOR_AUDITORS.md) · [CHANGELOG.md](CHANGELOG.md) · [SECURITY.md](SECURITY.md) (vulnerability disclosure).

---

<div align="center">

**Hermes Shield** · built where the agents run.

Licensed under [Apache-2.0](LICENSE) · Report a vulnerability via [SECURITY.md](SECURITY.md)

*Local. Read-only. Yours.*

</div>
