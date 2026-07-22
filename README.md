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

**Catches a real CVSS 9.8 CVE at the documented line · 12 frameworks / 361k+ stars scanned · independently security-reviewed, twice**

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

## `▸ commands & flags`

**You never need a flag for a first scan.**

```bash
pip install hermes-shield-scanner        # installs the current public release (0.8.0)

hermes-shield demo                       # a real red report in ~10 seconds
cd your-agent-repo && hermes-shield scan # scan your own agent — auto-detects the enclosing git repo
```

**What happens when you run it:**

1. It runs a **live scan by default** on a terminal — a HUD maps the action surface as the scan climbs.
2. The **report opens itself** in your browser the moment the scan finishes.
3. It then **offers a deeper AI pass** (`--ai-deep`) you can accept or decline — that's the whole first run.

> **Version note:** `pip install` gets **0.8.0**, the current release. It supersedes 0.7.x with the actions-firewall verdict change (reachable, unguarded agent-action sinks now band RED/AMBER instead of a false BLUE) plus dedup worst-band hardening — an intentional, more-severe core change. Details in [CHANGELOG.md](CHANGELOG.md).

### First-run guide

```bash
pip install hermes-shield-scanner        # or, zero-install: uvx hermes-shield-scanner scan .
hermes-shield demo                       # see a real red report on a bundled toy agent first
```

Then scan **your own** repo, two ways:

```bash
cd your-agent-repo
hermes-shield scan                       # no path: AUTO-DETECTS the enclosing git repo
# — or —
hermes-shield scan ./path/to/repo        # point it at an explicit path
```

**Where the report lands** — `./shield-report/outputs/` in your current directory:

- **`shield_customer_report.html`** — the report for humans; open it in a browser (it opens itself on a terminal run).
- **`hermes_shield_report.json`** — the machine record; **gate CI on this**.

> **CI note — the exit code is always `0`, regardless of findings.** A RED report does not fail the process; the scan writes its verdict to the report and the JSON, it does not signal via the exit status. **To gate a pipeline, parse `hermes_shield_report.json`** (e.g. check the verdict / reachable-unguarded / proven-live counts). A dedicated `--fail-on` flag is a planned future enhancement, not available today.

**Requirements:** Python 3.10+. The core scanner is **stdlib-only** — no runtime dependencies, nothing phones home, and the scan is **read-only**: it never writes to your code and, by default, never executes it. Reports land in *your* directory; everything runs on your machine. *(The one opt-in exception is `--prove` — below — which fires a benign canary inside a network-denied sandbox to promote a candidate to PROVEN-LIVE. Consent-gated, off by default, Linux + bubblewrap.)*

**Languages:** Python gets the **full engine** — sinks, taint, guards, reachability. TypeScript/JavaScript and C# are **sink-mapping only** (blast radius, no reachability verdict) via `pip install "hermes-shield-scanner[multilang]"`; `--semgrep` adds ~30-language breadth.

`hermes-shield demo` scans a bundled, deliberately vulnerable toy agent (shipped inert, never executed) and produces the full report — including a worst-case red verdict — so you see exactly what a red result looks like before you point it at anything real. (`demo --prove` is the consent-gated exception: it runs the fixture inside the sandbox to show a real PROVEN-LIVE result.)

### Power-user flags (optional)

A first scan needs none of these — they are additive tiers over the default core scan.

```bash
hermes-shield scan ./repo --semgrep      # + semgrep comparator (multi-language breadth)
hermes-shield scan ./repo --ai           # + per-file AI-assist recall (fast; needs the `claude` CLI)
hermes-shield scan ./repo --ai-deep      # + whole-repo agentic AI finder (slower + deeper; the deep pass the prompt offers)
hermes-shield scan ./repo --all          # core + semgrep + ai together
hermes-shield scan ./repo --deps         # + scan the repo's own pinned dependencies
hermes-shield scan ./repo --prove        # + sandboxed self-attack: PROVE a candidate sink is live (consent-gated)
hermes-shield scan ./repo --quiet        # plain output instead of the live HUD (the HUD is the default on a terminal)
hermes-shield diff ./repo                # scan + compare against a saved baseline
```

### Every command

| Command | What it does |
|---|---|
| `hermes-shield` | Prints help and exits `0`. |
| `hermes-shield demo` | Scan a bundled, deliberately vulnerable toy agent — a real red report in ~10s. Fixtures ship **inert** (`.txt` package data → temp dir → **never executed**); none of your code is scanned. |
| `hermes-shield scan [target]` | Scan a repo. No `target` → **auto-detects the enclosing git repo** of the CWD; or pass any explicit path (any repo on disk). |
| `hermes-shield diff [target]` | Scan and compare against a saved baseline. |
| `hermes-shield export-dashboard [target]` | Scan and write the dashboard JSON export. |
| `hermes-shield patch-plan [target]` | Scan and write the grouped fix plan. |
| `hermes-shield version` | Print the scanner version (`--version` also works at the top level). |

### Every flag

A first scan needs none of these. `demo` takes only `--out`/`--live`/`--quiet`/`--prove`; `--ai-deep` is `scan`-only; `--prove` applies to `scan` and `demo`.

| Flag | Applies to | What it does |
|---|---|---|
| `--out DIR` | scan · diff · export-dashboard · patch-plan · demo | Output dir for artefacts (default `./shield-report/`). Env: `HERMES_SHIELD_OUT`. |
| `--live` | scan · diff · export-dashboard · patch-plan · demo | No-op alias — the live HUD is already the terminal default. A non-TTY/piped run is always byte-clean, JSON-safe. |
| `--quiet` | scan · diff · export-dashboard · patch-plan · demo | Plain, JSON-safe stdout, no HUD — **the CI / agent / piping mode**. |
| `--ai` | scan · diff · export-dashboard · patch-plan | Per-file AI-assist recall via your own local `claude` CLI (**sends code to Anthropic under _your_ account; no key stored in the package**). Advisory, non-deterministic, **never in the deterministic headline**. OFF by default. |
| `--ai-backend {claude,ollama,anthropic,openai,venice,gemini}` | with `--ai` | AI transport (default `claude`). `ollama` = **local, zero-egress**; `anthropic`/`openai`/`venice`/`gemini` send the **secret-redacted** file source to that cloud provider **under your own key** (`ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `VENICE_API_KEY` / `GEMINI_API_KEY` — required, never stored; a missing key **fails loud**). Only meaningful with `--ai`; does **not** apply to `--ai-deep`. |
| `--ai-deep` | scan | Whole-repo agentic AI finder — slower + deeper than `--ai`; the same pass the post-scan prompt offers. Advisory; **Claude-only for now**; OFF by default. Env: `HERMES_SHIELD_AI_FINDER=1`. |
| `--semgrep` | scan · diff · export-dashboard · patch-plan | Semgrep comparator tier (~30-language breadth; deterministic; needs `semgrep` installed). Attributed separately, **never merged into the headline**. |
| `--deps` | scan · diff · export-dashboard · patch-plan | Also fetch + scan the repo's **own pinned first-party** packages (wheels only — **never installed, never executed**; **reaches the network**). Not in `--all`. OFF by default. |
| `--all` | scan · diff · export-dashboard · patch-plan | Full coverage: core + `--semgrep` + `--ai`. **Excludes** `--deps` and `--prove`. |
| `--prove` | scan · demo | PROVEN-LIVE self-attack: **executes** drivable candidate sinks inside a **network-denied sandbox** (benign canary, clean negative control) to prove they are live. Consent-gated; OFF by default; **only run on a repo you trust**. |
| `--yes-execute-my-code` | with `--prove` | Non-interactive consent for `--prove` (also `HERMES_SHIELD_PROVE_CONSENT=1`). |
| `--version` | top-level | Print the scanner version. |

### `--help`, verbatim

```text
$ hermes-shield --help
usage: hermes-shield [-h] [--version]
                     {scan,diff,export-dashboard,patch-plan,demo,version} ...

Hermes Shield scanner (local, read-only)

positional arguments:
  {scan,diff,export-dashboard,patch-plan,demo,version}
    demo                scan a bundled, deliberately vulnerable toy agent — a
                        real red report in ~10 seconds (fixtures ship as inert
                        .txt package data, copied to a temp dir; nothing is
                        executed)

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit

Exit code: hermes-shield returns 0 regardless of findings (a RED report does NOT fail the
process). For CI gating, parse the verdict from the report JSON
(shield-report/outputs/hermes_shield_report.json). A --fail-on flag is a future enhancement.
```

```text
$ hermes-shield scan --help
usage: hermes-shield scan [-h] [--out OUT] [--ai]
                          [--ai-backend {claude,ollama,anthropic,openai,venice,gemini}]
                          [--semgrep] [--all] [--deps] [--prove]
                          [--yes-execute-my-code] [--ai-deep] [--live]
                          [--quiet]
                          [target]

positional arguments:
  target                target repo path (default: enclosing git repo of the
                        CWD)

options:
  -h, --help            show this help message and exit
  --out OUT             output dir for scan artefacts (default: ./shield-
                        report/ in the CWD)
  --ai                  AI-assist: fast, per-FILE novel-sink recall (uses your
                        local `claude`, sends code to Anthropic under YOUR
                        account). Advisory, non-deterministic; OFF by default.
                        For the whole-repo, slower + deeper pass see --ai-
                        deep.
  --ai-backend {claude,ollama,anthropic,openai,venice,gemini}
                        AI-assist backend transport (default: claude, the
                        historical path). 'ollama' runs a LOCAL, zero-egress
                        model via localhost Ollama (HERMES_SHIELD_OLLAMA_HOST
                        / HERMES_SHIELD_OLLAMA_MODEL).
                        'anthropic'/'openai'/'venice'/'gemini' send the
                        SECRET-REDACTED file source to that cloud provider
                        under YOUR OWN key (ANTHROPIC_API_KEY / OPENAI_API_KEY
                        / VENICE_API_KEY / GEMINI_API_KEY — required, never
                        stored; a missing key fails loud). Only meaningful
                        with --ai (NOT --ai-deep, which stays Claude-only);
                        absent => claude (byte-identical to today).
  --semgrep             enable the semgrep comparator tier (multi-language
                        breadth; deterministic; needs `semgrep` installed)
  --all                 full coverage: run the core + --semgrep + --ai in one
                        command
  --deps                dependency-aware scan: also fetch + scan the repo's
                        OWN pinned first-party packages (catches a capability
                        relocated into a dep not in the tree; needs network +
                        pip; static only, never installs/executes; OFF by
                        default). Not included in --all because it reaches the
                        network.
  --prove               PROVEN-LIVE self-attack lane (Phase 1): after the
                        read-only scan, EXECUTE the drivable candidate RCE
                        sinks of the REAL target inside a sandbox to prove
                        they are live (benign canary, no network). Consent-
                        gated; OFF by default; NOT part of --all. Only run
                        this on a repo you trust.
  --yes-execute-my-code
                        non-interactive consent for --prove (also:
                        HERMES_SHIELD_PROVE_CONSENT=1)
  --ai-deep             whole-REPO agentic AI finder — slower + deeper than
                        --ai; same as accepting the post-scan prompt. Advisory
                        ai_suspected surfaces; reads across the repo; non-
                        deterministic; Claude-only for now — needs the
                        `claude` CLI, and --ai-backend does NOT apply to it;
                        OFF by default. Env equivalent:
                        HERMES_SHIELD_AI_FINDER=1.
  --live                the live HUD is now the DEFAULT on a terminal; --live
                        is kept as a no-op alias. Use --quiet for plain
                        output. (The HUD stays TTY-only: a non-TTY/piped run
                        always gets byte-clean, JSON-safe stdout, whether or
                        not --live is passed.)
  --quiet               plain, JSON-safe stdout with no live HUD — the CI /
                        agent / JSON-piping mode (a non-TTY/piped run is
                        already byte-clean; --quiet also silences a TTY run).
```

> **The exit-code epilog is load-bearing.** `hermes-shield` **always exits `0`**, regardless of findings — a RED report does **not** fail the process. **To gate CI, parse `hermes_shield_report.json`** (check the verdict / reachable-unguarded / proven-live counts). A dedicated `--fail-on` flag is a planned future enhancement, not available today.

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

- **`--ai`** — the recall booster. Fast, **per-file**: an LLM proposes *novel* sinks the static rules missed; every proposal is **AST-verified** before it's kept, and confirmed patterns become permanent static rules. **The scanner gets stricter over time.** AI findings live in a separate advisory tier — never counted in the deterministic headline. Uses your own local `claude` CLI (code goes to Anthropic under *your* account); off by default.
- **`--ai-deep`** — the whole-**repo** agentic finder: slower and deeper than `--ai`, it reads *across* the repo to surface agent-plumbing misses. This is the same pass the interactive post-scan prompt offers. Advisory, non-deterministic, Claude-only for now; off by default.
- **`--semgrep`** — an isolated comparator tier (~30 languages) for breadth. Attributed separately, never merged into the core headline.
- **`--deps`** — the **install-inherited** scan. Fetches the repo's *own pinned* packages (wheels only — never installed, never executed) and scans them with the same engine. Catches the dangerous capability that lives in a dependency rather than your tree — what you inherit the moment you `pip install`. Off by default (it reaches the network).

## `▸ the_report`

The report is built to be read by two people at once: the founder who needs a verdict, and the engineer who needs the evidence.

**The verdict banner** — antivirus-style, one glance:

- 🔴 **Action needed** — a proven-live, or a reachable-unguarded **high-impact/irreversible** action (RCE-class, payment, data-out, message-send) exists. Fix first.
- 🟠 **Review before you ship** — either a reachable **reversible/social** action (post, reply, like, browser click) worth a human look, or **install-liability**: a dangerous capability you inherit on install, whose reachability we can't rule out.
- 🔵 **No live threat proven** — clean run. Deliberately *never* worded "secure".

**The two tiers** — because "exploitable now" and "inherited on install" are different risks, and honest tooling refuses to blur them:

| Tier | Meaning |
|---|---|
| **Reachable — fix first (red)** | A **high-impact/irreversible** action (RCE-class, payment, data-out, message-send) live **now**, from your own entry points, unguarded. Fix first. |
| **Reachable — review (amber)** | A **reversible/social** action (post, reply, comment, like, browser click) reachable now — worth a human look before you ship. |
| **Install-liability** | **Inherited on install — reachability we can't rule out.** A dangerous capability shipped in the box. We could not prove untrusted input can't reach it, so we won't call it dormant. The moment someone wires this code into an agent that feeds it untrusted input, they inherit it. You downloaded it; you inherited the risk. |

**PROVEN-LIVE** is the strictest tier of all: PoC-confirmed findings — either human-traced, or proved by the opt-in **`--prove`** lane, which fires a benign, unguessable canary at a candidate sink inside a network-denied sandbox (with a clean negative control) and only promotes it if the attack actually lands. It is the only tier that ever gets a severity badge, and promotion is one-way: a failed proof leaves a finding a *candidate*, never marks it safe. Raw scanner criticals are candidates — counted, never badged. If the proven-live set is empty, the report says so, plainly.

And the line we will never soften: **a clean result means "no path was proven" — never "secure".** Reachability analysis proves a sink *is* reachable; it cannot prove one *is not*. Most tools hide that asymmetry. We print it on the report, because a security tool that overstates its own certainty is part of the attack surface.

> **PROVE, DON'T GUESS.**

## `▸ prove_dont_guess` — proof it's real

- **It catches a real 9.8.** [CVE-2023-39662](https://nvd.nist.gov/vuln/detail/CVE-2023-39662) — the CVSS 9.8 remote-code-execution flaw in LlamaIndex's `PandasQueryEngine` — is flagged by the scanner **at the exact documented line, on the genuinely vulnerable release** (`llama-index` v0.7.13; patched upstream since). A detector proof against a third-party-documented CVE — not a benchmark we wrote for ourselves, and not a claim about current LlamaIndex. Locked by a CI regression test — [`tests/test_cve_2023_39662.py`](tests/test_cve_2023_39662.py) — that scans the **real, byte-for-byte upstream file** (vendored under `tests/fixtures/cve_2023_39662/`, MIT, provenance recorded) and asserts the `code_exec` sink at the documented `eval` line, traced reachable and banded RED.
- **12 open-source agent frameworks scanned** — over **361,000 combined GitHub stars**, every repo pinned to a commit — mapping **8,447 action surfaces**: **596 reachable-in-repo** from a real entry point by entrypoint-grounded taint tracing, and **542 install-liability** — dangerous capabilities inherited on install whose reachability we can't rule out (the two are distinct risks, counted separately; **zero** are proven-live). The per-framework counts and pinned commits are in **[BENCHMARKS.md](BENCHMARKS.md)**. *(**v0.8.0 benchmark of record, re-stamped 2026-07-21** — deterministic core, same pinned commits; supersedes the historic pre-v0.3.6 figures, retained in [BENCHMARKS.md](BENCHMARKS.md) for transparency. v0.8.0's revised taxonomy bands reachable action sinks RED/AMBER and refuses to assert "inert" without proof, so the counts differ from the historic record.)*
- **Independently security-reviewed — twice.** The scanner has had **an independent security review by an industry professional** (unnamed), twice: the **first pass (v0.1.0) found 2 High + 1 Medium** (AI-cache symlink arbitrary write; symlink traversal), **all remediated in v0.3.7 with the reviewer's own regression tests**. The reviewer then re-reviewed that fixed build (v0.3.7) and confirmed **0 critical and 0 high** findings **in the build it reviewed** (it did raise 4 lower-severity items — 3 Medium, 1 Low, plus a fetch-time hardening — all fixed in v0.4.0). We found and fixed real issues in our own code and locked them shut — that loop is the point, not a clean first sheet. **The reviewed builds were v0.1.0 / v0.3.7; re-validation of the current core is pending** — core changes since the reviewed build are itemised in [CHANGELOG.md](CHANGELOG.md). The tool that grades your attack surface has had its own graded — and published the loop.

- **Deterministic where it counts.** The core engine is reproducible byte-for-byte — an auditor can re-run the scan and get the same numbers. The honest caveats above aren't hedges; they're the reason the numbers can be trusted.

## `▸ the_ladder` — find it free · fix it · shield it

| | Product | What it does | Status |
|---|---|---|---|
| 🔍 | **Scanner** | **Discovery** — map, trace and prove your agent's action surface. This repo. | **Free · here now** |
| 🔧 | **Repairer** | Applies the fixes — diff-proposed, **human-approved, never auto-fix**, re-scanned to confirm. | **Paid · coming — [join early access](https://hermesshield.ai/register-interest)** |
| 🛡️ | **Shield** | Always-on runtime action firewall — **Kill Switch, Action Gates, Audit Trail** on every action the agent takes. | **Paid · [recruiting a founding cohort](https://t.me/hermesshield)** |
| 🏛️ | **Enterprise** | Custom deployment, compliance mapping, dedicated support. | [Talk to us](mailto:hello@hermesshield.ai) |

The Scanner shows you the blast radius. The Repairer closes it. The Shield keeps it closed while the agent runs.

## `▸ contributing`

Found a bug or a sink we missed? **Open an issue** — a missed-detection report with a minimal repro is the most valuable thing you can send us. Vulnerabilities in the scanner itself go to [SECURITY.md](SECURITY.md), privately. And if a scan taught you something about your own agent, **star the repo** — it helps other builders find their blast radius too.

## `▸ links`

- **Website:** [hermesshield.ai](https://hermesshield.ai) · [Free scan](https://hermesshield.ai/free-scan) · [Methodology](https://hermesshield.ai/methodology) · [Scanner](https://hermesshield.ai/scanner)
- **Telegram:** [Join the founding cohort →](https://t.me/hermesshield)
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
