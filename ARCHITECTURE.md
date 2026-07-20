# Hermes Shield scanner — Architecture & Design

**Audience:** external security reviewer.
**Posture:** honest, under-claiming, code-accurate. Where the tool is weaker than it might sound, this document says so plainly.

**Scope:** the scanner package `src/hermes_shield/` in this repository, exposed as the `hermes-shield` CLI.

> **One-line summary an auditor should leave with:** Hermes Shield's scanner is a deterministic, static, entrypoint-grounded reachability analyser for AI-agent codebases. It proves *reachability* of dangerous action-sinks (sound-leaning: it never claims a sink is *un*-reachable), attributes guard coverage, and rates findings on an OWASP Severity × Likelihood matrix with a **proven-live-only headline**. It does **not** block prompt injection, does **not** auto-repair repositories, and its guard model is **Python-only**.

---

## 1. Mission & threat model

### 1.1 What it defends

Hermes Shield is an **action-side, last-line-of-defence** analysis tool for AI agents. Its threat model is **OWASP LLM06 — Excessive Agency**: an agent that has been subverted (by prompt injection, a poisoned tool result, a poisoned RAG corpus, or a malicious dependency) attempts to perform a **dangerous ACTION** — execute code, deserialise an attacker-controlled blob, run a shell command, invoke an LLM-chosen tool, write/delete a file, exfiltrate a secret, publish/send outbound content.

The defended asset is therefore the **action sink**, not the model's reasoning. The tool's job is to find, in a codebase, every point where a dangerous capability can be triggered, and to answer one question deterministically: *can untrusted input actually reach this sink, and is a real guard in the way?*

### 1.2 What it explicitly does NOT claim

These are load-bearing honesty caveats:

- **It does not block, detect, or mitigate prompt injection.** It assumes injection *succeeds* and looks at what the compromised agent can then *do*.
- **It does not prove code is safe.** The reachability analysis is **sound-leaning but not complete** (§3.5). It proves a sink *is* reachable; it never proves a sink *is not* reachable. "No finding" means "we did not prove a path", not "there is no path".
- **The deterministic core does not run the target's code.** Purely static (AST + optional tree-sitter): the core never imports, executes, or evaluates target code. **The one exception is the opt-in, consent-gated `--prove` lane** (off by default, never part of `--all`), which executes a benign, unguessable canary against a *candidate* sink inside a **network-denied bwrap sandbox** (read-only target, resource-capped, killed on timeout) purely to promote it to PROVEN-LIVE — promote-only, so a failed proof never marks a finding safe. The deterministic core writes only under its own report/output directory (default `./shield-report/` in the CWD — never the package, never the target), and reads only source files whose canonical path stays **within** the target root — symlinked files and symlinked directories that resolve outside the root are skipped, so a hostile repo cannot redirect it into reading arbitrary local files. It reads source *text* (so a secret hard-coded in an in-scope file is read like any other line — it does not go hunting for secret stores, but it is not blind to code that contains one). Optional tiers: `--ai` forwards selected in-root code text to your local `claude` CLI and caches under the operator output dir (never the target); `--deps` fetches the repo's own pinned packages over the network. Target-supplied `.hermes-shield.json` guard declarations are advisory only unless the operator explicitly trusts them.
- **Its guard reasoning is Python-only.** TypeScript/JavaScript and C# are detected at **sink level only** — no taint, no guard model (§3.4).
- **It is not an auto-repairer.** `patch_plan` emits required-control *plans* (strings), never diffs or fixes.

### 1.3 The two danger tiers

The report separates two fundamentally different risk states so a reader is never told an inert capability is "exploitable here":

| Tier | Meaning | Example |
|---|---|---|
| **Reachable-verified** (*live now*) | A dangerous sink **reachable from this repo's own entrypoints AND unguarded**, right now. Verdict `UNGUARDED_CRITICAL_LIVE_SINK`. | An HTTP handler whose untrusted body flows into `subprocess` with `shell=True`. |
| **Install-liability** (*live-on-install*) | A dangerous capability (RCE-class: `code_exec` / `deserialize` / `subprocess_exec` / `ssti`) present but **not reached from this repo's entrypoints** — inert here, but a live attack surface the moment a user wires the code into an agent that feeds it untrusted input. The risk you *inherit* on install. | A library helper that `pickle.load`s a path, never called by any local entrypoint. |

Install-liability is labelled, verbatim, "inert here, live on install" — **never** "exploitable in this repo". The rating enforces this: install-liability is capped at Med (§5).

---

## 2. Pipeline

The data flow lives in `scan_hermes.run_scan(root)`. Every stage is read-only and deterministic; the whole-repo call graph is built **once** and shared across the graph-consuming passes.

```
                         scan_hermes.run_scan(root)
                                    │
        ┌───────────────────────────┴───────────────────────────┐
        │  config_loader.load_target_guards → module_index       │  onboard the TARGET repo's
        │  (recognise the scanned repo's own control functions)   │  own guard identities
        └───────────────────────────┬───────────────────────────┘
                                    ▼
   ┌────────────────────────────────────────────────────────────────────┐
   │ repo_scanner.scan_repo                                              │
   │   • Python: ast_sinks.detect (PRIMARY) + regex fallback (parse-fail)│
   │     + intra-fn taint (taint.py) + focused detectors                 │
   │     (llm_eval_detector, secret_exfil_detector)                      │
   │   • TS/JS: ts_sinks + ts_taint   (sinks-only)                       │
   │   • C#:    cs_sinks              (sinks-only)                        │
   │   → ActionSurface[] + UntrustedIngress[]                            │
   └────────────────────────────────┬───────────────────────────────────┘
                                    ▼
   guard_detector.attach_test_evidence      (link the target's tests to surfaces)
                                    ▼
   build_graphs / build_mod2files           (ONE shared whole-repo call graph)
                                    ▼
   cross_module.apply         (conservative cross-module guard proof, upgrade-only)
                                    ▼
   surface_classifier.classify (per-surface honest verdict from guard evidence)
                                    ▼
   inter_taint.apply          (entrypoint-grounded inter-procedural taint
                              → sets tainted_reachable on cross-function paths)
                                    ▼
   guard_attribution.apply    (THE QUADRANT: tainted × critical_guard_on_path
                              → severity_rank + verdict; downgrade-only)
                                    ▼
   entrypoint_proof.apply     (reviewed real-entrypoint proof for modelled public helpers)
                                    ▼
   guard_integrity.annotate   (does a present guard actually BLOCK, or is it a no-op?)
                                    ▼
   [ ai_tier.apply ]          (OPTIONAL, off by default — §4; re-runs cross_module→
                              inter_taint→guard_attribution→entrypoint_proof over AI surfaces)
                                    ▼
   install_report.build_report / render
       → OWASP Severity × Likelihood rating, PROVEN-LIVE-only headline (§5)
```

**Key ordering invariant (baked into the pipeline):** reachability (`inter_taint`) runs *before* `guard_attribution` reads the tainted axis, so guard-attribution sees true cross-function reachability. When the AI tier is on, the same reachability chain is re-run over AI-found surfaces in the identical order (CM → IT → GA → EP), so an AI-detected sink gets a real reachability disposition rather than being stranded as "detected" ("AI suggests, engine proves").

**Failure posture:** each stage is wrapped so a failure is *loud* (a `WARNING` to stderr) but non-fatal — e.g. if `guard_attribution` throws, the scan records `{"error": ...}` rather than silently leaving every surface at the least-severe default. The intra-function taint bit stands as the fail-open floor.

**Outputs** (written under `<out>/outputs/`, default `./shield-report/outputs/` in the CWD): the raw surface scan, a lane-protection matrix, the patch plan, a dashboard export, the OWASP-rated `hermes_shield_report.{json,md}`, and the customer/auditor-facing `shield_customer_report.{md,html}`. The out dir is resolved by `scan_hermes.resolve_out_paths` — `--out` → `HERMES_SHIELD_OUT` → CWD default; **never** the package dir, **never** the target repo (locked by `tests/test_s8_87_out_dir.py`).

---

## 3. Detection

### 3.1 AST sink detection (Python, primary)

`ast_sinks.detect(text)` returns `(ok, sinks)` by walking **actual `ast.Call` / write nodes** — import lines, `def` lines, bare references, comments and string literals are structurally excluded because they are not Call nodes. Detection families:

- **Name sinks** — distinctive method names (`create_tweet`, `send_direct_message`, `put_object`, `insert_one`, `render_template_string`, …).
- **Dotted deserialisation sinks** — `pickle.load(s)`, `yaml.load`, `torch.load`, `joblib.load`, `numpy.load`, `shelve.open`, … (the ML supply-chain pickle-RCE family).
- **Structural family rules** — match on the **resolved module family + verb family** (e.g. the whole `subprocess` family, `asyncio.create_subprocess_*`) rather than enumerated name allowlists, so siblings generalise without firing on `asyncio.run` (an event loop, not a subprocess).
- **Danger-library roots** — a call on an object from a known-dangerous SDK is a sink *regardless of method name* (`stripe`→payment, `web3`→blockchain_tx, `boto3`→cloud_write, `paramiko`/`docker`/`e2b`→subprocess_exec, `langchain`/`crewai`/`autogen`/`mcp`→tool_invoke, …).
- **Learned sinks** — `learned_sinks.json` carries sink names absorbed from public OSS agent frameworks (provenance recorded per entry); loaded statically by `learned_sinks.py`.
- **Regex fallback** — used **only** when a file fails to AST-parse; labelled `regex_fallback` and treated as weak (never a full-path protection claim).

Note: the detector code necessarily **contains credential-shaped detection patterns** (e.g. regexes for `sk-…`/`AKIA…`-style strings and names like `api_key`, `access_token` in `secret_exfil_detector.py` and `patterns.py`). These are patterns for finding secrets in *target* code; the package itself contains no credentials.

### 3.2 Capability vocabulary

The **authoritative critical-capability set** is `patterns.CRITICAL_CAPS`:

```
deserialize, code_exec, ssti, secret_exfil, cloud_write, blockchain_tx,
payment, file_perms, tool_invoke, file_delete, post, reply, comment, like,
dm, email_send, telegram_send, browser_click, browser_type, browser_submit,
computer_use, queue_mutation, external_write, subprocess_exec, publish_write
```

Read-only capabilities (`external_read`, `model_call`, `pdf_ocr_ingest`, `vision_model_call`) are tracked but classified as non-blocking. The rating (§5) keys on two subsets in `install_report.py`: `_RCE_CAPS = {code_exec, deserialize, subprocess_exec, ssti}` and `_ACT_CAPS = {external_write, file_write, file_delete, tool_invoke, publish_write, secret_exfil}`.

> **Honesty note:** the `CAPABILITIES` list in `models.py` is a *stale, illustrative* taxonomy — the live vocabulary is defined by `patterns.CRITICAL_CAPS` + the maps in `ast_sinks.py`. Documentation/enum drift, not a detection bug (the gates key on the authoritative sets), but a reviewer should not treat `models.CAPABILITIES` as the contract.

### 3.3 Focused, high-precision detectors

Three narrow detectors target proven attack classes, each with explicit stated limits:

- **`llm_eval_detector`** — `eval()`/`exec()` on a value derived from the model's **own output** (the "prompts become shells" class). Per-function backward provenance trace. **Intra-procedural only** — cross-function flows are *missed by design*; it reports candidates + confidence, never "proven".
- **`secret_exfil_detector`** — ships only the two statically high-precision sub-patterns: (A) secret → serialiser (`pickle`/`json`/`yaml` dumps) → egress, and (B) secret → LLM prompt. A secret in a `headers=`/`auth=`/`cookies=` kwarg is **excluded** (normal authentication). Deliberately *does not* ship a general "secret reaches egress" rule (a false-positive cannon). Under-claims: cross-function secret flow, generically-named secret vars, file/DB-read secrets.
- **SSTI** — `render_template_string` / Jinja `from_string` on untrusted input → RCE, as an `ssti` capability (severity 5).

### 3.4 TypeScript/JavaScript and C# — the honest limit

`ts_sinks` (tree-sitter TS/TSX/JS) and `cs_sinks` (tree-sitter C#) are **sinks-only (blast-radius)**. They map dangerous calls to the shared capability vocabulary but perform **no taint and no guard analysis**. Consequently:

- Every non-Python surface is emitted with `tainted_reachable = False` (TS taint, `ts_taint`, exists as a partial upgrade and can set it for TS — the guard axis still stays `"unknown"`).
- Guard-attribution reads the guard axis as `"unknown"` → the quadrant yields `NEEDS_CALL_GRAPH` / REVIEW.
- **A non-Python surface can NEVER be rated `UNGUARDED_CRITICAL_LIVE_SINK`** — that requires proven taint + proven "no guard", which the TS/C# front-ends do not compute.

The report states this itself: `guard_model_note` is set to `"python-only"` whenever any non-Python surface is present. The tree-sitter dependencies are an **optional extra** (`pip install "hermes-shield-scanner[multilang]"`); without them non-Python files are skipped.

### 3.5 The reachability model — SOUND, not COMPLETE

The central honesty claim; a reviewer should test the tool against it.

- **Entrypoint-grounded.** Taint is seeded **only** at detected real entrypoints — HTTP route handlers (`@app.post`, `@router.get`, `@app.route`, `@app.websocket`), event/webhook handlers (`on_message`, `handle_*`, `@bot.on`), and genuine bot command handlers — *not* at suggestively-named parameters. `@bot.command` seeds untrusted **only when it is not** a Typer/Click operator CLI verb. Explicit source calls (request bodies, LLM outputs, store rows, RAG reads) are grounded intrinsically in `taint._is_source_call`.
- **Sound-leaning, no guessing.** A sink is marked tainted only when a **concrete, resolved** origin → param → arg → … → sink chain exists. Unresolved calls (dynamic dispatch, `getattr`, `importlib` on a variable, ambiguous/star imports, `*args`) are **skipped, never guessed**. Cross-function taint is a bounded worklist fixpoint (max 6 rounds) over two per-function summaries (return-taint and tainted-params) plus a same-class field-cell for the `receive()→act()` agent-injection shape.
- **Upgrade-only.** Reachability passes never flip a sink from reachable to not-reachable; they fail open to the intra-function bit.
- **The direction of the guarantee.** The tool proves **reachability** (a real path exists). It does **not** prove **un-reachability**. `tainted_reachable = False` means "no path was proven" — an unguarded but not-proven-reachable sink is still flagged, just ranked below a proven-reachable one. Whole-program taint in dynamic Python is undecidable; every practical tool (Pysa, Semgrep, CodeQL) is best-effort. This tool states that ceiling rather than hiding it.

### 3.6 Guard attribution — the quadrant

`guard_attribution.py` runs on **every** prod critical-capability surface and asks one deterministic question: *does a CRITICAL guard (kill-switch / final-action-gate / declared target-repo gate) dominate the sink on every resolvable path from an entry?* Design invariants:

- **Downgrade-only.** A *proven* critical guard can move a surface **down** the severity ladder; the *absence* of a guard never moves anything down. The default for an unproven path is the **higher** severity.
- **Never over-credit.** Unknown / unresolved / dynamic dispatch / depth-exceeded = "no critical guard proven" = the worse rank. Over-crediting (calling an unguarded path guarded) is the catastrophic failure; under-crediting is merely annoying.
- **Presence + dominance only.** It proves a critical guard is *called before* the sink on every path. It does **not** prove the guard fails-closed — that is `guard_integrity`. So "guard present" yields REVIEW, never ALLOW on its own.
- A critical guard is credited **only** on a resolved-to-source identity (resolved import / certified gateway / configured guard) — never a bare `LOCAL_DEFINITION`, so a local no-op `def assert_action_allowed(): return True` decoy cannot downgrade a sink.

The quadrant (`tainted × critical_guard_on_path`, 0 = most severe):

| tainted | guard | rank | verdict | promotion |
|---|---|---|---|---|
| True | no | 0 | `UNGUARDED_CRITICAL_LIVE_SINK` | BLOCK |
| True | partial | 1 | `UNGUARDED_CRITICAL_LIVE_SINK` | BLOCK |
| True | unknown | 2 | `NEEDS_CALL_GRAPH` | REVIEW |
| True | yes | 3 | *(keep classifier's)* | REVIEW |
| False | no | 4 | `EXPECTED_GUARD_MISSING` | BLOCK |
| False | partial | 5 | `CALLER_GUARDED_NOT_PROVEN` | REVIEW |
| False | unknown | 6 | `NEEDS_CALL_GRAPH` | REVIEW |
| False | yes | 7 | *(keep classifier's)* | REVIEW |

Sanctioned, bounded exceptions (each on *positive* evidence, capped at REVIEW, never ALLOW): an authenticated FastAPI route (`Depends(current_org/user)`) → `AUTH_GATED_REVIEW`; an `external_write` to a **constant/config** destination → `CONFIG_DESTINATION_WRITE_REVIEW` (exfil needs an attacker-controlled *destination*); a `subprocess` with a tainted arg but **no shell interpretation** → `SUBPROCESS_NON_SHELL_REVIEW`.

### 3.7 Cross-module & reviewed-entrypoint proof

- `cross_module.apply` proves `cross_module_entry_guard_before_helper` **only** when *every resolvable call site* of a sink-bearing helper runs a dominating guard before the call, and there is no unguarded/ambiguous/dynamic/unresolved site anywhere. Import resolution uses a single package-root-anchored resolver so a same-named function in another package never collides; ambiguity fails safe. The resulting verdict is the deliberately-weaker `PROTECTED_CROSS_MODULE_VISIBLE` (REVIEW, never ALLOW) because dynamic/reflective callers are invisible to static analysis.
- `entrypoint_proof.apply` handles **public helpers** modelled in `config/entrypoints.json` (ships empty; a schema example is included) or the target's own `.hermes-shield.json`, with `allowed_callers` + `expected_guards`. Only if every in-file caller is allowed **and** runs an expected guard before the call does it emit `PROTECTED_BY_REVIEWED_ENTRYPOINT` (REVIEW) — which still records the residual "helper remains technically public". A disallowed caller → `NEEDS_ENTRYPOINT_CONFIG`; a missing expected guard → `EXPECTED_GUARD_UNPROVEN` (BLOCK + a patch-plan item).

---

## 4. The AI-assist tier (advisory, `--ai`)

Optional, **off by default** (`--ai` on the CLI; env `HERMES_SHIELD_AI_TIER=1`). It sends unfamiliar code to a coding agent (default: the user's own local `claude` CLI — no credential ships in this package) to propose **novel** dangerous surfaces the static rules do not know, then **AST-verifies every finding** so a stronger agent yields more recall but no agent can fabricate past the gate.

Discipline (each property is enforced in code):

- **The LLM proposes; a deterministic AST check disposes.** `ai_assist._ast_verify` drops any finding whose named call does not resolve to a real `ast.Call`, rejects known-safe callees, rejects `getattr`/constructor mislabels, and drops severe-capability claims on benign factory/getter names. Survivors are tiered `ai_corroborated` (static also flags the callee) or `ai_suspected`.
- **Separate tier, never the headline.** Every AI finding becomes an `ActionSurface` with `detection_source ∈ {ai_suspected, ai_corroborated}` and verdict `AI_SUSPECTED_REVIEW`. It is **never** folded into the deterministic static headline.
- **Residual + plumbing prioritised, budget-capped, SHA-cached.** Files are prioritised agent-plumbing-first (tool-dispatch/MCP/delegation — where static misses live), then zero-finding files; capped at `HERMES_SHIELD_AI_TIER_BUDGET` LLM calls (default 120); findings are SHA-cached on `(file_sha256, model, prompt_version)` so re-scans are near-free and reproducible given the cache.
- **Capability normalisation** (`cap_normalise`) — AI findings carry free-text caps (`tool-invoke`, `code-execution`) that never match the canonical underscore vocabulary. An ordered, deliberately narrow rule list maps clear signals to canonical caps; ambiguous caps are **left non-canonical on purpose** — under-marking is safe, force-fitting would inflate the counts.
- **AI surfaces get real reachability.** After normalisation, AI surfaces are re-classified and run through `cross_module → inter_taint → guard_attribution → entrypoint_proof` in the same order as static, so an AI-found sink can become a rated `UNGUARDED_CRITICAL_LIVE_SINK` or be correctly left as install-liability — not stranded as "detected".
- **Cache-only mode** (`HERMES_SHIELD_AI_TIER_CACHE_ONLY=1`) — a cache **miss is skipped** instead of spawning a subprocess; cache hits replay exactly; off-path behaviour is byte-identical (locked by `tests/test_ai_tier_cache_only.py`).

**Honest limit:** this is an **advisory tier**. It raises recall on novel/framework-abstracted surfaces, but it is **non-deterministic** and its findings are always `AI_SUSPECTED_REVIEW` — they require human review and are never presented as proven.

## 4b. The semgrep comparator (`--semgrep`)

Optional, deterministic. Runs semgrep (the user's own install, or dockerised) as an **isolated, attributed comparator tier**: findings are mapped to the capability vocabulary, tagged `source: semgrep-classic`, and **never merged into the core headline** — proven-live and the non-gated kicker come only from the scanner's own reachability engine. Semgrep CE is intra-procedural, so its findings are reachability-unproven candidates; the honest framing is "here is what a best free SAST finds across the file; here is the agent-reachable subset only we prove". Fail-open: a comparator failure never blocks the core scan (locked by `tests/test_s8_89_semgrep_comparator.py`).

---

## 5. Rating

`install_report.py` applies the **OWASP Risk Rating Methodology** (Severity × Likelihood), cross-referenced to NIST SP 800-30 Rev.1 and ISO/IEC 27005.

- **Severity (1–5)** by capability: RCE-class = 5; secret-exfil = 4; write/act = 3; `queue_mutation` = 2.
- **Likelihood (1–5)**: not reachable = 1 (install-liability); non-Python (guard model cannot reason) = 3; validated guard protects it = 2; **PoC-proven** = 5; candidate/non-gated/unproven = 4.
- **Index** = Severity × Likelihood → `High` (≥15) / `Med` (≥8) / `Low`.
- **Guardrail G1:** install-liability (not reachable here) is **capped at Med** — inert, "live on install", never "exploitable here".

**The headline comes from PROVEN-LIVE ONLY.** A "proven-live" finding is one a **human traced and a harmless PoC confirmed** — supplied as an explicit `validated` set. The scanner's raw grounded-criticals are **CANDIDATES** (may include false positives), counted separately and shown un-badged as "needs validation". The overall rating is `None (no proven-live)` unless something is PoC-confirmed — a candidate can **never** drive a severity badge. `None (no proven-live)` means **not demonstrated**, never "secure". This is the single most important honesty rule in the rating and is enforced in `build_report`.

**Coverage caveat (be precise):** `coverage_pct` = `files_scanned` ÷ (all `*.py` under root via `rglob`). The denominator includes vendored/skipped trees (`site-packages`, `node_modules`, …) the scanner deliberately does not analyse, so the figure *understates* coverage of first-party code. It is an honest floor, not a defect — read it as "of every `.py` on disk", not "of the code we intended to scan".

---

## 6. Known limits & gaps (stated plainly)

1. **Reachability is sound-leaning, not complete.** Proves reachability; never proves un-reachability. Cross-process store writes, dynamic dispatch, reflective/monkeypatched callers, and unresolved attribute flows lose taint by design.
2. **Guard model is Python-only.** TS/JS and C# are sinks-only; they can never be rated `UNGUARDED_CRITICAL_LIVE_SINK`.
3. **`llm_eval_detector` is intra-procedural** — cross-function eval-on-LLM-output is missed; candidates + confidence only, never "proven".
4. **`secret_exfil_detector` ships only two high-precision sub-patterns** — cross-function secret flow, generically-named secrets, and file/DB-read secrets are missed by design.
5. **No repair, no CI mode.** The patch plan emits required-control strings only. One-shot scans only — no always-on/CI mode.
6. **The learned-sinks memory does not learn automatically.** `learned_sinks.json` persists absorbed sink names and fires on every scan, but no discovery loop runs per scan.
7. **The AI tier is non-deterministic** and advisory; its findings never enter the deterministic headline.
8. **Stale metadata:** the version string is `mvp-1a.0`; `models.CAPABILITIES` is not the authoritative capability vocabulary (§3.2).

---

## 7. Test posture

- The `tests/` suite in this repository (59 test files, 575 tests collected — run `pytest --collect-only` for the live count; 517 run sandbox-free with 0 skips, the remaining 58 are the `--prove` / live-scan lanes that need a working bubblewrap sandbox) covers: guard-attribution invariants, inter-procedural taint, cross-module proof, entrypoint maps, AST sink detection, false-positive suppression, adversarial red-team cases, a frozen corpus (`tests/corpus/` — labelled positive/negative fixtures), out-dir hygiene (artefacts never written into the package or the target), AI-tier cache-only guarantees, and the semgrep comparator isolation.
- `test_verified_fires.py` is the anti-drift gate: it asserts each wired detector actually **emits** on its positive fixture (eval-on-LLM-output, secret-exfil, SSTI) and that a benign file stays clean — turning "wired" into "verified-fires".
- The corpus + mock lanes (`tests/mock_lanes/`) include deliberate decoys (no-op guards, comment/string guards, wrong-module name collisions) reflecting the "never over-credit" invariant.

---

*Prepared for external security review. Every claim above is traceable to code in `src/hermes_shield/`. Where the tool is weaker than a headline might suggest, this document says so — that is the intended reading.*
