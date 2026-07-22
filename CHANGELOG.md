# Changelog

All notable changes to the Hermes Shield scanner are recorded here.
Format follows [Keep a Changelog](https://keepachangelog.com/); versioning is [SemVer](https://semver.org/).

## [0.8.0] — 2026-07-22 · actions-firewall + dedup-worst-band hardening (intentional core verdict change)

**MINOR bump (SemVer): this is a deliberate core verdict-behaviour change — output is intentionally NOT
byte-identical to 0.7.x.** Two hardenings: (1) reachable, unguarded **agent-action sinks** (payment /
message-send / post / …) now drive a RED or AMBER verdict instead of a false BLUE "no live threat proven";
(2) dedup now folds each partition to its **worst-banded** member so a benign sibling can no longer hide a
dangerous one. The reviewed builds were v0.1.0 / v0.3.7; re-validation of the current core against the
independent security review (last of v0.3.7) is pending.

### Changed — VERDICT BEHAVIOUR (intentional core change; output is deliberately NOT byte-identical)
- **Closed the actions-firewall gap.** `guard_attribution` stamps `UNGUARDED_CRITICAL_LIVE_SINK` onto **any**
  reachable-from-untrusted, unguarded `CRITICAL_CAPS` surface — which includes the agent-action sinks
  (`payment`, `email_send`, `dm`, `post`, `like`, …). But `install_report` only counted `_RCE_CAPS | _ACT_CAPS`
  toward `non_gated_vulnerable`, so a repo whose **only** live sink was, say, a money-moving `payment` or a
  message-sending `email_send`/`dm` reported **BLUE "no live threat proven"**. That was a *false all-clear*: a
  hijacked agent could wire an untrusted prompt straight to an irreversible/costly action and the scanner said
  nothing. **Why it matters:** excessive-agency (OWASP LLM06) is exactly about what a hijacked agent can *do* —
  the action sinks are the firewall, and they were invisible.
- **New agreed taxonomy drives the verdict** (both bands static-only, so the Loop-1 invariant holds — an
  AI-suspected guess can never drive either):
  - **RED caps** (high-impact / costly / irreversible) now count into `non_gated_vulnerable` and drive the RED
    **"Action needed"** verdict + the reachable-now table, exactly like an RCE sink:
    `payment, blockchain_tx, cloud_write, file_perms, email_send, dm, telegram_send, computer_use, browser_submit`
    (added to `_VULN_CAPS` via a new `_RED_ACTION_CAPS` set feeding `is_non_gated_vulnerable`).
  - **AMBER caps** (reversible / social) resolve to a **new "Reachable actions — review" AMBER band** —
    never BLUE, never RED — counted as `reachable_amber_actions` via the new `is_reachable_amber_action`
    predicate and wired into `verdict_band(..., amber_actions=…)`:
    `post, reply, comment, like, browser_click, browser_type, queue_mutation`.
- **`--live` stays consistent** (no Act-1-vs-Act-3 contradiction): the HUD red stream and the finale both use
  the shared `is_non_gated_vulnerable`; the finale/quiet line and the HTML banner both call the widened
  `verdict_band` with the amber-actions count and render a dedicated amber "reachable actions" band + plain-
  words line. The HTML "Reachable in-repo" table and the new amber table **partition** every reachable-
  unguarded surface — nothing is silently dropped.
- **Repairer feed corrected:** the newly-counted reachable actions (static only) already flow into
  `patch_plan.build` / the fix plan via their `UNGUARDED_CRITICAL_LIVE_SINK` verdict; concrete fix-at-source
  controls were added for each new red/amber cap (spend/recipient allowlists + human approval), so the paid
  Repairer no longer falls through to the generic fallback for a live action sink.
- **Repairer feed now shares the report's RED/AMBER partition (cross-surface consistency).** The fix-plan
  tier (`shield_report._fix_plan_rows`) and the machine Repairer block flag (`patch_plan.build`) were still
  keyed on a *bare* `verdict == UNGUARDED_CRITICAL_LIVE_SINK` test — which ignores the red-vs-amber capability
  split. A reachable AMBER action (e.g. a `post` sink) was therefore shown in the RED **"fix first — reachable
  now"** table (badge `.ff`) and flagged `block_live_promotion=True` in `hermes_patch_plan.json`, while the
  deterministic banner + "Reachable in-repo" table correctly called it **amber "review before you ship"** — a
  same-file:line verdict-vs-Repairer-feed contradiction that over-stated an amber social action as red.
  **Fix:** both now reuse the shared predicates — `is_non_gated_vulnerable` for the red fix-first tier /
  block flag, `is_reachable_amber_action` routed to a new **"Reachable actions — review before you ship"**
  fix-plan section (badge `.rv`, never `block_live_promotion`), everything else to the wiring-time tier. Since
  `guard_attribution` only stamps the verdict onto `CRITICAL_CAPS` (== red ∪ amber caps), the three tiers
  partition every finding with nothing dropped. Explicit hard-block verdicts (`BLOCK_LIVE_PROMOTION`,
  `GUARD_LOST`) still block regardless of band. Loop-1 static-only invariant preserved (both predicates gate
  on `detection_source == "static"`).
- **Tests:** updated the one test that locked the OLD under-reporting (`post/email_send/payment/dm/blockchain_tx
  → BLUE`) to assert the NEW correct behaviour (red-caps → RED + reachable table; amber-caps → the amber band);
  added regression tests for AI-suspected action sinks (still never red/amber), a clean repo (still BLUE), the
  HTML red/amber banners, and — for the fix-plan/Repairer-feed partition — that an amber action is routed to
  the review tier (never the red fix-first table) and is never `block_live_promotion`, that a red action still
  blocks, and that hard-block verdicts still block. (Shipped suite count for this release is recorded once,
  at the end of this entry: **517 passed, 0 skipped** in the portable sandbox-free config.)

### Changed — DEDUP HARDENING: "a safe sink can no longer hide a dangerous one" (Fable-5 under-report class, structurally closed)

- **The class, in one line.** When several raw sinks of the same scope/capability collapsed to a single
  customer-facing row (dedup), the scanner used to pick the *displayed* row by a **pre-verdict severity
  proxy** (`repo_scanner._sink_severity`, which ranks only taint + destination). Any verdict-determining
  signal the proxy could not see let a **benign representative hide a band-driving sibling**, lowering the
  customer band (RED → AMBER/BLUE). This is a **under-report** family: the scan says "safe" while a real
  reachable-unguarded sink sits folded behind the row.
- **Why it kept coming back (the whack-a-mole).** Each newly-found axis was patched by bolting on another
  partition key or extending the proxy — but only for the axis someone had already found:
  1. **Taint axis** — an untainted send that sorts first hid a tainted exfil sibling → fixed by choosing the
     **worst `_sink_severity` member** instead of the textually-first one.
  2. **Destination axis** — a constant/config-destination send hid an attacker-controlled-destination exfil
     of the same partition → same worst-member fix folded it in.
  3. **Guard-wrapper axis** — a guardable call and its wrapper shared a partition → fixed by keying the
     partition on the **distinct call name** (`975a425`).
  4. **Shell-form axis** — a non-shell subprocess hid a shell-injection sibling → fixed by adding
     **`shell_form` to the partition key** (`8f2bab9`).
  Every fix was reactive. The **5th axis** (guard **strength** vs proof-identity) proved the pattern was
  open-ended: `fg.prove()` counts a `LOCAL_DEFINITION` **decoy guard** as "proven", so a decoy-guarded RED
  exfil and a genuinely kill-switch-guarded REVIEW sibling landed in the **same "proven" partition**, and the
  proxy — ranking the guarded sibling higher on its taint/dest tuple — folded the RED sink behind it and
  reported BLUE. Context/mutating was a lurking **6th** candidate.
- **The structural fix (stop adding keys; fold AFTER the verdict).** Instead of a 7th partition key,
  `repo_scanner` now **emits a full surface for every raw sink** of a partition (the display-preferred
  representative carries the others on `_dedup_folded`). `scan_hermes.run_scan` merges those shadows into the
  surface set so **every** raw sink is banded by the full verdict pipeline (classify → cross-module →
  inter-procedural taint → **guard-attribution**). Then `install_report.collapse_dedup_to_worst_band` folds
  each partition back to **one display row — the WORST-BANDED member** — using **exactly the shared band
  predicates** (`is_non_gated_vulnerable` / `is_reachable_amber_action` / `is_reachable_fixed_dest_review`)
  that drive `verdict_band`. The survivor therefore drives the **max band over ALL raw members on every axis**
  — taint, destination, shell form, guard strength, context/mutating, and **any future verdict input** — so a
  folded sibling can **never** lower the band, independent of which sink is the display representative.
- **Why this closes the CLASS, not just the 5th axis.** The collapse runs **immediately after
  guard-attribution**, which is the **last** pass that can write a band-driving verdict
  (`UNGUARDED_CRITICAL_LIVE_SINK` / `CONFIG_DESTINATION_WRITE_REVIEW`). The only later passes
  (`entrypoint_proof`, `guard_integrity`) write **downgrade/neutral** verdicts only
  (`NEEDS_ENTRYPOINT_CONFIG`, `EXPECTED_GUARD_UNPROVEN`, `PROTECTED_BY_REVIEWED_ENTRYPOINT`,
  `GUARD_INTEGRITY_SUSPECT`), so no later pass can escalate a folded sibling above the chosen survivor. The
  band is now a **provable function of the worst raw sink**, not of display-row selection.
- **Invariants preserved.**
  - **No under-count** — the fold only ever **raises** a partition to its true worst band, never lowers it.
  - **No over-count** — exactly **one row per partition** survives (verified on the real repo: max 1 surface
    per partition id, 0 leaked `_dedup_folded` shadows); display and band-driving counts are unchanged when
    no sibling was hidden.
  - **No display churn** — when all members share the worst band, the survivor is the display-preferred
    member and source order is preserved: **byte-identical** to the prior behaviour on any partition that had
    no hidden band-driving sibling (`band_promoted == 0` on the whole hermes-social scan).
  - **Loop-1 honesty invariant intact** — every band predicate still gates on `detection_source == "static"`,
    so an AI-suspected guess can never drive RED or AMBER via a folded sibling.
- **Tests.** New `tests/test_dedup_worst_band.py`: (1) **end-to-end** reproduction of the 5th axis — a
  decoy-guarded RED exfil sharing a "proven" partition with a critically-guarded REVIEW sibling stays **RED
  in both source orders** (order-independence); (2) the **collapse invariant itself**, parametrised across
  taint / destination / shell / guard-strength / context(mutating) / amber-action / amber-fixed — survivor
  band == max band over all raw members, one row per partition, with the promotion recorded; plus
  all-benign-keeps-display and non-partitioned-surfaces-untouched cases. Suite (portable sandbox-free
  config, the two env-dependent sandbox suites `test_prove_lane.py` + `test_s8_94_live_scan.py` excluded):
  **517 passed, 0 skipped** — 575 tests collected in total, the extra 58 being the `--prove` / live-scan
  lanes that pass under a working bubblewrap sandbox and skip without one.

## [0.7.1] — 2026-07-17  ·  FIRST PUBLIC RELEASE (launch-hardening)

### Changed / Fixed (from an adversarial launch review — no scan-engine change)
- **Reviewer name genericised** across all docs, source and tests (an independent security review by an unnamed industry professional). The
  deterministic core is byte-identical; only comments/docs changed.
- **`--prove` isolation is now structural.** The lane **refuses to run without a real bubblewrap sandbox** —
  the rlimit-only fallback never executes target code (previously the fallback was reachable via the module
  API). Promote-only preserved; `isolation_config` no longer mislabels the refused path.
- **`FOR_AUDITORS.md` reconciled with `--prove`** (it no longer claims PoCs are never run); **`RELEASES.md`**
  rewritten as a clean public version ledger (internal GTM removed) that states the core is byte-identical
  across versions; **`BENCHMARKS.md` added** — the 12 scanned frameworks with pinned commits and the
  8,509 / 474 / 520 counts, so the README's figures are verifiable.
- **README** images switched to absolute URLs (render on PyPI); the sunset hero banner is the header; the CI
  exit-code behaviour is documented (exit 0 regardless of findings — parse the report JSON to gate CI).
- Suite: **379 passed**.

## [0.7.0] — 2026-07-16  ·  LAUNCH BUILD (report redesign · recall · Windows-safe --prove · SECURITY/CI)

### Changed — the customer report is redesigned to read like antivirus + the website
- **Antivirus-style status banner** leads every report: **RED "Action needed"** (proven-live or reachable-
  unguarded > 0), **AMBER "Review before you ship"** (install-liability > 0), **BLUE "No live threat proven"**
  (clean — never "secure"). State is encoded in colour + icon + plain words so a non-technical reader gets an
  instant read.
- **Coherence fix:** the fix plan derives each row's tier from the SAME rule as the headline stat
  (`UNGUARDED_CRITICAL_LIVE_SINK`). Reachable-unguarded → "reachable now — fix first"; install-liability →
  a separate "wiring-time — gate on install" treatment. No finding is ever both "fix-first reachable" and
  "inert"; the fix-first count equals the reachable stat.
- **Honest paid-Repairer CTA** ("The Repairer is coming — the paid tier, early access"; diff-proposed,
  human-approved, re-scanned; never auto-fix; no price, no present-tense overclaim) with a clickable link.
- **Plain-language strip** (found / urgent / to-do) + jargon expanded once (RCE-class, install-liability,
  proven-live); readable masthead with scan date + version; footer over-claim removed.
- **Sunset-terminal skin** matching hermesshield.ai (Fraunces / IBM Plex Mono / Instrument Sans; blaze / heat
  / blue / cream; fonts embedded — the report opens offline). Coverage % is computed against the scanned
  target (not the CWD); singular/plural fixed.

### Added / Fixed
- **`.get()` untrusted-source recall (deterministic core, additive):** `request.args.get("x")` /
  `.form.get` / `.json.get` / `.getlist` are now recognised as untrusted sources — the common Flask/FastAPI
  idiom the engine was missing. Request-scoped: innocent `dict.get`/`os.environ.get`/`cfg.get` stay quiet.
  Every existing finding still found; nothing removed.
- **`--prove` refuses cleanly off Linux+bubblewrap** (was: would crash on native Windows via the POSIX-only
  fallback, or run a network-exposed sandbox on macOS). Now a plain "the scan itself ran fully" message.
- **`SECURITY.md`** (vulnerability-disclosure policy), **GitHub Actions CI** (3-OS × Python 3.10–3.13 +
  demo smoke test; artefact-only release workflow, no publish step), and a **`conftest.py`** so a bare-
  checkout `pytest` works before an editable install.

### Unchanged / safety
- Deterministic core numbers byte-identical except the intended additive `.get()` recall. Report changes are
  display-only (scan data byte-identical). Honesty phrases preserved. Suite: **377 passed**.
- **Not published** — publishing to PyPI + a public repo remain human-gated.

## [0.6.0] — 2026-07-16  ·  PROVEN-LIVE self-attack lane (opt-in, sandboxed, promote-only)

### Added — `--prove`: empirically prove a finding is live, harmlessly, on your own machine
- **New opt-in `--prove` lane** (off by default, **not** in `--all`, loud per-run consent). After the read-only
  scan it attempts to PROVE candidate-critical RCE surfaces by driving them with a benign, per-run
  **unforgeable-nonce** canary payload **inside a bwrap sandbox** (network denied, target read-only, tmpfs,
  one writable cell, rlimits + wall-clock kill). A finding is promoted to **PROVEN-LIVE** only when the nonce
  fires *via the sink*, a **negative control** stays clean, and the result **reproduces**. **Promote-only** —
  a failed/inconclusive/refused proof leaves the finding a candidate; it **never** downgrades anything to
  "safe" and never emits a false "proven". Each attempt writes an evidence bundle (payload, entrypoint,
  taint path, nonce effect, negative control, isolation config). Available on `demo --prove` (bundled
  fixture) and `scan --prove <repo>` (a repo you trust). Fills the existing `build_report(validated=)` hook.
- **Dataflow-based drivability (was parameter-name-based).** Whether a sink is provable is now decided by
  real intra-function dataflow — does a value derived from a parameter reach the sink's *injectable*
  argument — not by the parameter's NAME. This **unlocks real `eval`/`exec` vulns the name-gate silently
  missed** (a sink fed by a param named `expr`/`code`/`cmd` now proves) **and kills false positives** (a sink
  whose injectable argument is a compile-time constant — e.g. `__import__("re")`, a constant JS body — is no
  longer treated as an injection point). The driver now fills other required parameters with benign defaults
  (no more `missing 'url'` aborts) and binds positional-only params correctly.
- **Proves shell-injection `subprocess_exec`** (Phase 2a): a `shell=True`/`os.system` sink whose command
  string is param-derived is proven with a benign shell canary (`: ; printf <nonce> > <cell>/<nonce>`);
  list-argv and constant commands are refused (recipe only). This covers the two commonest agent-RCE shapes
  (untrusted→`eval`, model-output→shell). Demonstrated: on a realistic vulnerable agent the lane proves
  `eval(expr)`, a shell tool, and an LLM-output→shell sink — 3 PROVEN-LIVE, HIGH.

### Unchanged / safety
- The **deterministic core, `--semgrep`, `--ai`, `--deps`, and all scan numbers are byte-identical with
  `--prove` off.** The scanner's default taint path (`analyze()`) is untouched; all new logic lives behind
  `--prove`. Honesty phrases preserved. Suite: **370 passed**.
- **Known robustness gap (fails SAFE):** under an exotic multi-hop interpreter symlink chain (e.g. a
  uv-managed venv under a sandbox-masked path like `/tmp`), a proof returns *inconclusive* rather than
  proving — never a false "proven". Real installs (system Python, pipx, normal venvs) prove correctly. Bind
  the full interpreter symlink chain as a follow-up.
- **Not a public claim yet:** proven-live counts are only quotable publicly once run on genuinely-vulnerable
  code we did not author (a real framework, responsibly disclosed) — not on fixtures we named to be provable.

## [0.5.0] — 2026-07-16  ·  LAUNCH-HARDENING (honesty reframe · Windows fixes · CLI ergonomics · licence)

### Changed — the report leads with the MAP, not the verdict
- **Customer report + terminal panel now lead with the action-surface map.** The headline was
  `"OVERALL RISK: None (no proven-live)"`, which read as *"found nothing"* even on a repo with hundreds of
  surfaces. The customer HTML/terminal now lead with *"N places this code can act — mapped"* and display-map
  the verdict to **"No proven-live exploit path"** (amber/neutral, **never green** — green read as "all
  clear"). Zero-state lines mean a scan with 0 reachable but >0 install-liability still says what it FOUND,
  and a 0/0 scan still reports the surfaces mapped — it never says "found nothing". **Display-only:** the
  deterministic audit artefacts (`install_report` JSON/markdown, all scan numbers) are **byte-identical**, and
  the honesty phrases ("inert here, live on install", "not demonstrated", 'never "secure"') survive verbatim.

### Fixed — Windows launch blockers
- **Report-write crash on native Windows.** 37 text I/O calls omitted `encoding=`; on a cp1252 code page the
  scan finished then crashed writing the (box-art/Unicode) report. All now `encoding="utf-8"`.
- **`--ai` failed silently on Windows** (and swallowed all AI-tier errors everywhere). The claude subprocess
  now resolves via `shutil.which` and **fails loud** — a broken/absent/timed-out AI backend records a visible
  `AI tier: FAILED — <reason>` in the summary and report instead of masquerading as "AI ran, found nothing".
  The deterministic core scan still completes regardless (fail-open preserved).
- **"Open the report" hint** used `start` (a cmd builtin) — broken in PowerShell (the Win11 default); now
  `Invoke-Item`.

### Added — friction-killers
- **`hermes-shield demo`** — scans a bundled, inert vulnerable-agent fixture and produces a real red
  `UNGUARDED_CRITICAL_LIVE_SINK` report in ~10 seconds, so a first-time user sees what a finding looks like.
- **No-arg `hermes-shield scan` "detect & pick".** With no target it narrates the enclosing-git-repo it will
  scan (with an escape hatch), and when run outside a repo it offers a bounded, TTY-only picker of candidate
  repos. CI/piped behaviour unchanged (scans CWD, never blocks on stdin).
- **`--version`** flag; bare `hermes-shield` now prints help and exits 0.

### Licence & packaging
- **LICENSE is now the complete Apache-2.0 text** (was a stub reading "replace before public release"); README
  licence line reconciled (the "evaluation use only" wording is gone).
- **PyPI-ready metadata** (authors, project URLs, classifiers, `_demo` package data) and a second console
  script so `uvx hermes-shield-scanner scan .` works. `dependencies = []` (stdlib-only) preserved. **Not
  published** — publishing remains a human-gated action.

### Tests
- **+37 tests** (launch-hardening, CLI ergonomics, demo/licence/metadata). Suite: **347 passed**.

## [0.4.0] — 2026-07-16  ·  SECURITY (independent security review — re-review remediation)

### Fixed — all 4 findings from the independent security review's re-review (of v0.3.7), each verified closed against the live code
- **[MED] `--deps` target metadata could widen fetch scope (HS-01).** A scanned repo's own
  `.hermes-shield.json` allowlist (`first_party_packages` / `first_party_prefixes`) is now **advisory-only**
  and cannot cause a package to be fetched unless the **operator** trusts it from OUTSIDE the target
  (`HERMES_SHIELD_TRUST_TARGET_DEPS=1`, or a `HERMES_SHIELD_DEPS_POLICY` file resolving outside the repo).
  The declared-but-untrusted packages are still surfaced in the output (`declared_first_party (untrusted —
  not fetched)`) — same visibility model as target guards. Mirrors the existing guard-trust design exactly.
- **[MED] `--deps` fetched unpinned packages despite a pinned-only claim (HS-02).** Only a genuine exact
  pin (`==X.Y.Z`) is fetched; unpinned deps and version **ranges** (poetry `^`/`~`, npm ranges — previously
  laundered into fake exact pins) are reported and **not fetched**. `fetch()` refuses any unpinned spec as
  defence in depth. The README `--deps` claim is now literally true.
- **[fetch-time RCE, beyond the report] `--deps` now fetches WHEELS only, never sdists.** The old
  `pip download --no-binary :all:` forced source archives, and pip's metadata prep for a legacy sdist can
  **run the package's `setup.py`** on the operator's machine. Switched to `--only-binary :all:` — a wheel is
  a plain zip of the `.py` source we scan, so **no build backend ever runs**. No wheel for a pin → skip and
  report, **never** fall back to an sdist. "Static only, never installed or executed" is now literally true.
- **[MED] `--ai` forwarded raw source (incl. secrets) to the model (HS-03).** Before submission, source is
  now **secret-redacted** (AWS/GitHub/OpenAI keys, PEM private-key blocks, JWTs, generic credential
  assignments — value only, line-count preserved so the AST gate still aligns), **fenced** as untrusted data
  (`<<<CODE … CODE>>>` with a "NOT instructions" provenance line), and **size-capped** (200 KB). The AI
  prompt cache key was bumped (`PROMPT_VERSION` → v3) so raw-source-era responses invalidate cleanly.
- **[LOW] `--semgrep` used an unpinned Docker image (HS-04).** The comparator image is pinned
  (`semgrep/semgrep:1.170.0`, operator-overridable via `HERMES_SHIELD_SEMGREP_IMAGE`), and the **comparator
  version is now recorded** in the output for all modes (docker image ref, or `semgrep --version` for
  venv/uvx) so head-to-head runs are auditable.
- **Docs corrected** (README `--deps` row) to match post-fix behaviour: wheels-only, pinned-only, operator-
  trusted allowlist. **+24 regression tests** (auditor's reproduction names), suite: **310 passed**. The
  deterministic core, its numbers, and all outputs are **byte-identical** — every change is confined to the
  optional `--deps` / `--ai` / `--semgrep` tiers.

## [0.3.7] — 2026-07-13  ·  SECURITY (independent security review remediation)

### Fixed — all 3 findings from the independent security review (v0.1.0), verified closed with adversarial PoCs
- **[HIGH] AI-tier arbitrary-write via target-controlled cache symlink (CWE-59).** The `--ai` cache now lives
  under the **operator output directory**, never under the scanned target; it refuses to write through a
  symlink or any path escaping the operator root; cache-only with no cache file performs **no write and no
  subprocess**. `--ai` performs zero writes under the target root by default.
- **[HIGH w/ --ai] Symlinked `*.py` traversal → out-of-root reads + AI disclosure (CWE-22/61).** Traversal
  (`_iter_py`/`_iter_lang`) skips symlinks and resolves every candidate against the canonical target root
  before reading; the `--ai` target selection re-asserts the same containment — out-of-root files are never
  read or forwarded to the local `claude` CLI.
- **[MED] Target `.hermes-shield.json` self-attesting critical guards.** Target-declared guards are now
  **advisory-only** and cannot downgrade a finding unless an operator explicitly trusts them from OUTSIDE
  the target (`HERMES_SHIELD_TRUST_TARGET_GUARDS=1` or a `HERMES_SHIELD_GUARD_POLICY` file outside the repo);
  the scan record marks their trust status.
- **Docs corrected** so safety claims match post-fix behaviour (banner, report, README, ARCHITECTURE,
  FOR_AUDITORS): the deterministic core is read-only + local + symlink-safe; `--ai` forwards in-root code text
  to your local `claude`; `--deps` fetches your pinned packages. Dropped the unqualified "never reads secrets".
- **+5 regression tests** (the auditor's exact finding names) so none of these can regress. Suite: **286 passed**.

## [0.3.6] — 2026-07-10

### Fixed
- **Core recall fix — group sinks by full scope path** (`ast_sinks` emits `scope_path`; `repo_scanner`
  groups by `(scope_path, capability)` not the bare enclosing name). Two same-named methods in DIFFERENT
  classes (e.g. `ClassA.handle` and `ClassB.handle`, each with an `eval`) no longer collapse into one
  surface — each becomes its own finding. Surfaced by the Gate-4 benchmark (SuperAGI `output_handler.py:180`
  was hidden as a sibling of `:149`; now distinct). **True same-function duplicate sinks still collapse**
  (intentional noise control). Gate-4 recall on the known-RCE set: **4/6 → 5/6** (the remaining miss,
  RA.Aid `ciayn_agent.py:691`, is a genuine same-method duplicate — detected, reported as a sibling of the
  caught `:533` surface — not a dedup bug). Blast radius on surface counts: +0.5–0.7% (more honest recall,
  not inflation). Displayed `symbol` unchanged (scope path is a grouping key only).

## [0.3.5] — 2026-07-10

### Added
- **"Fix plan — generated, not applied" report section** (HTML + markdown) — the bridge to the paid
  repairer. A real **remediation dictionary** keyed on actual capabilities (`code_exec` → "replace eval/exec
  with ast.literal_eval or a sandboxed evaluator + human-gate", `subprocess_exec` → "shell=False, argument
  allowlist, never interpolate model output", `deserialize`/`ssti`/`secret_exfil`/`tool_invoke`/… ) in
  fix-at-source language — replaces the old Hermes-lane jargon. Scoped **hard** to confirmed NO_GATE /
  FAKE_GATE findings only (never unproven/possibly-guarded code). Every item is labelled **PLANNED — not
  applied**; the section states the scanner plans and does NOT modify code, and the paid repairer "applies
  under a human gate — never auto-fix". Install-liability items get wiring-time guidance, never
  "fix this vulnerability". +7 tests (281 total).

## [0.3.4] — 2026-07-10

### Fixed (honesty patch — credibility before external eyes)
- **HTML report no longer hardcodes "100% of the source tree"** — it prints the real computed coverage
  ("X% of scannable source"), sourced from the corrected denominator below.
- **Coverage denominator now honest** — `install_report._coverage_pct` counts files using the SAME
  SKIP_DIRS walk as the scanner (`repo_scanner`), so `.venv`/`build`/`dist` no longer inflate the
  denominator and under-report coverage.
- **`FOR_AUDITORS.md` reproduce command corrected** — `PYTHONPATH=src python3 -m pytest tests/` (274 pass,
  0 skipped); the old bare `pytest tests/` (which aborts on a non-installed checkout) and stale 255/1 count
  are gone.
- **OS-aware "open the report" hint** — macOS `open`, WSL `explorer.exe`, other Linux `xdg-open`, Windows
  `start`; no wrong-OS instruction.
- **Banner "no network egress" is now truthful under `--deps`** — reworded to "network: fetches your pinned
  deps only" when the dependency tier (which reaches the network) is active.

## [0.3.3] — 2026-07-10

### Changed
- **Messaging rewritten to a professional security-vendor voice** across the CLI banner and the HTML report. Removed the
  defensive lines ("honest by rule", "we never run your private code") — replaced with capability/architecture
  statements: *excessive-agency scanner for AI-agent code · static analysis · runs fully local ·
  reachability-rated · no network egress*. The report subtitle, meta-line, "how to read this" note and footer
  now carry the same voice (evidence-based severity, "not demonstrated exploitable", no virtue claims).

## [0.3.2] — 2026-07-10

### Changed
- **Branded HTML report.** The customer/exec report (`shield_customer_report.html`) is rebuilt: dark,
  branded (matches the CLI), and leads with the SAME headline as the scan — reachable-in-repo,
  install-liability (with band), action-surfaces, files, and the OWASP LLM06 verdict with its honesty
  caveat. Adds the real reachable findings table (`file:line` + capability), the install-liability table,
  and a by-capability action-surface map. Self-contained, screenshot-ready — the report is now a coherent
  final frame, not a plain afterthought.

## [0.3.1] — 2026-07-10

### Changed
- **Phase 2 (reachability) now shows named, progressing sub-steps** instead of a frozen counter — building
  the call graph (live X/N counter), cross-module guard-proof, inter-procedural taint, attributing guards
  (live X/N) — each with the animated spinner + elapsed, so no step ever looks stalled on large repos.
- **Streams the real reachable "● live" findings** (verdict-confirmed, `file:line` + sink) as the payoff of
  the trace, before the results panel. All from the real scan; capped inline, the rest in the report.

## [0.3.0] — 2026-07-10

### Added
- **Live streaming scan output.** Replaces the single static spinner with a real, phase-by-phase stream:
  a climbing file/surface counter while files are mapped, **RCE-class findings ticking off** (`file:line` +
  sink) as their file is scanned, then a climbing **reachability counter** — each phase freezing into a
  green ✓ receipt with its real timing (Map → Trace reachability & guards → Rate OWASP). The spinner
  animates continuously so no phase looks frozen. Every counter and finding is emitted by the real scan as
  the work happens (new optional `progress` callbacks in `repo_scanner.scan_repo` and
  `guard_attribution.apply`) — no fabricated progress, no padding. TTY-only; piped/CI output unchanged.

## [0.2.3] — 2026-07-10

### Added
- **Live scan progress + results panel.** While a scan runs, an animated spinner cycles the real pipeline
  phases (mapping surfaces → tracing reachability → attributing guards → AI/semgrep/deps tiers → OWASP
  rating) with elapsed time, so a scan *feels* like work. On completion, a boxed colour-coded **results
  panel** lands: files + coverage, action-surfaces mapped, the two-tier risk model (Reachable-in-repo /
  Install-liability with band), the OWASP LLM06 verdict with its honesty caveat, and a **"Report written →"**
  pointer to the exact report paths plus a one-line `explorer.exe` open hint. TTY-only: piped/CI output keeps
  the stable terse lines. Cosmetic — never changes the scan or its numbers.

## [0.2.2] — 2026-07-10

### Changed
- **CLI banner wordmark switched to the `Pagga` font** — a compact LED-texture block that reads closest to
  the Hermes Shield dot-matrix mark in a real terminal. Two-tone orange (solid strokes bright, light-shade
  texture dim). Everything else (taglines, tier status line, prompt) unchanged.

## [0.2.1] — 2026-07-10

### Added
- **Branded CLI banner** at the start of a scan: the `HERMES SHIELD` block mark in two-tone orange, the
  tagline (`agent action-security scanner · v<version>` · `local-first · honest by rule` · `we never run
  your private code`), and a live status line showing the **active tiers** (`Core · + AI · + semgrep ·
  + deps`) and the target being scanned. Pure stdlib; degrades to plain text when piped or under `NO_COLOR`;
  suppressed by `--quiet` or `HERMES_SHIELD_NO_BANNER`. Cosmetic only — it never affects the scan.

## [0.2.0] — 2026-07-10

### Added
- **`--deps` dependency-aware scan.** Reads the target's manifest, identifies the repo's **own** pinned
  first-party packages (by namespace / an optional `.hermes-shield.json` allowlist), fetches them
  (`pip download --no-deps --no-binary` — **static only, never installed or executed**), triages each
  (a real capability package vs a benign generated HTTP client), scans the capability packages with the
  same engine, and reports their findings in a **separate `install-inherited-via-dependency` tier** that is
  never merged into the tree headline. New artefact: `hermes_dep_inherited.json`.
  - Motivation: a project can relocate its dangerous capability into pinned deps that are not in the git
    tree, so a tree-only scan under-reports. Verified on a real framework whose execution runtime had moved
    into three pinned SDK packages — `--deps` recovered 28 inherited install-liability surfaces the tree
    scan missed, having correctly ignored 86 of 89 third-party deps.
  - Opt-in + network; OFF by default; **not** included in `--all` (which stays offline). Fail-open: without
    `pip` or when offline, the tier no-ops and the core scan still completes.

### Unchanged
- The deterministic core, `--semgrep`, and `--ai` tiers are byte-identical to 0.1.0 when `--deps` is off.

## [0.1.0] — 2026-07-09

### Added
- Initial standalone action-surface security scanner for AI-agent codebases (OWASP LLM06, Excessive Agency).
- Deterministic core (Python AST sinks + intra/inter-procedural taint + guard-before-sink proof;
  TS/JS + C# sinks-only), optional `--semgrep` comparator, optional `--ai` recall tier, `--all`.
- Two-tier risk model (reachable-in-repo vs install-liability), OWASP severity×likelihood rating.
- Auditor pack: `ARCHITECTURE.md`, `FOR_AUDITORS.md`, sample vulnerable-agent scan.
- **Submitted for an independent security review by an industry professional (2026-07-09).**
