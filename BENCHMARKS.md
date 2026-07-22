# Benchmarks — the 12-framework scan of record

**Current (v0.8.0, re-stamped 2026-07-21):** **12 open-source agent frameworks · 361k+ combined GitHub
stars · 8,447 action surfaces mapped · 596 reachable-in-repo · 542 install-liability (reachability we
can't rule out).**

> **v0.8.1 re-run (2026-07-22):** 8,438 / 596 / 533 — **within 0.1%** of the v0.8.0 record; **NOT re-stamped.**
> The v0.8.1 precision fix removed constant-literal false positives that were concentrated in non-framework
> code, so the 12-framework benchmark is essentially unchanged. The v0.8.0 figures above remain the dated
> benchmark of record — deliberately held stable rather than churned for a negligible difference.

> **ENGINE-VERSION NOTE.** The **v0.8.0** figures above supersede the historic pre-v0.3.6 record (8,509 /
> 474 / 520, record date 2026-07-08, table further down). Two things moved, both by design:
> - **Reachable-in-repo 474 → 596.** v0.8.0's revised taxonomy bands reachable, unguarded agent-action
>   sinks RED/AMBER instead of silently BLUE, so it surfaces more real paths.
> - **Install-liability 520 → 542, and now 0 "proven-inert".** v0.8.0 refuses to assert a dangerous
>   inherited capability is *inert* when it cannot prove untrusted input can't reach it. Every one of the
>   542 is banded **reachability-unknown** — dangerous capability you inherit on install, whose reachability
>   we **can't rule out**. We no longer call any of them "dormant/inert"; that was an unbacked safety claim
>   the v0.8.0 engine is built to refuse. The tiers now split by **evidence, not safety**: reachable-in-repo
>   = "we found the path"; install-liability = "we can't clear the path". **Zero** are proven-live.
>
> Basis of the v0.8.0 re-stamp: **deterministic core only** (no AI tier, no cache, no network beyond clone),
> each framework at the same pinned SHA, canonical counts from the scanner's own reconciled report. Fully
> reproducible. The historic table below is retained for transparency — a silent swap would be the real
> attack surface.

## v0.8.0 per-framework (2026-07-21, deterministic core, pinned commits)

| Framework | Pinned commit | Action surfaces | Reachable-in-repo | Install-liability |
|---|---|---:|---:|---:|
| babyagi | `fa8930ebe72a` | 42 | 2 | 5 |
| SuperAGI | `c3c1982e7bd6` | 346 | 25 | 23 |
| julep | `64fc34ca836c` | 75 | 6 | 17 |
| notte | `8f3df6a163b7` | 115 | 0 | 9 |
| cua | `b654f27d609e` | 1,109 | 33 | 273 |
| potpie | `a191a5ea2e93` | 620 | 21 | 34 |
| langflow | `315cc41b43c4` | 955 | 20 | 55 |
| RA.Aid | `e71bb83dcfdf` | 55 | 1 | 16 |
| agno | `f28a2469a17c` | 1,887 | 205 | 35 |
| llama_index | `7fd33e00a894` | 1,280 | 157 | 26 |
| letta | `b76da9092518` | 1,005 | 100 | 35 |
| semantic-kernel | `e6c9673684ca` | 958 | 26 | 14 |
| **Total (12)** | — | **8,447** | **596** | **542** |

*(Install-liability here = the v0.8.0 `reachability-unknown` band: RCE-class capability inherited on install
whose reachability the static tracer cannot rule out. 0 of the 542 are proven-inert.)*

---

## Historic record (pre-v0.3.6 engine, record date 2026-07-08)

This is the original evidence behind the earlier README line: **8,509 action surfaces mapped · 474 proved
reachable · 520 install-liability**.

> **HISTORIC — pre-v0.3.6 engine (record date 2026-07-08).** These counts are NOT current v0.8.0 output.
> Superseded by the v0.8.0 re-stamp above; retained for transparency.

Every framework was scanned **at a pinned commit** (the `@SHA` below), with the deterministic core plus a
**cache-only** AI tier (`HERMES_SHIELD_AI_TIER=1` + `HERMES_SHIELD_AI_TIER_CACHE_ONLY=1`, `ai_calls == 0`
asserted on every repo — no network). The numbers are a **de-inflation** of an earlier draft: the three
corrections applied can only *remove* false positives, never add findings.

- **Date of record:** 2026-07-08
- **Scanner engine of record:** as of 2026-07-08 — **pre-v0.3.6**. These figures predate three later
  recall/verdict changes to the deterministic core (0.3.6 scope-path recall, 0.7.0 `.get()` untrusted-source
  recall, and the v0.8.0 verdict taxonomy + dedup worst-band fold). See the reproduction note at the foot of
  this file — a re-run on a current engine will report **different (generally higher)** counts.
- **Mode:** local, deterministic core + cache-only AI tier (no network, `ai_calls == 0`)
- **Headline metric:** **install-liability** — the dangerous capability (code-exec / deserialize / shell /
  SSTI class) a user **inherits the moment they install** and wire the tool into an agent that reads
  untrusted input. Inert in the repo, live on install. **Reachable-in-repo is secondary** — it counts sinks
  reachable from a *real in-repo entry point* per static taint (some of these frameworks ship apps/servers,
  so a non-zero count is legitimate).

## Per-framework results (each scanned at a pinned commit)

| Framework | Pinned commit | Action surfaces | Reachable-in-repo | Install-liability |
|---|---|---:|---:|---:|
| babyagi | `fa8930ebe72a` | 80 | 2 | 11 |
| SuperAGI | `c3c1982e7bd6` | 366 | 20 | 22 |
| julep | `64fc34ca836c` | 102 | 3 | 21 |
| notte | `8f3df6a163b7` | 136 | 0 | 13 |
| cua | `b654f27d609e` | 1,081 | 21 | 261 |
| potpie | `a191a5ea2e93` | 575 | 15 | 34 |
| langflow | `315cc41b43c4` | 923 | 15 | 47 |
| RA.Aid | `e71bb83dcfdf` | 54 | 1 | 16 |
| agno | `f28a2469a17c` | 1,763 | 131 | 20 |
| llama_index | `7fd33e00a894` | 1,108 | 116 | 26 |
| letta | `b76da9092518` | 1,401 | 141 | 34 |
| semantic-kernel | `e6c9673684ca` | 920 | 9 | 15 |
| **Total (12)** | — | **8,509** | **474** | **520** |

*(The `Reachable-in-repo` and `Install-liability` columns are the post-correction, post-AI-tier totals — the
`reach_after` / `install-liab_after` numbers in the source record. Combined GitHub stars — **361k+** — is the
public GitHub star figure for these 12 repositories, not a scanner output.)*

## What these numbers mean (and do not)

- **Install-liability (520)** is the honest headline for installable frameworks. `cua` (a computer-use agent,
  genuinely exec/subprocess-heavy) alone accounts for 261 of it.
- **Reachable-in-repo (474)** is accurate and secondary — a real in-repo entry point's untrusted value
  reaches the sink unguarded per static taint. It is **not** a proof-of-concept and **not** "exploitable".
- **OWASP overall rating = `None (no proven-live)` on all 12.** No finding here is human-traced +
  PoC-confirmed; there is no severity verdict attached to any of these candidates.
- **Sound-leaning, not complete.** The corrections remove-only (dev/vendor reclassification, a `cap_normalise`
  force-fit fix, and a stdin-in-CLI-`__main__` exclusion). The guard model is Python-only; non-Python surfaces
  (e.g. C#/TS in semantic-kernel / cua) are counted but their gated/non-gated reasoning is not trusted.
- **Cache-only AI tier.** An AI surface only appears if its analysis was already cached; a cache miss is
  skipped — so the AI net-new contribution is a floor, not a ceiling.

Full methodology, the three corrections, and the brutally-honest "what actually moved" breakdown are in the
internal scan record this file is derived from (Stage S8.85, 2026-07-08).

## Reproducing these figures (engine-version stamp)

These figures were produced by the scanner **engine as of the date of record, 2026-07-08 (pre-v0.3.6)**.
Later engine versions have strictly higher recall and, **as of v0.8.0**, a revised verdict taxonomy
(reachable, unguarded agent-action sinks now band RED/AMBER rather than BLUE), so a re-run with a **current**
version will report **different — generally higher** — counts. To reproduce these **exact** figures, check
out the engine as of the record date (the pre-v0.3.6 tree) and scan the same pinned commits. The refreshed
12-framework run on v0.8.0 was **completed and re-stamped on 2026-07-21** — see the v0.8.0 table at the top
(deterministic core, same pinned commits, canonical reconciled counts).

