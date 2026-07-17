# Benchmarks — the 12-framework scan of record

This is the evidence behind the README line: **12 open-source agent frameworks · 361k+ combined GitHub
stars · 8,509 action surfaces mapped · 474 proved reachable · 520 install-liability**.

Every framework was scanned **at a pinned commit** (the `@SHA` below), with the deterministic core plus a
**cache-only** AI tier (`HERMES_SHIELD_AI_TIER=1` + `HERMES_SHIELD_AI_TIER_CACHE_ONLY=1`, `ai_calls == 0`
asserted on every repo — no network). The numbers are a **de-inflation** of an earlier draft: the three
corrections applied can only *remove* false positives, never add findings.

- **Date of record:** 2026-07-08
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
internal scan record this file is derived from (Stage S8.85, 2026-07-08). This document reproduces the
numbers of record for public verification; re-run the scanner against the same pinned commits to reproduce them.
