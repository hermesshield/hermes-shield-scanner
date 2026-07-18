# Releases ledger

The public record of **what shipped, when — and how to reproduce or roll back any version**. Every release
is tagged in git and kept as an immutable artifact, so any version can be checked out and re-built byte-for-byte.

## The deterministic core: what's stable, and what deliberately evolves

The **safety properties** of the deterministic core — read-only, fully local, never executes the target's
code, symlink-safe traversal — hold across **every** version below and are regression-locked. What the core
**detects** and how it **rates** a finding does deliberately improve over time: each change is
recall-additive or verdict-correcting, itemised per-version in `CHANGELOG.md`, and locked by a regression
test so it cannot silently reverse. Later releases also add *optional, off-by-default* tiers (`--ai`,
`--semgrep`, `--deps`, `--prove`) confined to those tiers.

The independent security assessments were of **v0.1.0** (first pass) and **v0.3.7** (re-assessment). Every
core change since those builds is recorded in `CHANGELOG.md`, so an auditor can diff the assessed tree
against any later tag — `git diff v0.3.7 vX.Y.Z`. **Re-validation of the current core against the
assessment is pending.** Within a single version the core is deterministic: same input, same output,
byte-for-byte. The assessment record (findings + remediation) is in `CHANGELOG.md` and `FOR_AUDITORS.md`.

## Shipped versions

| Version | Git tag | Date | Notes |
|---|---|---|---|
| 0.8.0 | *(pending tag — this branch)* | 2026-07-18 | **current (unreleased).** Core verdict-taxonomy change — output **intentionally NOT identical to 0.7.x**: reachable, unguarded agent-action sinks now band RED (high-impact/irreversible) or AMBER (reversible/social) instead of BLUE; dedup folds a partition to its worst-banded member. Detail in `CHANGELOG.md`. |
| 0.7.1 | `v0.7.1` | 2026-07-17 | **first public release.** On PyPI: `pip install hermes-shield-scanner`. Live-install verified on Linux/macOS/Windows × py3.10–3.13. |
| 0.7.0 | `v0.7.0` | 2026-07-16 | report redesign · `.get()` recall · Windows-safe `--prove` · SECURITY.md / CI |
| 0.6.0 | `v0.6.0` | 2026-07-16 | proven-live self-attack lane (opt-in `--prove`, sandboxed, promote-only; dataflow drivability; shell-injection proving) |
| 0.5.0 | `v0.5.0` | 2026-07-16 | launch-hardening — report reframe · Windows fixes · demo / detect-pick / `--version` · Apache-2.0 licence |
| 0.4.0 | `v0.4.0` | 2026-07-16 | security — third-party re-assessment remediation (HS-01/02/03/04 + fetch-time-RCE closed, all in optional tiers) |
| 0.3.7 | `v0.3.7` | 2026-07-13 | security — third-party assessment remediation (HS findings closed with adversarial PoCs) |
| 0.3.6 | `v0.3.6` | 2026-07-10 | core recall fix (group sinks by full scope path) |
| 0.3.5 | `v0.3.5` | 2026-07-10 | maintenance |
| 0.3.4 | `v0.3.4` | 2026-07-10 | maintenance |
| 0.3.3 | `v0.3.3` | 2026-07-10 | maintenance |
| 0.3.2 | `v0.3.2` | 2026-07-10 | maintenance |
| 0.3.1 | `v0.3.1` | 2026-07-10 | maintenance |
| 0.3.0 | `v0.3.0` | 2026-07-10 | maintenance |
| 0.2.3 | `v0.2.3` | 2026-07-10 | maintenance |
| 0.2.2 | `v0.2.2` | 2026-07-10 | maintenance |
| 0.2.1 | `v0.2.1` | 2026-07-10 | maintenance |
| 0.2.0 | `v0.2.0` | 2026-07-10 | `--deps` dependency-aware scan added |
| 0.1.0 | `v0.1.0` | 2026-07-09 | initial standalone scanner — the build put through the first independent third-party security assessment |

The full, dated change detail for every version is in **`CHANGELOG.md`**.

## Roll back / reproduce any version

- **Source:** `git checkout vX.Y.Z` — the exact tree that version was built from.
- **Shipped bytes:** each tagged version has a matching immutable artifact under `dist/`, never overwritten.
- **Diff two versions:** `git diff v0.1.0 v0.2.0`.

## How a release is cut (every iterate → ship)

1. Make the change on a branch; tests green — `PYTHONPATH=src pytest tests/`.
2. Bump the version in **two** places (they must match): `pyproject.toml` and
   `src/hermes_shield/models.py` (`SCANNER_VERSION`). SemVer: PATCH = fix, MINOR = new feature (e.g. a new
   optional tier), MAJOR = breaking change.
3. Add a `CHANGELOG.md` entry for the version (what changed + why).
4. Commit, then tag: `git tag -a vX.Y.Z -m "..."`.
5. Build the versioned artifact from the tag (tracked files only — no local cruft).
6. Add a row to the table above (version, tag, date, notes).
7. **Update the site truth file in the same change** — `hermes_shield_site/content/hermes-shield-truth.json`
   (`scanner_version` and any quoted metrics) — so the site never drifts from the shipped package.

One source of truth: this ledger for *what shipped and how to reproduce it*, `CHANGELOG.md` for *the detail*.
