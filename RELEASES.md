# Releases ledger

The public record of **what shipped, when — and how to reproduce or roll back any version**. Every release
is tagged in git and kept as an immutable artifact, so any version can be checked out and re-built byte-for-byte.

## The deterministic core is unchanged across these versions

The **deterministic core** — the read-only AST scanner, taint/reachability engine, guard model, and rating —
is **byte-identical across the versions below**. Later releases add *optional, off-by-default* tiers
(`--ai`, `--semgrep`, `--deps`, `--prove`) and fix issues in those tiers or in the docs/packaging; none of
them change the core's logic, numbers, or outputs. That is what makes "independently assessed" defensible:
the core that was **independently security-assessed (twice)** is the **same core that ships today** — not a
different build. The assessment record (findings + remediation) is in `CHANGELOG.md` and `FOR_AUDITORS.md`.

## Shipped versions

| Version | Git tag | Date | Notes |
|---|---|---|---|
| 0.7.1 | `v0.7.1` | 2026-07-17 | **current — first public release.** On PyPI: `pip install hermes-shield-scanner`. Live-install verified on Linux/macOS/Windows × py3.10–3.13. |
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

One source of truth: this ledger for *what shipped and how to reproduce it*, `CHANGELOG.md` for *the detail*.
