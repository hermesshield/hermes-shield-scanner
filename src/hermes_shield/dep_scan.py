#!/usr/bin/env python3
"""Dependency-aware scan (S8.90) — optional, flag-gated (HERMES_SHIELD_DEPS=1), network, opt-in.

WHY THIS EXISTS. A project can factor its dangerous capability into pinned FIRST-PARTY dependency
packages that are not in the git tree. The motivating case: OpenHands (2026-07) relocated its whole
code-execution runtime out of the repo into `openhands-sdk` / `openhands-tools` / `openhands-agent-server`
(pinned `==1.30.0`). A tree-only scan then saw ~0 reachable RCE while a user who *installs* the tool
inherits 28 shell/terminal/exec surfaces. This tier closes that coverage gap: it reads the repo's own
manifest, identifies the repo's OWN pinned first-party packages, fetches them (static only — never
installed, never executed), triages each (a benign HTTP client vs a real capability package), scans the
capability packages with the SAME engine, and reports their findings in a SEPARATE
`install-inherited-via-dependency` tier that is NEVER merged into the tree headline.

HONESTY RAILS (non-negotiable):
- Only FIRST-PARTY pins (the repo's own supply chain, by namespace prefix or an operator-trusted
  allowlist). Third-party deps (requests, numpy, langgraph, ...) are never fetched.
- PINNED-ONLY (HS-02). Only a genuine exact `==X.Y.Z` pin is fetched. Unpinned deps and range
  specifiers (poetry `^`/`~`, npm `^`/`~`, wildcards) are reported but NEVER fetched — an unpinned
  fetch would pull whatever is latest on the index, which the repo never tested.
- OPT-IN + NETWORK. OFF by default; degrades gracefully if pip is missing or the machine is offline.
- NEVER install or execute a fetched package. Fetch is WHEELS ONLY
  (`pip download --no-deps --only-binary :all:`): a wheel is a plain zip archive of the `.py` source
  we scan — no build backend / `setup.py` ever runs. If no wheel exists, the dep is skipped and
  reported; we never fall back to an sdist (whose metadata prep can execute code at fetch time).
- TARGET CONFIG IS UNTRUSTED (HS-01). The target-local `.hermes-shield.json` allowlist keys are
  parsed and SURFACED but IGNORED for classification unless the OPERATOR opts in from OUTSIDE the
  target (HERMES_SHIELD_TRUST_TARGET_DEPS=1, or HERMES_SHIELD_DEPS_POLICY pointing at a policy file
  outside the target root). Mirrors scan_hermes._operator_trusts_target_guards.
- benign-client vs capability triage is reported; a client dep (generated HTTP SDK, 0 exec sinks) is not
  deep-scanned and is labelled so — the same distinction that keeps composio-client / letta-client honest.
- This tier's counts are attributed `install-inherited-via-dependency` and stand ALONGSIDE, never inside,
  the tree's reach/install headline.

Config (optional) via the target's `.hermes-shield.json` (untrusted by default, see above):
    { "first_party_prefixes": ["myorg"], "first_party_packages": ["some-exact-dep"] }
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tarfile
import zipfile
from pathlib import Path

# RCE-class capability tokens used for the cheap triage grep (mirrors patterns._RCE_CAPS intent).
_EXEC_RE = re.compile(
    r"subprocess\.(?:run|Popen|call|check_call|check_output)\(|\bos\.system\(|\bos\.popen\("
    r"|\bexec\(|\beval\(|\bpty\.|\bpickle\.load|\byaml\.load\(|\b__import__\(|/bin/(?:sh|bash)"
)
# Generated-HTTP-client signature (Stainless/OpenAPI style): present => likely a benign API client.
_CLIENT_MARKERS = ("_streaming.py", "_response.py", "_base_client.py", "_resource.py", "_client.py")

_SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", "test", "tests"}


# --------------------------------------------------------------------------- manifest parsing

def _load_toml(text: str):
    """Best-effort TOML load: tomllib (3.11+) -> tomli -> None (caller falls back to regex)."""
    try:
        import tomllib  # type: ignore
        return tomllib.loads(text)
    except Exception:
        pass
    try:
        import tomli  # type: ignore
        return tomli.loads(text)
    except Exception:
        return None


_REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*([<>=!~][^;#]*)?", )

# A genuine EXACT pin: a bare version ("1.2.3") or explicitly "==1.2.3" / "=1.2.3".
# Deliberately EXCLUDES range operators (^ ~ > < * ,) — a range is unpinned (HS-02).
_EXACT_PIN_RE = re.compile(r"(?:==?\s*)?([0-9][0-9A-Za-z.\-+]*)")


def _exact_pin(v) -> str:
    """Return the exact pinned version from a manifest value, or '' if it is anything other than a
    genuine exact pin (caret/tilde/wildcard ranges, comparators, dicts, tables => unpinned)."""
    if not isinstance(v, str):
        return ""
    m = _EXACT_PIN_RE.fullmatch(v.strip())
    return m.group(1) if m else ""


def _split_req(spec: str):
    """'openhands-sdk==1.30.0 ; extra' -> (name, pin_or_'') . Returns (None, '') on junk."""
    spec = (spec or "").split(";", 1)[0].strip()
    if not spec or spec.startswith(("#", "-", "git+", "http", ".", "/")):
        return None, ""
    m = _REQ_RE.match(spec)
    if not m:
        return None, ""
    name = m.group(1)
    verspec = (m.group(2) or "").strip()
    pin = ""
    pm = re.search(r"==\s*([0-9][0-9A-Za-z.\-+]*)", verspec)
    if pm:
        pin = pm.group(1)
    return name, pin


def parse_manifest_deps(root: Path) -> list[dict]:
    """Collect declared dependencies from the repo's manifests. Returns
    [{name, pin, ecosystem, source}] (deduped by name). Fail-open per file."""
    root = Path(root)
    out: dict[str, dict] = {}

    def add(name, pin, eco, src):
        if not name:
            return
        key = name.lower().replace("_", "-")
        # keep the first pin we see, but prefer a concrete pin over an empty one
        if key not in out or (pin and not out[key]["pin"]):
            out[key] = {"name": name, "pin": pin, "ecosystem": eco, "source": src}

    # pyproject.toml — PEP 621 [project] + poetry [tool.poetry]
    pp = root / "pyproject.toml"
    if pp.exists():
        text = _safe_read(pp)
        data = _load_toml(text) if text else None
        if data:
            proj = data.get("project", {}) or {}
            for dep in proj.get("dependencies", []) or []:
                n, pin = _split_req(dep)
                add(n, pin, "python", "pyproject:dependencies")
            for _grp, deps in (proj.get("optional-dependencies", {}) or {}).items():
                for dep in deps or []:
                    n, pin = _split_req(dep)
                    add(n, pin, "python", "pyproject:optional")
            poetry = (data.get("tool", {}) or {}).get("poetry", {}) or {}
            for n, v in (poetry.get("dependencies", {}) or {}).items():
                if n.lower() == "python":
                    continue
                # HS-02: only a genuine EXACT pin counts ("1.2.3" or "==1.2.3"). Poetry caret/tilde
                # ranges (^1.30.0, ~1.2) and wildcards (1.*) are RANGES — stripping the operator and
                # treating them as exact pins would fetch a version the repo never tested. Ranges are
                # classified unpinned (pin="") and therefore never fetched.
                add(n, _exact_pin(v), "python", "pyproject:poetry")
        elif text:
            # regex fallback if no TOML parser is available
            for m in re.finditer(r'"([A-Za-z0-9][A-Za-z0-9._-]*\s*(?:[<>=!~][^"]*)?)"', text):
                n, pin = _split_req(m.group(1))
                add(n, pin, "python", "pyproject:regex")

    # requirements*.txt
    for req in sorted(root.glob("requirements*.txt")) + sorted(root.glob("*/requirements*.txt")):
        text = _safe_read(req)
        if not text:
            continue
        for line in text.splitlines():
            n, pin = _split_req(line)
            add(n, pin, "python", f"requirements:{req.name}")

    # package.json — JS (detected + reported; JS fetch is a documented limitation for now)
    pj = root / "package.json"
    if pj.exists():
        try:
            data = json.loads(_safe_read(pj) or "{}")
            for section in ("dependencies", "optionalDependencies"):
                for n, v in (data.get(section, {}) or {}).items():
                    # HS-02 (same rule as poetry): npm ^/~ ranges are NOT exact pins.
                    add(n, _exact_pin(v), "npm", f"package.json:{section}")
        except Exception:
            pass

    return list(out.values())


# --------------------------------------------------------------------------- first-party classification

def _repo_namespaces(root: Path) -> set[str]:
    """Namespaces that mark a dependency as the repo's OWN (first-party). Derived from the project name
    and the top-level importable package dirs. Normalised (lower, '_'~'-'), min length 3.

    HS-01 NOTE (accepted, by design): this derives first-party namespaces from the TARGET's own
    pyproject name / package dirs, so it is target-influenced. That is the point of the tier — the
    repo's own supply chain IS defined by the repo. The blast radius is bounded elsewhere: only
    genuine exact pins are ever fetched (HS-02), fetch is wheels-only static (never executes), and
    the fetched code is only SCANNED — a hostile manifest can at worst add scan noise in the
    separate, attributed dependency tier, never code execution and never headline changes."""
    root = Path(root)
    ns: set[str] = set()

    def _add(token: str):
        t = (token or "").strip().lower().replace("_", "-")
        if len(t) >= 3:
            ns.add(t)
            ns.add(t.split("-")[0]) if len(t.split("-")[0]) >= 3 else None

    pp = root / "pyproject.toml"
    if pp.exists():
        data = _load_toml(_safe_read(pp) or "")
        if data:
            _add(((data.get("project", {}) or {}).get("name") or ""))
            _add((((data.get("tool", {}) or {}).get("poetry", {}) or {}).get("name") or ""))
    # importable top-level packages (incl. src/<pkg> layout)
    for base in (root, root / "src"):
        if not base.is_dir():
            continue
        for child in base.iterdir():
            try:
                if child.is_dir() and (child / "__init__.py").exists() and child.name not in _SKIP_DIRS:
                    _add(child.name)
            except Exception:
                pass
    ns.discard("")
    return ns


def classify_first_party(deps: list[dict], root: Path, cfg: dict | None = None) -> list[dict]:
    """Tag each dep first_party True/False. A dep is first-party if its (normalised) name equals or is
    prefixed by one of the repo's namespaces, OR it is named/prefixed by the .hermes-shield.json allowlist.
    Prefix-match is deliberately conservative — an exact-version pin ALONE is NOT treated as first-party
    (too noisy); it only counts alongside a namespace match."""
    cfg = cfg or {}
    ns = _repo_namespaces(root)
    pref = {p.lower().replace("_", "-") for p in (cfg.get("first_party_prefixes") or [])}
    allow = {p.lower().replace("_", "-") for p in (cfg.get("first_party_packages") or [])}
    ns |= pref

    def _is_fp(name: str) -> bool:
        n = name.lower().replace("_", "-")
        if n in allow:
            return True
        for base in ns:
            if n == base or n.startswith(base + "-"):
                return True
        return False

    tagged = []
    for d in deps:
        d = dict(d)
        d["first_party"] = _is_fp(d["name"])
        tagged.append(d)
    return tagged


def _load_cfg(root: Path) -> dict:
    try:
        return json.loads((Path(root) / ".hermes-shield.json").read_text(encoding="utf-8"))
    except Exception:
        return {}


def _dep_policy_path(root: Path) -> Path | None:
    """HS-01: resolve HERMES_SHIELD_DEPS_POLICY to a trusted policy file. The file must resolve
    OUTSIDE the target root — a policy inside the target would itself be attacker-controlled, so it
    is ignored. Returns the resolved path or None."""
    pol = os.getenv("HERMES_SHIELD_DEPS_POLICY")
    if not pol:
        return None
    try:
        pp = Path(pol).resolve()
        rr = Path(root).resolve()
        inside_target = pp == rr or rr in pp.parents
        if pp.is_file() and not inside_target:
            return pp
    except OSError:
        pass
    return None


def _operator_trusts_target_dep_cfg(root: Path) -> bool:
    """HS-01: the target-local .hermes-shield.json `first_party_packages`/`first_party_prefixes`
    keys expand what gets FETCHED, so they earn classification credit ONLY on an explicit OPERATOR
    opt-in made OUTSIDE the untrusted target (the exact model of
    scan_hermes._operator_trusts_target_guards). Two operator channels:
      - HERMES_SHIELD_TRUST_TARGET_DEPS=1     (blanket opt-in to the target-local allowlist), or
      - HERMES_SHIELD_DEPS_POLICY=<path>      pointing at a policy file that resolves OUTSIDE the
        target root — in which case the allowlist is loaded from THAT file, never the target's.
    Default: False (target-local allowlist is parsed, surfaced, and IGNORED for classification)."""
    if os.getenv("HERMES_SHIELD_TRUST_TARGET_DEPS") == "1":
        return True
    return _dep_policy_path(root) is not None


def _effective_dep_cfg(root: Path, target_cfg: dict) -> tuple[dict, bool, str]:
    """Return (cfg_used_for_classification, trusted, status_note). Precedence:
    blanket env opt-in trusts the target-local cfg; otherwise an operator policy file OUTSIDE the
    target substitutes its OWN allowlist; otherwise the target-local cfg is ignored (advisory)."""
    if os.getenv("HERMES_SHIELD_TRUST_TARGET_DEPS") == "1":
        return dict(target_cfg or {}), True, "operator-trusted (HERMES_SHIELD_TRUST_TARGET_DEPS=1)"
    pol = _dep_policy_path(root)
    if pol is not None:
        try:
            cfg = json.loads(pol.read_text(encoding="utf-8"))
            if not isinstance(cfg, dict):
                cfg = {}
        except Exception:
            cfg = {}
        return cfg, True, f"operator policy file ({pol})"
    return {}, False, "advisory-only (untrusted — target-local allowlist ignored)"


# --------------------------------------------------------------------------- fetch (network, opt-in)

def fetch(dep: dict, dest: Path) -> Path | None:
    """Fetch a Python WHEEL with pip (NO deps, ONLY binary), unpack it, and return the unpacked source dir.

    WHEELS ONLY (audit re-assessment, hidden risk): `pip download --no-binary :all:` forces sdists,
    and pip's metadata preparation for a legacy sdist can RUN the package's build backend / `setup.py`
    on the operator's machine — code execution at fetch time. A wheel is a plain zip archive of the
    `.py` source we scan: no build step runs, so "static only, never installed or executed" is
    literally true. If no wheel exists for the pin, the dep is skipped and reported (via
    dep["fetch_note"]); we NEVER fall back to an sdist.

    PINNED ONLY (HS-02 defence in depth): refuses to fetch without a genuine exact pin — apply()
    already filters unpinned deps out, but an unpinned spec here would download whatever is latest.

    Never installs, never executes. Cached: an already-unpacked dir is reused. Returns None on any
    failure (fail-open — the core tree scan is unaffected)."""
    if dep.get("ecosystem") != "python":
        return None
    name, pin = dep["name"], dep.get("pin") or ""
    if not pin:
        dep["fetch_note"] = "unpinned — not fetched (pinned-only policy)"
        return None
    slug = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{name}-{pin}")
    pkg_dest = Path(dest) / slug
    unpacked = pkg_dest / "_src"
    if unpacked.is_dir() and any(unpacked.rglob("*.py")):
        return unpacked  # cache hit
    pkg_dest.mkdir(parents=True, exist_ok=True)
    spec = f"{name}=={pin}"
    try:
        r = subprocess.run(
            ["pip", "download", "--no-deps", "--only-binary", ":all:", spec, "-d", str(pkg_dest)],
            capture_output=True, text=True, timeout=300,
        )
    except Exception:
        return None
    if r.returncode != 0:
        err = ((r.stderr or "") + (r.stdout or "")).lower()
        if "no matching distribution" in err or "could not find a version" in err:
            dep["fetch_note"] = "no wheel available — skipped (never falls back to sdist)"
        return None
    wheels = list(pkg_dest.glob("*.whl"))
    if not wheels:
        dep["fetch_note"] = "no wheel available — skipped (never falls back to sdist)"
        return None
    unpacked.mkdir(parents=True, exist_ok=True)
    try:
        _safe_extract_zip(wheels[0], unpacked)
    except Exception:
        return None
    return unpacked


# --------------------------------------------------------------------------- triage

def triage(pkg_dir: Path) -> dict:
    """Cheap static triage of a fetched package: count exec-class sink files, detect the generated-client
    signature. Returns {kind, exec_files, has_client_markers}. 'benign-client' = 0 exec + client markers;
    'capability' = has exec sinks; 'inert' = neither (no visible capability)."""
    pkg_dir = Path(pkg_dir)
    exec_files, has_markers = 0, False
    for py in pkg_dir.rglob("*.py"):
        if any(part in _SKIP_DIRS for part in py.parts):
            continue
        if py.name in _CLIENT_MARKERS:
            has_markers = True
        text = _safe_read(py)
        if text and _EXEC_RE.search(text):
            exec_files += 1
    if exec_files > 0:
        kind = "capability"
    elif has_markers:
        kind = "benign-client"
    else:
        kind = "inert"
    return {"kind": kind, "exec_files": exec_files, "has_client_markers": has_markers}


# --------------------------------------------------------------------------- per-package scan

def scan_package(pkg_dir: Path) -> dict:
    """Scan a fetched package with the same engine and rate it. Sets a recursion guard so the nested scan
    does NOT itself fetch dependencies. Returns the inherited-tier figures for this package."""
    from . import scan_hermes, install_report
    prev = os.environ.get("_HERMES_SHIELD_IN_DEP_SCAN")
    os.environ["_HERMES_SHIELD_IN_DEP_SCAN"] = "1"
    try:
        scan = scan_hermes.run_scan(Path(pkg_dir))
        rep = install_report.build_report(Path(pkg_dir), scan)
    finally:
        if prev is None:
            os.environ.pop("_HERMES_SHIELD_IN_DEP_SCAN", None)
        else:
            os.environ["_HERMES_SHIELD_IN_DEP_SCAN"] = prev
    return {
        "files": scan.get("files_scanned", 0),
        "reachable": rep.get("non_gated_vulnerable", 0),
        "install_liab": rep.get("install_liability_rce", 0),
        "band": (rep.get("install_liability_rating") or {}).get("band", ""),
        "overall": rep.get("overall_rating", ""),
    }


# --------------------------------------------------------------------------- orchestration

def apply(root: Path, dest: Path | None = None, fetch_fn=fetch) -> dict:
    """Run the dependency-aware tier. Parses manifests, keeps first-party EXACT pins, fetches + triages
    them, deep-scans capability packages, and returns the attributed inherited tier. fetch_fn is
    injectable so tests never hit the network. Fail-open: returns a structured result even when nothing
    is fetched.

    HS-01: the target-local allowlist is untrusted by default — see _operator_trusts_target_dep_cfg.
    Deps the target DECLARED first-party but the operator has not trusted are surfaced (visibility,
    like scan["target_guards"]) but never fetched.
    HS-02: unpinned first-party deps are surfaced but never fetched (pinned-only policy)."""
    root = Path(root)
    dest = Path(dest) if dest else (root.parent / f".hermes_shield_deps_{root.name}")
    target_cfg = _load_cfg(root)
    cfg, cfg_trusted, cfg_status = _effective_dep_cfg(root, target_cfg)
    deps = parse_manifest_deps(root)
    tagged = classify_first_party(deps, root, cfg)
    first_party = [d for d in tagged if d["first_party"]]

    # HS-01 visibility: what the target ASKED to be treated as first-party but the operator has not
    # trusted. Parsed, surfaced, never fetched — the operator can SEE the request and opt in.
    declared_untrusted = []
    if not cfg_trusted and target_cfg:
        fp_names = {d["name"].lower() for d in first_party}
        declared_untrusted = [d for d in classify_first_party(deps, root, target_cfg)
                              if d["first_party"] and d["name"].lower() not in fp_names]

    results = []
    tot_reach = tot_install = 0
    for d in declared_untrusted:
        results.append({"name": d["name"], "pin": d.get("pin", ""), "ecosystem": d["ecosystem"],
                        "source": d.get("source", ""), "fetched": False, "kind": None, "scan": None,
                        "declared_first_party": True,
                        "note": "declared_first_party (untrusted — not fetched)"})
    for d in first_party:
        entry = {"name": d["name"], "pin": d.get("pin", ""), "ecosystem": d["ecosystem"],
                 "source": d.get("source", ""), "fetched": False, "kind": None, "scan": None,
                 "note": ""}
        if d["ecosystem"] != "python":
            entry["note"] = "non-python ecosystem — fetch not yet implemented (detected, not scanned)"
            results.append(entry)
            continue
        if not d.get("pin"):
            # HS-02: never fetch without a genuine exact pin — an unpinned fetch pulls whatever is
            # latest on the index, which is not the supply chain the repo declared.
            entry["note"] = "unpinned — not fetched (pinned-only policy)"
            results.append(entry)
            continue
        pkg_dir = fetch_fn(d, dest)
        if not pkg_dir:
            entry["note"] = d.get("fetch_note") or "fetch failed or offline — not scanned"
            results.append(entry)
            continue
        entry["fetched"] = True
        tri = triage(Path(pkg_dir))
        entry["kind"] = tri["kind"]
        entry["exec_files"] = tri["exec_files"]
        if tri["kind"] == "capability":
            sc = scan_package(Path(pkg_dir))
            entry["scan"] = sc
            tot_reach += sc["reachable"]
            tot_install += sc["install_liab"]
            entry["note"] = "capability package — deep-scanned (inherited surface)"
        elif tri["kind"] == "benign-client":
            entry["note"] = "generated HTTP client (0 exec sinks) — not deep-scanned"
        else:
            entry["note"] = "no visible capability (0 exec sinks) — not deep-scanned"
        results.append(entry)

    return {
        "tier": "install-inherited-via-dependency",
        "merged_into_headline": False,
        "manifest_deps": len(deps),
        "first_party": len(first_party),
        "fetched": sum(1 for r in results if r["fetched"]),
        "capability_packages": sum(1 for r in results if r["kind"] == "capability"),
        "inherited_reachable": tot_reach,
        "inherited_install_liability": tot_install,
        # HS-01 visibility: trust status of the target-local allowlist (same pattern as
        # scan["target_guards"]) + how many declared-but-untrusted deps were surfaced, not fetched.
        "target_dep_cfg": {"trusted_by_operator": bool(cfg_trusted),
                           "status": cfg_status,
                           "declared_untrusted": len(declared_untrusted)},
        "packages": results,
    }


# --------------------------------------------------------------------------- helpers

def _safe_read(p: Path) -> str:
    try:
        return Path(p).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _safe_extract_zip(archive: Path, dest: Path):
    """Extract a wheel/zip, rejecting any member that would escape `dest` (the same path-traversal
    guard as _safe_extract, for zip archives). We never execute the contents — a wheel is unpacked
    for static scanning only."""
    dest = Path(dest).resolve()
    with zipfile.ZipFile(archive) as z:
        for info in z.infolist():
            target = (dest / info.filename).resolve()
            if not str(target).startswith(str(dest) + os.sep) and target != dest:
                continue  # skip traversal attempts
            z.extract(info, dest)


def _safe_extract(tar: tarfile.TarFile, dest: Path):
    """Extract a tarball, rejecting any member that would escape `dest` (path-traversal guard). We never
    execute the contents, but we still refuse to write outside the destination."""
    dest = Path(dest).resolve()
    for member in tar.getmembers():
        target = (dest / member.name).resolve()
        if not str(target).startswith(str(dest)):
            continue  # skip traversal attempts
        if member.isdev():
            continue
    tar.extractall(dest, members=[m for m in tar.getmembers()
                                  if str((dest / m.name).resolve()).startswith(str(dest)) and not m.isdev()])
