"""
test_s8_90_dep_scan — dependency-aware tier (S8.90): fetch + scan the repo's OWN pinned first-party
packages, catching a capability relocated into a dep not in the tree (the OpenHands case).

Locks:
  - manifest parsing pulls declared deps (pyproject PEP 621 + requirements),
  - first-party classification is by namespace prefix / OPERATOR-TRUSTED allowlist; third-party is EXCLUDED,
  - HS-01: the target-local .hermes-shield.json allowlist is UNTRUSTED by default (surfaced, never fetched);
    it is honoured only via HERMES_SHIELD_TRUST_TARGET_DEPS=1 or HERMES_SHIELD_DEPS_POLICY resolving
    OUTSIDE the target root,
  - HS-02: pinned-only — unpinned first-party deps (incl. poetry ^/~ ranges) are reported, never fetched;
    fetch() itself refuses without an exact pin and builds exactly `name==pin`,
  - hidden risk: fetch is WHEELS-ONLY (`--only-binary :all:`, never `--no-binary`/sdist — no setup.py runs),
  - triage separates a capability package (exec sinks) from a benign HTTP client (0 exec + client markers),
  - apply() with an INJECTED fetch_fn (no network) deep-scans capability pkgs, skips clients, and keeps its
    counts in a separate tier (merged_into_headline == False),
  - the default scan is UNCHANGED when the flag is off (scan["dep_scan"] == {}),
  - the recursion guard stops a nested dep scan from re-triggering the tier.
"""
from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hermes_shield import dep_scan as DS  # noqa: E402
from hermes_shield import scan_hermes as SH  # noqa: E402


def _write(p: Path, text: str):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


# --------------------------------------------------------------------------- manifest parsing

def test_parse_manifest_pyproject_and_requirements(tmp_path):
    _write(tmp_path / "pyproject.toml",
           '[project]\nname = "myagent"\n'
           'dependencies = ["requests>=2.0", "myagent-runtime==1.2.3", "numpy"]\n')
    _write(tmp_path / "requirements.txt", "flask==3.0.0\n# a comment\nmyagent-tools==0.9\n")
    deps = {d["name"].lower(): d for d in DS.parse_manifest_deps(tmp_path)}
    assert "myagent-runtime" in deps and deps["myagent-runtime"]["pin"] == "1.2.3"
    assert "requests" in deps and "numpy" in deps
    assert "flask" in deps and deps["flask"]["pin"] == "3.0.0"
    assert "myagent-tools" in deps


# --------------------------------------------------------------------------- first-party classification

def test_first_party_by_namespace_prefix(tmp_path):
    _write(tmp_path / "pyproject.toml",
           '[project]\nname = "myagent"\n'
           'dependencies = ["requests>=2.0", "myagent-runtime==1.2.3", "myagent-tools==0.9", "numpy"]\n')
    tagged = {d["name"].lower(): d["first_party"] for d in
              DS.classify_first_party(DS.parse_manifest_deps(tmp_path), tmp_path)}
    assert tagged["myagent-runtime"] is True
    assert tagged["myagent-tools"] is True
    assert tagged["requests"] is False     # third-party never fetched
    assert tagged["numpy"] is False


def test_first_party_config_allowlist(tmp_path, monkeypatch):
    """HS-01 (inverted lock): a TARGET-LOCAL allowlist ALONE is untrusted — it must NOT make a dep
    first-party, and apply() must NOT fetch it. It is surfaced for operator visibility only."""
    monkeypatch.delenv("HERMES_SHIELD_TRUST_TARGET_DEPS", raising=False)
    monkeypatch.delenv("HERMES_SHIELD_DEPS_POLICY", raising=False)
    _write(tmp_path / "pyproject.toml",
           '[project]\nname = "myagent"\ndependencies = ["totally-unrelated==1.0", "requests"]\n')
    _write(tmp_path / ".hermes-shield.json", '{"first_party_packages": ["totally-unrelated"]}')
    cfg, trusted, _status = DS._effective_dep_cfg(tmp_path, DS._load_cfg(tmp_path))
    assert trusted is False and cfg == {}
    tagged = {d["name"].lower(): d["first_party"] for d in
              DS.classify_first_party(DS.parse_manifest_deps(tmp_path), tmp_path, cfg)}
    assert tagged["totally-unrelated"] is False    # target-local allowlist alone -> NOT first-party
    assert tagged["requests"] is False

    calls = []
    res = DS.apply(tmp_path, dest=tmp_path / "_d",
                   fetch_fn=lambda dep, dest: calls.append(dep["name"]) or None)
    assert calls == []                             # NOTHING fetched off a target-local allowlist
    assert res["first_party"] == 0
    assert res["target_dep_cfg"]["trusted_by_operator"] is False
    by = {p["name"].lower(): p for p in res["packages"]}
    assert by["totally-unrelated"]["fetched"] is False
    assert by["totally-unrelated"]["note"] == "declared_first_party (untrusted — not fetched)"


def test_deps_policy_outside_target_honoured(tmp_path, monkeypatch):
    """HS-01 positive: an operator policy file OUTSIDE the target root supplies the allowlist."""
    monkeypatch.delenv("HERMES_SHIELD_TRUST_TARGET_DEPS", raising=False)
    repo = tmp_path / "repo"
    _write(repo / "pyproject.toml",
           '[project]\nname = "myagent"\ndependencies = ["totally-unrelated==1.0", "requests"]\n')
    # the target's own allowlist names something ELSE — it must not leak into classification
    _write(repo / ".hermes-shield.json", '{"first_party_packages": ["requests"]}')
    policy = tmp_path / "operator_policy.json"          # OUTSIDE the target root
    _write(policy, '{"first_party_packages": ["totally-unrelated"]}')
    monkeypatch.setenv("HERMES_SHIELD_DEPS_POLICY", str(policy))

    assert DS._operator_trusts_target_dep_cfg(repo) is True
    fetched = []

    def capture(dep, dest):
        fetched.append(dep["name"].lower())
        return None

    res = DS.apply(repo, dest=tmp_path / "_d", fetch_fn=capture)
    assert fetched == ["totally-unrelated"]             # policy allowlist honoured
    assert res["target_dep_cfg"]["trusted_by_operator"] is True
    by = {p["name"].lower(): p for p in res["packages"]}
    assert "requests" not in by                         # target's own allowlist NOT used


def test_deps_policy_inside_target_ignored(tmp_path, monkeypatch):
    """HS-01 negative: a policy file INSIDE the target root is attacker-controlled — ignored."""
    monkeypatch.delenv("HERMES_SHIELD_TRUST_TARGET_DEPS", raising=False)
    repo = tmp_path / "repo"
    _write(repo / "pyproject.toml",
           '[project]\nname = "myagent"\ndependencies = ["totally-unrelated==1.0"]\n')
    policy = repo / "policy.json"                       # INSIDE the target root
    _write(policy, '{"first_party_packages": ["totally-unrelated"]}')
    monkeypatch.setenv("HERMES_SHIELD_DEPS_POLICY", str(policy))

    assert DS._operator_trusts_target_dep_cfg(repo) is False
    calls = []
    res = DS.apply(repo, dest=tmp_path / "_d",
                   fetch_fn=lambda dep, dest: calls.append(dep["name"]) or None)
    assert calls == [] and res["first_party"] == 0
    assert res["target_dep_cfg"]["trusted_by_operator"] is False


def test_trust_target_deps_env_optin(tmp_path, monkeypatch):
    """HS-01: the blanket operator opt-in (env=1, set OUTSIDE the target) honours the target-local
    allowlist."""
    monkeypatch.delenv("HERMES_SHIELD_DEPS_POLICY", raising=False)
    monkeypatch.setenv("HERMES_SHIELD_TRUST_TARGET_DEPS", "1")
    _write(tmp_path / "pyproject.toml",
           '[project]\nname = "myagent"\ndependencies = ["totally-unrelated==1.0", "requests"]\n')
    _write(tmp_path / ".hermes-shield.json", '{"first_party_packages": ["totally-unrelated"]}')
    fetched = []
    res = DS.apply(tmp_path, dest=tmp_path / "_d",
                   fetch_fn=lambda dep, dest: fetched.append(dep["name"].lower()) or None)
    assert fetched == ["totally-unrelated"]
    assert res["target_dep_cfg"]["trusted_by_operator"] is True


# --------------------------------------------------------------------------- triage

def test_triage_capability_vs_client_vs_inert(tmp_path):
    cap = tmp_path / "cap"
    _write(cap / "runtime.py", "import subprocess\ndef go(x):\n    subprocess.run(x, shell=True)\n")
    assert DS.triage(cap)["kind"] == "capability"

    client = tmp_path / "client"
    _write(client / "_streaming.py", "class Stream:\n    pass\n")
    _write(client / "api.py", "def get(): return 1\n")
    t = DS.triage(client)
    assert t["kind"] == "benign-client" and t["exec_files"] == 0

    inert = tmp_path / "inert"
    _write(inert / "util.py", "def add(a, b): return a + b\n")
    assert DS.triage(inert)["kind"] == "inert"


# --------------------------------------------------------------------------- apply (no network)

def test_apply_deep_scans_capability_skips_client(tmp_path):
    # a repo declaring two OWN pinned deps: a capability package and a benign client
    _write(tmp_path / "pyproject.toml",
           '[project]\nname = "myagent"\n'
           'dependencies = ["myagent-runtime==1.0", "myagent-client==1.0", "requests"]\n')

    # fake fetched package trees (what fetch() would unpack) — no network
    runtime = tmp_path / "_fetched" / "runtime"
    _write(runtime / "exec.py", "import subprocess\ndef run(cmd):\n    subprocess.Popen(cmd, shell=True)\n")
    client = tmp_path / "_fetched" / "client"
    _write(client / "_streaming.py", "class S: pass\n")
    _write(client / "resource.py", "def call(): return 2\n")

    def fake_fetch(dep, dest):
        return {"myagent-runtime": runtime, "myagent-client": client}.get(dep["name"].lower())

    res = DS.apply(tmp_path, dest=tmp_path / "_dest", fetch_fn=fake_fetch)
    assert res["tier"] == "install-inherited-via-dependency"
    assert res["merged_into_headline"] is False
    assert res["first_party"] == 2           # runtime + client (requests excluded)
    assert res["capability_packages"] == 1   # only the runtime is deep-scanned
    by = {p["name"].lower(): p for p in res["packages"]}
    assert by["myagent-runtime"]["kind"] == "capability" and by["myagent-runtime"]["scan"] is not None
    assert by["myagent-client"]["kind"] == "benign-client" and by["myagent-client"]["scan"] is None
    assert isinstance(res["inherited_install_liability"], int)


def test_apply_fetch_failure_is_fail_open(tmp_path):
    _write(tmp_path / "pyproject.toml",
           '[project]\nname = "myagent"\ndependencies = ["myagent-runtime==1.0"]\n')
    res = DS.apply(tmp_path, dest=tmp_path / "_d", fetch_fn=lambda dep, dest: None)
    assert res["first_party"] == 1 and res["fetched"] == 0
    assert res["packages"][0]["note"].startswith("fetch failed")


# --------------------------------------------------------------------------- HS-02: pinned-only fetch

def test_unpinned_first_party_never_fetched(tmp_path):
    """HS-02: an unpinned first-party dep is reported but the fetch function is NEVER called."""
    _write(tmp_path / "pyproject.toml",
           '[project]\nname = "myagent"\n'
           'dependencies = ["myagent-runtime", "myagent-tools>=0.9", "myagent-core==1.2.3"]\n')
    calls = []

    def capture(dep, dest):
        calls.append(dep["name"].lower())
        return None

    res = DS.apply(tmp_path, dest=tmp_path / "_d", fetch_fn=capture)
    assert calls == ["myagent-core"]                    # ONLY the exact pin reaches fetch
    by = {p["name"].lower(): p for p in res["packages"]}
    assert by["myagent-runtime"]["fetched"] is False
    assert by["myagent-runtime"]["note"] == "unpinned — not fetched (pinned-only policy)"
    assert by["myagent-tools"]["fetched"] is False      # >=0.9 is a range, not a pin
    assert by["myagent-tools"]["note"] == "unpinned — not fetched (pinned-only policy)"


def test_poetry_caret_and_tilde_ranges_are_unpinned(tmp_path):
    """HS-02: poetry ^/~ ranges must NOT be laundered into fake exact pins; bare exact stays a pin."""
    _write(tmp_path / "pyproject.toml",
           '[tool.poetry]\nname = "myagent"\n'
           '[tool.poetry.dependencies]\npython = "^3.10"\n'
           'myagent-runtime = "^1.30.0"\nmyagent-tools = "~1.2"\nmyagent-core = "1.5.0"\n')
    deps = {d["name"].lower(): d for d in DS.parse_manifest_deps(tmp_path)}
    assert deps["myagent-runtime"]["pin"] == ""         # ^1.30.0 is a RANGE
    assert deps["myagent-tools"]["pin"] == ""           # ~1.2 is a RANGE
    assert deps["myagent-core"]["pin"] == "1.5.0"       # bare exact = genuine pin

    calls = []
    res = DS.apply(tmp_path, dest=tmp_path / "_d",
                   fetch_fn=lambda dep, dest: calls.append(dep["name"].lower()) or None)
    assert calls == ["myagent-core"]                    # ranges never fetched
    by = {p["name"].lower(): p for p in res["packages"]}
    assert by["myagent-runtime"]["note"] == "unpinned — not fetched (pinned-only policy)"


def test_fetch_refuses_unpinned_defence_in_depth(tmp_path, monkeypatch):
    """HS-02 defence in depth: fetch() itself returns None (no pip call) without an exact pin."""
    ran = []
    monkeypatch.setattr(DS.subprocess, "run", lambda *a, **k: ran.append(a) or None)
    dep = {"name": "myagent-runtime", "pin": "", "ecosystem": "python"}
    assert DS.fetch(dep, tmp_path / "_d") is None
    assert ran == []                                    # pip never invoked
    assert dep["fetch_note"] == "unpinned — not fetched (pinned-only policy)"


def test_fetch_command_exact_pin_and_wheels_only(tmp_path, monkeypatch):
    """HS-02 + hidden risk (fetch command capture): the pip spec is exactly `name==pin` and the
    download is wheels-only (`--only-binary :all:`, never `--no-binary`/sdist — no setup.py runs)."""
    captured = {}

    class _R:
        returncode = 1
        stdout, stderr = "", "network down"

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        return _R()

    monkeypatch.setattr(DS.subprocess, "run", fake_run)
    dep = {"name": "myagent-runtime", "pin": "1.30.0", "ecosystem": "python"}
    DS.fetch(dep, tmp_path / "_d")
    cmd = captured["cmd"]
    assert "myagent-runtime==1.30.0" in cmd             # exact pin, nothing looser
    assert "--only-binary" in cmd and ":all:" in cmd    # wheels only
    assert "--no-binary" not in cmd                     # the sdist path is GONE
    assert "--no-deps" in cmd


def test_fetch_no_wheel_available_skips_never_sdist(tmp_path, monkeypatch):
    """Hidden risk: when no wheel exists for the pin, fetch skips-and-reports — it never retries
    with an sdist (whose metadata prep could execute setup.py)."""
    pip_calls = []

    class _R:
        returncode = 1
        stdout = ""
        stderr = "ERROR: Could not find a version that satisfies the requirement myagent-runtime==1.0\n" \
                 "ERROR: No matching distribution found for myagent-runtime==1.0"

    def fake_run(cmd, **kw):
        pip_calls.append(cmd)
        return _R()

    monkeypatch.setattr(DS.subprocess, "run", fake_run)
    dep = {"name": "myagent-runtime", "pin": "1.0", "ecosystem": "python"}
    assert DS.fetch(dep, tmp_path / "_d") is None
    assert len(pip_calls) == 1                          # ONE wheels-only attempt, no sdist retry
    assert dep["fetch_note"] == "no wheel available — skipped (never falls back to sdist)"

    # and apply() surfaces that note verbatim
    _write(tmp_path / "pyproject.toml",
           '[project]\nname = "myagent"\ndependencies = ["myagent-runtime==1.0"]\n')
    res = DS.apply(tmp_path, dest=tmp_path / "_d2")     # real fetch, pip stubbed above
    assert res["packages"][0]["fetched"] is False
    assert res["packages"][0]["note"] == "no wheel available — skipped (never falls back to sdist)"


def test_fetch_unpacks_wheel_source(tmp_path, monkeypatch):
    """A downloaded wheel (plain zip) is unpacked via the path-traversal guard and its .py source
    returned for static scanning; a traversal member is skipped."""
    import zipfile

    def fake_run(cmd, **kw):
        dest = Path(cmd[cmd.index("-d") + 1])
        whl = dest / "myagent_runtime-1.0-py3-none-any.whl"
        with zipfile.ZipFile(whl, "w") as z:
            z.writestr("myagent_runtime/__init__.py", "VERSION = '1.0'\n")
            z.writestr("myagent_runtime/core.py", "def go():\n    return 1\n")
            z.writestr("../escape.py", "print('escaped')\n")   # traversal attempt

        class _R:
            returncode = 0
            stdout, stderr = "", ""
        return _R()

    monkeypatch.setattr(DS.subprocess, "run", fake_run)
    dep = {"name": "myagent-runtime", "pin": "1.0", "ecosystem": "python"}
    out = DS.fetch(dep, tmp_path / "_d")
    assert out is not None
    py = sorted(p.name for p in Path(out).rglob("*.py"))
    assert py == ["__init__.py", "core.py"]
    assert not list(Path(tmp_path).rglob("escape.py"))  # traversal member skipped everywhere


# --------------------------------------------------------------------------- wiring: default off + guard

def test_flag_off_default_unchanged(tmp_path, monkeypatch):
    _write(tmp_path / "pyproject.toml",
           '[project]\nname = "myagent"\ndependencies = ["myagent-runtime==1.0"]\n')
    monkeypatch.delenv("HERMES_SHIELD_DEPS", raising=False)
    scan = SH.run_scan(tmp_path)
    assert scan["dep_scan"] == {}          # byte-identical default: tier never ran


def test_recursion_guard_blocks_nested_tier(tmp_path, monkeypatch):
    _write(tmp_path / "pyproject.toml",
           '[project]\nname = "myagent"\ndependencies = ["myagent-runtime==1.0"]\n')
    monkeypatch.setenv("HERMES_SHIELD_DEPS", "1")
    monkeypatch.setenv("_HERMES_SHIELD_IN_DEP_SCAN", "1")   # simulate being inside a dep scan
    scan = SH.run_scan(tmp_path)
    assert scan["dep_scan"] == {}          # guard prevents fetch-of-deps-of-deps
