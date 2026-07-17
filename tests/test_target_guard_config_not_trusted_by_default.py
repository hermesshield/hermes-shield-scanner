"""
audit finding #3 (MED, CWE-501 target self-attestation) — a repo-local `.hermes-shield.json` must NOT,
on its own, downgrade the target's own unguarded critical sink to a guarded/trusted state. Target-declared
guards are honoured only on an explicit OPERATOR opt-in made OUTSIDE the untrusted target.
"""
import json
import tempfile
from pathlib import Path

from hermes_shield import scan_hermes as SH

_CFG = {"guard_modules": ["myguards"], "guard_symbols": ["assert_ok"]}


def _repo(cfg=None):
    d = Path(tempfile.mkdtemp())
    (d / "myguards.py").write_text("def assert_ok():\n    return True\n")
    (d / "app.py").write_text(
        "from myguards import assert_ok\n"
        "def handle(request):\n"
        "    x = request.data\n"
        "    assert_ok()\n"
        "    import os\n"
        "    os.system(x)\n")
    if cfg is not None:
        (d / ".hermes-shield.json").write_text(json.dumps(cfg))
    return d


def _subproc_verdicts(scan):
    return {s.verdict for s in scan["surfaces"] if s.capability == "subprocess_exec"}


def test_target_guard_config_not_trusted_by_default(monkeypatch):
    monkeypatch.delenv("HERMES_SHIELD_TRUST_TARGET_GUARDS", raising=False)
    monkeypatch.delenv("HERMES_SHIELD_GUARD_POLICY", raising=False)

    no_cfg = _subproc_verdicts(SH.run_scan(_repo(None)))
    default = _subproc_verdicts(SH.run_scan(_repo(_CFG)))

    # the unguarded critical sink is present without config...
    assert "UNGUARDED_CRITICAL_LIVE_SINK" in no_cfg
    # ...and a repo-local config ALONE must not change/downgrade it (byte-identical to no config)
    assert default == no_cfg, f"repo-local .hermes-shield.json downgraded the sink without operator trust: {default}"
    assert "UNGUARDED_CRITICAL_LIVE_SINK" in default

    # non-vacuous: an explicit operator opt-in DOES let the same declaration influence the verdict,
    # proving the guard is genuinely on-path and only operator trust gates its effect.
    monkeypatch.setenv("HERMES_SHIELD_TRUST_TARGET_GUARDS", "1")
    trusted = _subproc_verdicts(SH.run_scan(_repo(_CFG)))
    assert trusted != no_cfg, "operator opt-in did not change guard crediting — test would be vacuous"
    # and the scan record marks the trust status visibly
    meta = SH.run_scan(_repo(_CFG))["target_guards"]
    assert meta["trusted_by_operator"] is True and meta["declared_symbols"] == 1
