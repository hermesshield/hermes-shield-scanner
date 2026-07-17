"""
audit finding #1 (HIGH) — the AI-tier cache must live under an OPERATOR-owned directory, never under
the untrusted target root. With default settings, running the AI tier must not create a cache file
anywhere inside the scanned repo.
"""
import tempfile
from pathlib import Path

from hermes_shield import ai_tier


def test_ai_default_cache_not_under_target_root(monkeypatch):
    monkeypatch.setenv("HERMES_SHIELD_AI_TIER_CACHE_ONLY", "1")   # ensure no subprocess/side effects
    d = Path(tempfile.mkdtemp())
    (d / "svc.py").write_text("import subprocess\ndef run(self, c):\n    subprocess.Popen(c, shell=True)\n")

    # default cache location (no cache_path, no cache_dir) — must NOT be derived from the target root
    ai_tier.apply(d, [], budget=5)

    assert not (d / ".hermes_shield_ai_cache.json").exists(), "cache created directly under target root"
    assert not list(d.rglob(".hermes_shield_ai_cache.json")), "cache created somewhere under target root"
