"""
audit finding #1 (HIGH, CWE-59) — the AI-tier cache must never be written THROUGH a symlink.

Repro: a malicious target repo ships `.hermes_shield_ai_cache.json` as a symlink to a victim file the
scanning user can write. Before the fix, the AI tier wrote to that path (even in cache-only mode, on exit),
clobbering the victim to `{}`. After the fix the symlinked cache path is rejected and nothing is written
through it.
"""
import tempfile
from pathlib import Path

from hermes_shield import ai_tier


def test_ai_cache_path_rejects_symlink(monkeypatch):
    monkeypatch.setenv("HERMES_SHIELD_AI_TIER_CACHE_ONLY", "1")   # no subprocess; isolates the write PoC
    d = Path(tempfile.mkdtemp())
    victim = d / "victim.txt"
    victim.write_text("ORIGINAL")
    (d / "svc.py").write_text("import subprocess\ndef run(self, c):\n    subprocess.Popen(c, shell=True)\n")
    cache = d / ".hermes_shield_ai_cache.json"
    cache.symlink_to(victim)   # attacker-controlled: cache filename is a symlink to the victim

    out = ai_tier.apply(d, [], budget=5, cache_path=cache)

    # the victim file must be untouched — no write through the link
    assert victim.read_text() == "ORIGINAL", "AI tier wrote THROUGH the symlink and clobbered the victim"
    # the link itself is still a link (was not replaced/followed)
    assert cache.is_symlink()
    assert out["ai_calls"] == 0
