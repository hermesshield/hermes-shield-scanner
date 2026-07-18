"""
S8.82 CACHE-ONLY mode for the AI-assist tier. The hang bug: ai_tier.apply -> ai_assist.analyze_source spawns
`claude -p` as a subprocess on any cache MISS, and on several repos that subprocess hangs (do_wait) and
freezes the whole scan. HERMES_SHIELD_AI_TIER_CACHE_ONLY=1 makes a cache MISS a skip instead of a subprocess
call, so nothing can hang. These tests prove:
  1. cache-only NEVER calls ai_assist.analyze_source (no subprocess), even on a guaranteed miss;
  2. a cache HIT still replays and adds the AI surface (cache-only does not disable hits);
  3. with the flag OFF, a miss DOES call analyze_source (unchanged behaviour, byte-identical path).
"""
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
for p in (str(_ROOT),):
    if p not in sys.path:
        sys.path.insert(0, p)

from hermes_shield import ai_tier, ai_assist
from hermes_shield.models import ActionSurface


# a prod file that trips the risk/plumbing prefilter so it becomes an AI target
_RISKY = "import subprocess\ndef run(self, cmd):\n    subprocess.Popen(cmd, shell=True)\n"


def _mk_repo(body=_RISKY):
    tmp = Path(tempfile.mkdtemp())
    (tmp / "svc.py").write_text(body)
    return tmp


def _no_call_agent():
    def _propose(prompt, timeout):  # pragma: no cover - must never run in cache-only
        raise AssertionError("analyze_source/subprocess was invoked in CACHE-ONLY mode")
    return _propose


def test_cache_only_miss_never_calls_analyze_source(monkeypatch):
    monkeypatch.setenv("HERMES_SHIELD_AI_TIER_CACHE_ONLY", "1")
    called = {"n": 0}
    orig = ai_assist.analyze_source

    def _boom(*a, **k):
        called["n"] += 1
        raise AssertionError("analyze_source called in cache-only mode")

    monkeypatch.setattr(ai_assist, "analyze_source", _boom)
    root = _mk_repo()
    cache_path = root / ".hermes_shield_ai_cache.json"  # absent -> guaranteed miss
    out = ai_tier.apply(root, [], budget=5, cache_path=cache_path)
    assert called["n"] == 0
    assert out["ai_calls"] == 0
    assert out.get("ai_cache_only") is True
    assert out["ai_skipped_cache_miss"] >= 1
    assert out["ai_surfaces_added"] == 0
    monkeypatch.setattr(ai_assist, "analyze_source", orig)


def test_cache_hit_still_replays_in_cache_only(monkeypatch):
    monkeypatch.setenv("HERMES_SHIELD_AI_TIER_CACHE_ONLY", "1")
    root = _mk_repo()
    cache_path = root / ".hermes_shield_ai_cache.json"
    # pre-seed the cache with the EXACT key ai_tier computes for svc.py
    import hashlib, json
    txt = (root / "svc.py").read_text()
    key = hashlib.sha256(f"{txt}|default|default|{ai_tier.PROMPT_VERSION}".encode()).hexdigest()
    cache_path.write_text(json.dumps({key: [
        {"line": 99, "call": "danger()", "capability": "code_exec", "why": "x", "confidence": 0.9}
    ]}))
    monkeypatch.setattr(ai_assist, "analyze_source", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("hit should not call analyze_source")))
    surfaces = []
    out = ai_tier.apply(root, surfaces, budget=5, cache_path=cache_path)
    assert out["ai_surfaces_added"] == 1, "a cache HIT must still add its AI surface in cache-only mode"
    assert any(s.detection_source in ("ai_suspected", "ai_corroborated") for s in surfaces)


def test_flag_off_miss_calls_analyze_source(monkeypatch):
    monkeypatch.delenv("HERMES_SHIELD_AI_TIER_CACHE_ONLY", raising=False)
    calls = {"n": 0}
    monkeypatch.setattr(ai_assist, "analyze_source", lambda *a, **k: (calls.__setitem__("n", calls["n"] + 1) or []))
    root = _mk_repo()
    cache_path = root / ".hermes_shield_ai_cache.json"
    out = ai_tier.apply(root, [], budget=5, cache_path=cache_path)
    assert calls["n"] >= 1, "with the flag OFF a cache miss must still call analyze_source (unchanged path)"
    assert "ai_cache_only" not in out, "off-path return must stay byte-identical (no cache-only keys)"
