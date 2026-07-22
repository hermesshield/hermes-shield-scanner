"""Shared AI backend layer — first slice (branch fix/ai-suspected-verdict-leak).

`ai_backends.get_backend(id)` returns the `propose(prompt, timeout) -> raw_text` callable that
`ai_assist.analyze_source(..., agent=)` / `ai_tier.apply(..., agent=)` already accept. Because redaction
(`_redact_secrets`) + size-cap (`_cap_ai_source`) run INSIDE analyze_source BEFORE the prompt reaches any
backend, every backend threaded through that seam is protected for free.

These tests lock the safety-critical invariants:
  (a) byte-identical golden — AI-off scan output unchanged vs the golden captured from HEAD.
  (b) default / unset backend routes to ai_assist.claude_agent VERBATIM (byte-identical to today).
  (c) EVERY wired backend's prompt goes through _redact_secrets — a planted secret never reaches the
      mocked transport (claude subprocess AND ollama urllib — no real network).
  (d) ollama-on only APPENDS an ai_suspected surface; it never mutates a static surface's verdict.
  (e) a broken ollama (mocked HTTP 500 / refused connection) raises AIAgentError and surfaces
      ai_status == "failed" — it does NOT silently report empty.

All secret values below are SYNTHETIC.
"""
from __future__ import annotations

import io
import json
import os
import urllib.error
from pathlib import Path

import pytest

from hermes_shield import ai_assist, ai_backends, ai_tier
from hermes_shield.models import ActionSurface

_GHP = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"          # 36-char synthetic github token


# =====================================================================================================
# (a) BYTE-IDENTICAL GOLDEN — AI-off scan output unchanged vs HEAD
# =====================================================================================================
def _serialise_ai_off_scan():
    from hermes_shield import scan_hermes
    root = (Path(__file__).resolve().parent / "mock_lanes")
    scan = scan_hermes.run_scan(root)
    surfaces = sorted((s.to_dict() for s in scan["surfaces"]),
                      key=lambda d: json.dumps(d, sort_keys=True))
    return json.dumps({"surfaces": surfaces,
                       "ai_tier_counts": scan.get("ai_tier_counts", {}),
                       "files_scanned": scan.get("files_scanned")}, sort_keys=True, indent=2)


def test_ai_off_scan_is_byte_identical_to_golden(monkeypatch):
    """With the AI tier OFF (and no backend selected), the deterministic scan of the mock lanes is
    byte-identical to the golden captured from HEAD — the backend seam is inert off the AI path."""
    monkeypatch.delenv("HERMES_SHIELD_AI_TIER", raising=False)
    monkeypatch.delenv("HERMES_SHIELD_AI_BACKEND", raising=False)
    golden = (Path(__file__).resolve().parent / "fixtures" / "golden_ai_off_mock_lanes.json").read_text()
    assert _serialise_ai_off_scan() == golden


# =====================================================================================================
# (b) DEFAULT / UNSET backend == ai_assist.claude_agent VERBATIM (byte-identical to today)
# =====================================================================================================
def test_default_and_unset_backend_route_to_claude_agent(monkeypatch):
    """get_backend(None) and get_backend("claude") must return exactly ai_assist.claude_agent(model) — so an
    unset selection is byte-identical to the historical default path."""
    calls = []
    sentinel = object()

    def fake_claude_agent(model=None):
        calls.append(model)
        return sentinel

    monkeypatch.setattr(ai_assist, "claude_agent", fake_claude_agent)

    assert ai_backends.get_backend(None, model="m") is sentinel
    assert ai_backends.get_backend("", model="m") is sentinel
    assert ai_backends.get_backend("claude", model="m") is sentinel
    assert ai_backends.get_backend("CLAUDE") is sentinel          # id is case-insensitive
    assert calls == ["m", "m", "m", None]


def test_cloud_backends_are_wired_and_fail_loud_without_key(monkeypatch):
    """anthropic / openai / venice / gemini are WIRED (Loop 5) — with the key env MISSING they fail loud
    AT CONSTRUCTION with an actionable 'set X_API_KEY' message, never a silent skip. The full cloud suite
    (endpoint/auth/extraction/redaction, mocked HTTP) lives in test_ai_backends_cloud.py."""
    for bid, env in (("anthropic", "ANTHROPIC_API_KEY"), ("openai", "OPENAI_API_KEY"),
                     ("venice", "VENICE_API_KEY"), ("gemini", "GEMINI_API_KEY")):
        monkeypatch.delenv(env, raising=False)
        assert bid in ai_backends.WIRED_BACKENDS
        with pytest.raises(ai_assist.AIAgentError) as ei:
            ai_backends.get_backend(bid)
        assert f"set {env}" in str(ei.value)


def test_unknown_backend_fails_loud():
    """An unknown id fails loud (never silently falls back to claude and hides a typo)."""
    with pytest.raises(ai_assist.AIAgentError) as ei:
        ai_backends.get_backend("gpt5")
    assert "unknown AI backend" in str(ei.value)


# =====================================================================================================
# (c) REDACTION applies to EVERY wired backend — secret never reaches the mocked transport
# =====================================================================================================
_SECRET_SRC = (
    "import subprocess\n"
    f'TOKEN = "{_GHP}"\n'
    "def run(cmd):\n"
    "    subprocess.run(cmd, shell=True)\n"
)


def test_claude_backend_prompt_is_redacted(monkeypatch):
    """The claude backend receives a prompt with the secret REDACTED (redaction happens in analyze_source
    before the propose() transport is called). Mocks the subprocess — no CLI is launched."""
    seen = {}

    class _Proc:
        returncode = 0
        stdout = "[]"
        stderr = ""

    def fake_run(cmd, **kw):
        seen["prompt"] = cmd[cmd.index("-p") + 1]
        return _Proc()

    monkeypatch.setattr(ai_assist.shutil, "which", lambda name: "/usr/bin/claude")
    monkeypatch.setattr(ai_assist.subprocess, "run", fake_run)

    ai_assist.analyze_source(_SECRET_SRC, agent=ai_backends.get_backend("claude"))
    assert _GHP not in seen["prompt"], "raw secret leaked to the claude backend"
    assert "[REDACTED:github-token]" in seen["prompt"]


class _FakeResp:
    """Minimal urlopen()-compatible response usable as a context manager."""
    def __init__(self, body: str, status: int = 200):
        self._body = body.encode("utf-8")
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def getcode(self):
        return self.status

    def read(self):
        return self._body


def test_ollama_backend_prompt_is_redacted(monkeypatch):
    """The ollama backend receives a prompt with the secret REDACTED. Mocks urllib.urlopen — no network."""
    seen = {}

    def fake_urlopen(req, timeout=None):
        payload = json.loads(req.data.decode("utf-8"))
        seen["prompt"] = payload["prompt"]
        seen["model"] = payload["model"]
        return _FakeResp(json.dumps({"response": "[]"}))

    monkeypatch.setattr(ai_backends.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setenv("HERMES_SHIELD_OLLAMA_MODEL", "llama-test")

    ai_assist.analyze_source(_SECRET_SRC, agent=ai_backends.get_backend("ollama"))
    assert _GHP not in seen["prompt"], "raw secret leaked to the ollama backend"
    assert "[REDACTED:github-token]" in seen["prompt"]
    assert seen["model"] == "llama-test"                          # env-configured model honoured


# =====================================================================================================
# (d) ollama-on only APPENDS an ai_suspected surface — never mutates a static verdict
# =====================================================================================================
_NOVEL_SRC = (
    "import subprocess\n"                     # 1
    "def run(cmd):\n"                         # 2
    "    subprocess.run(cmd, shell=True)\n"   # 3  <- static surface here
    "def send(client, payload):\n"           # 4
    "    a = 1\n"                             # 5
    "    b = 2\n"                             # 6
    "    c = 3\n"                             # 7
    "    d = 4\n"                             # 8
    "    return client.deliver(payload)\n"    # 9  <- novel surface the AI 'finds' (far from static line)
)


def test_ollama_only_appends_ai_suspected_row(monkeypatch, tmp_path):
    (tmp_path / "agent_app.py").write_text(_NOVEL_SRC)
    # a pre-existing STATIC surface for the subprocess line — its verdict must be untouched.
    static = ActionSurface(id="static", file_path="agent_app.py", line_start=3, sink_line=3,
                           symbol="run", capability="code_exec", context="prod",
                           detection_source="static", verdict="BLOCK_LIVE_PROMOTION")
    surfaces = [static]

    def fake_urlopen(req, timeout=None):
        reply = json.dumps([{"line": 9, "call": "client.deliver(payload)", "capability": "send",
                             "why": "novel exfil surface static missed", "confidence": 0.7}])
        return _FakeResp(json.dumps({"response": reply}))

    monkeypatch.setattr(ai_backends.urllib.request, "urlopen", fake_urlopen)
    agent = ai_backends.get_backend("ollama")
    out = ai_tier.apply(tmp_path, surfaces, budget=5, agent=agent, cache_path=tmp_path / "cache.json")

    assert out["ai_status"] == "ok"
    assert out["ai_surfaces_added"] == 1
    # the static surface's deterministic verdict is UNCHANGED
    assert static.verdict == "BLOCK_LIVE_PROMOTION"
    # exactly one appended AI surface, advisory-tiered, never a deterministic verdict
    ai_rows = [s for s in surfaces if s.detection_source != "static"]
    assert len(ai_rows) == 1
    assert ai_rows[0].detection_source == "ai_suspected"
    assert ai_rows[0].verdict == "AI_SUSPECTED_REVIEW"
    assert ai_rows[0].line_start == 9


# =====================================================================================================
# (e) broken ollama raises AIAgentError and surfaces ai_status == "failed" — never a silent empty
# =====================================================================================================
def test_broken_ollama_http_500_raises_ai_agent_error(monkeypatch):
    def fake_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 500, "Internal Server Error", {}, io.BytesIO(b""))

    monkeypatch.setattr(ai_backends.urllib.request, "urlopen", fake_urlopen)
    propose = ai_backends.get_backend("ollama")
    with pytest.raises(ai_assist.AIAgentError) as ei:
        propose("prompt", 5)
    assert "HTTP 500" in str(ei.value)


def test_broken_ollama_refused_raises_ai_agent_error(monkeypatch):
    def fake_urlopen(req, timeout=None):
        raise urllib.error.URLError("Connection refused")

    monkeypatch.setattr(ai_backends.urllib.request, "urlopen", fake_urlopen)
    propose = ai_backends.get_backend("ollama")
    with pytest.raises(ai_assist.AIAgentError) as ei:
        propose("prompt", 5)
    assert "unreachable" in str(ei.value)


def test_broken_ollama_surfaces_failed_status_not_silent_empty(monkeypatch, tmp_path):
    """Through the real ai_tier.apply seam a broken ollama backend yields ai_status='failed' with a visible
    reason — NOT ai_status='ok' with zero surfaces (the silent-zero antipattern)."""
    (tmp_path / "agent_app.py").write_text(_NOVEL_SRC)

    def fake_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 500, "boom", {}, io.BytesIO(b""))

    monkeypatch.setattr(ai_backends.urllib.request, "urlopen", fake_urlopen)
    agent = ai_backends.get_backend("ollama")
    out = ai_tier.apply(tmp_path, [], budget=5, agent=agent, cache_path=tmp_path / "cache.json")

    assert out["ai_status"] == "failed"
    assert out["ai_surfaces_added"] == 0
    assert "ai_failure" in out and "HTTP 500" in out["ai_failure"]


# =====================================================================================================
# (f) ZERO-EGRESS HOST GUARD — a non-loopback HERMES_SHIELD_OLLAMA_HOST is refused unless the operator
#     EXPLICITLY opts in. The redacted prompt still carries the file source, so an off-box host = code egress.
# =====================================================================================================
@pytest.mark.parametrize("bad_host", [
    "http://attacker.example.com",
    "http://10.0.0.5:11434",
    "https://evil.tld",
    "http://169.254.169.254",          # cloud metadata endpoint — must NOT be reachable by default
])
def test_ollama_remote_host_refused_by_default(monkeypatch, bad_host):
    """A poisoned HERMES_SHIELD_OLLAMA_HOST pointing off-box fails LOUD at backend construction — the
    (redacted) file source is never sent to a non-loopback host without an explicit opt-in."""
    monkeypatch.setenv("HERMES_SHIELD_OLLAMA_HOST", bad_host)
    monkeypatch.delenv("HERMES_SHIELD_OLLAMA_ALLOW_REMOTE", raising=False)
    with pytest.raises(ai_assist.AIAgentError) as ei:
        ai_backends.get_backend("ollama")
    assert "not loopback" in str(ei.value)


@pytest.mark.parametrize("good_host", [
    "http://localhost:11434",
    "http://127.0.0.1:11434",
    "http://127.5.6.7:11434",          # anywhere in 127.0.0.0/8 is loopback
    "http://[::1]:11434",
])
def test_ollama_loopback_host_allowed(monkeypatch, good_host):
    """Loopback hosts are accepted with no opt-in flag — the default local/zero-egress path is unbroken."""
    monkeypatch.setenv("HERMES_SHIELD_OLLAMA_HOST", good_host)
    monkeypatch.delenv("HERMES_SHIELD_OLLAMA_ALLOW_REMOTE", raising=False)
    assert callable(ai_backends.get_backend("ollama"))          # constructs without raising


def test_ollama_remote_host_allowed_with_explicit_optin(monkeypatch):
    """An operator can deliberately allow a remote ollama host via HERMES_SHIELD_OLLAMA_ALLOW_REMOTE=1."""
    monkeypatch.setenv("HERMES_SHIELD_OLLAMA_HOST", "http://10.0.0.5:11434")
    monkeypatch.setenv("HERMES_SHIELD_OLLAMA_ALLOW_REMOTE", "1")
    assert callable(ai_backends.get_backend("ollama"))          # opt-in honoured, no raise


# =====================================================================================================
# (g) SILENT-EMPTY KILL — a 200 body lacking "response" (or carrying an "error") FAILS LOUD, never "".
# =====================================================================================================
def test_ollama_200_missing_response_field_raises(monkeypatch):
    """A 200 JSON body with no 'response' key (e.g. a proxy interposing) must raise, not return "" — the
    exact silent-empty masquerade the module claims to kill."""
    def fake_urlopen(req, timeout=None):
        return _FakeResp(json.dumps({"done": True}))            # no "response"
    monkeypatch.setattr(ai_backends.urllib.request, "urlopen", fake_urlopen)
    propose = ai_backends.get_backend("ollama")
    with pytest.raises(ai_assist.AIAgentError) as ei:
        propose("prompt", 5)
    assert "no 'response' field" in str(ei.value)


def test_ollama_200_error_body_raises(monkeypatch):
    """A 200 body carrying an 'error' (e.g. {"error":"model not found"}) fails loud instead of reporting
    a clean zero."""
    def fake_urlopen(req, timeout=None):
        return _FakeResp(json.dumps({"error": "model not found"}))
    monkeypatch.setattr(ai_backends.urllib.request, "urlopen", fake_urlopen)
    propose = ai_backends.get_backend("ollama")
    with pytest.raises(ai_assist.AIAgentError) as ei:
        propose("prompt", 5)
    assert "model not found" in str(ei.value)


def test_ollama_200_nonobject_body_raises(monkeypatch):
    """A 200 body that is a JSON array/scalar (not an object) fails loud rather than AttributeError-ing."""
    def fake_urlopen(req, timeout=None):
        return _FakeResp(json.dumps([1, 2, 3]))
    monkeypatch.setattr(ai_backends.urllib.request, "urlopen", fake_urlopen)
    propose = ai_backends.get_backend("ollama")
    with pytest.raises(ai_assist.AIAgentError) as ei:
        propose("prompt", 5)
    assert "non-object JSON body" in str(ei.value)


def test_ollama_genuine_empty_response_is_preserved(monkeypatch):
    """A PRESENT but empty 'response' is a real, non-error zero — it returns "" (not raised). This keeps the
    honest 'AI ran and genuinely found nothing' path intact while killing the missing-field masquerade."""
    def fake_urlopen(req, timeout=None):
        return _FakeResp(json.dumps({"response": ""}))
    monkeypatch.setattr(ai_backends.urllib.request, "urlopen", fake_urlopen)
    propose = ai_backends.get_backend("ollama")
    assert propose("prompt", 5) == ""


# =====================================================================================================
# (h) CACHE PROVENANCE — the AI cache key includes the backend id, so a claude-warmed cache can NEVER
#     silently replay for a (broken/absent) ollama run as ai_status="ok" with ai_calls=0.
# =====================================================================================================
def test_cache_is_not_shared_across_backends(monkeypatch, tmp_path):
    """A cache entry written under backend 'claude' must not be replayed under backend 'ollama'. With no
    ollama daemon reachable, the ollama run must make a REAL call (and here fail loud) — never replay
    claude's cached findings and report a clean zero."""
    (tmp_path / "agent_app.py").write_text(_NOVEL_SRC)
    cache_path = tmp_path / "cache.json"

    # 1) warm the cache with a claude-backed run that "finds" the novel surface.
    class _Proc:
        returncode = 0
        stdout = json.dumps([{"line": 9, "call": "client.deliver(payload)", "capability": "send",
                              "why": "novel", "confidence": 0.7}])
        stderr = ""

    monkeypatch.setattr(ai_assist.shutil, "which", lambda name: "/usr/bin/claude")
    monkeypatch.setattr(ai_assist.subprocess, "run", lambda cmd, **kw: _Proc())
    warm = ai_tier.apply(tmp_path, [], budget=5, agent=ai_backends.get_backend("claude"),
                         cache_path=cache_path, backend_id="claude")
    assert warm["ai_status"] == "ok" and warm["ai_calls"] == 1 and warm["ai_surfaces_added"] == 1

    # 2) a subsequent ollama run (broken daemon: refused connection) must NOT replay claude's cache.
    def fake_urlopen(req, timeout=None):
        raise urllib.error.URLError("Connection refused")
    monkeypatch.setattr(ai_backends.urllib.request, "urlopen", fake_urlopen)
    out = ai_tier.apply(tmp_path, [], budget=5, agent=ai_backends.get_backend("ollama"),
                        cache_path=cache_path, backend_id="ollama")
    # cross-backend replay would have yielded ai_status="ok", ai_calls=0, 1 surface. Provenance isolation
    # forces a real (failed) call instead — a broken backend can never masquerade as a clean cached zero.
    assert out["ai_status"] == "failed"
    assert out["ai_surfaces_added"] == 0
