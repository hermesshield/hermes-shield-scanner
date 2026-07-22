"""Loop 5 (multi-model) — USER-KEY cloud backends: anthropic / openai / venice / gemini.

EGRESS-CRITICAL suite. Every test runs against a MONKEYPATCHED urllib.request.urlopen — no test makes a
real network call and no test needs a real key (all key values below are SYNTHETIC).

What is locked here, per backend:
  (1) WIRE SHAPE — the hard-coded HTTPS endpoint, the auth header (x-api-key + anthropic-version for
      Anthropic; Authorization: Bearer for the OpenAI-compatible trio), and the request body shape.
  (2) HAPPY PATH — a genuine text field comes back verbatim.
  (3) FAIL-LOUD — a non-200, a 200-with-error-body, a 200 MISSING the text field, an EMPTY choices list,
      a TRUNCATED reply (finish_reason=length / stop_reason=max_tokens), an anthropic refusal, and a
      MISSING key env must all raise AIAgentError. None of them may return "" — a broken/hijacked cloud
      call must never masquerade as 'AI ran and found nothing'.
  (4) REDACTION INHERITANCE — the prompt that reaches the wire is the _redact_secrets-processed one:
      a planted secret NEVER appears in the outbound payload; the [REDACTED:*] marker does.
  (5) KEY HYGIENE — the API key travels ONLY in request headers, never in the JSON body.
"""
from __future__ import annotations

import io
import json
import urllib.error

import pytest

from hermes_shield import ai_assist, ai_backends

_GHP = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"          # 36-char synthetic github token

_SECRET_SRC = (
    "import subprocess\n"
    f'TOKEN = "{_GHP}"\n'
    "def run(cmd):\n"
    "    subprocess.run(cmd, shell=True)\n"
)

# (backend_id, key_env, synthetic_key, expected_url)
_ANTHROPIC = ("anthropic", "ANTHROPIC_API_KEY", "synthetic-anthropic-key-000",
              "https://api.anthropic.com/v1/messages")
_OPENAI_COMPAT = [
    ("openai", "OPENAI_API_KEY", "synthetic-openai-key-000",
     "https://api.openai.com/v1/chat/completions"),
    ("venice", "VENICE_API_KEY", "synthetic-venice-key-000",
     "https://api.venice.ai/api/v1/chat/completions"),
    ("gemini", "GEMINI_API_KEY", "synthetic-gemini-key-000",
     "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"),
]
_ALL = [_ANTHROPIC] + _OPENAI_COMPAT

_OPENAI_OK_BODY = {"choices": [{"message": {"content": "[]"}, "finish_reason": "stop"}]}
_ANTHROPIC_OK_BODY = {"type": "message", "stop_reason": "end_turn",
                      "content": [{"type": "text", "text": "[]"}]}


class _FakeResp:
    """Minimal urlopen()-compatible response usable as a context manager."""
    def __init__(self, body, status: int = 200):
        self._body = (body if isinstance(body, str) else json.dumps(body)).encode("utf-8")
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def getcode(self):
        return self.status

    def read(self):
        return self._body


def _arm(monkeypatch, backend_id, key_env, key):
    """Set ONLY this backend's synthetic key (and clear the others, so a stray real key in the
    developer's environment can never be picked up by a test)."""
    for _, env, _k, _u in _ALL:
        monkeypatch.delenv(env, raising=False)
    monkeypatch.setenv(key_env, key)


def _capture(monkeypatch, reply_body):
    """Monkeypatch urlopen to capture the outgoing Request and return `reply_body`."""
    seen = {}

    def fake_urlopen(req, timeout=None):
        seen["url"] = req.full_url
        seen["method"] = req.get_method()
        seen["headers"] = {k.lower(): v for k, v in req.headers.items()}
        seen["payload"] = json.loads(req.data.decode("utf-8"))
        seen["timeout"] = timeout
        return _FakeResp(reply_body)

    monkeypatch.setattr(ai_backends.urllib.request, "urlopen", fake_urlopen)
    return seen


# =====================================================================================================
# (1) + (2) WIRE SHAPE + HAPPY PATH
# =====================================================================================================
def test_anthropic_endpoint_auth_body_and_happy_path(monkeypatch):
    bid, env, key, url = _ANTHROPIC
    _arm(monkeypatch, bid, env, key)
    seen = _capture(monkeypatch, _ANTHROPIC_OK_BODY)
    propose = ai_backends.get_backend("anthropic")

    assert propose("PROMPT", 30) == "[]"
    assert seen["url"] == url and seen["url"].startswith("https://")
    assert seen["method"] == "POST"
    assert seen["headers"]["x-api-key"] == key
    assert seen["headers"]["anthropic-version"] == "2023-06-01"
    assert seen["headers"]["content-type"] == "application/json"
    p = seen["payload"]
    assert p["messages"] == [{"role": "user", "content": "PROMPT"}]
    assert isinstance(p["max_tokens"], int) and p["max_tokens"] > 0
    assert p["model"]                                            # a concrete model id is always sent
    assert seen["timeout"] == 30


def test_anthropic_multiple_text_blocks_are_joined(monkeypatch):
    bid, env, key, url = _ANTHROPIC
    _arm(monkeypatch, bid, env, key)
    _capture(monkeypatch, {"type": "message", "stop_reason": "end_turn",
                           "content": [{"type": "text", "text": "["},
                                       {"type": "text", "text": "]"}]})
    assert ai_backends.get_backend("anthropic")("p", 5) == "[]"


@pytest.mark.parametrize("bid,env,key,url", _OPENAI_COMPAT)
def test_openai_compat_endpoint_auth_body_and_happy_path(monkeypatch, bid, env, key, url):
    _arm(monkeypatch, bid, env, key)
    seen = _capture(monkeypatch, _OPENAI_OK_BODY)
    propose = ai_backends.get_backend(bid)

    assert propose("PROMPT", 45) == "[]"
    assert seen["url"] == url and seen["url"].startswith("https://")
    assert seen["method"] == "POST"
    assert seen["headers"]["authorization"] == f"Bearer {key}"
    assert seen["headers"]["content-type"] == "application/json"
    assert seen["payload"]["messages"] == [{"role": "user", "content": "PROMPT"}]
    assert seen["payload"]["model"]
    assert seen["timeout"] == 45


def test_model_env_override_is_honoured(monkeypatch):
    bid, env, key, url = _OPENAI_COMPAT[0]
    _arm(monkeypatch, bid, env, key)
    monkeypatch.setenv("HERMES_SHIELD_OPENAI_MODEL", "gpt-test-model")
    seen = _capture(monkeypatch, _OPENAI_OK_BODY)
    ai_backends.get_backend("openai")("p", 5)
    assert seen["payload"]["model"] == "gpt-test-model"


def test_explicit_model_arg_beats_env(monkeypatch):
    bid, env, key, url = _ANTHROPIC
    _arm(monkeypatch, bid, env, key)
    monkeypatch.setenv("HERMES_SHIELD_ANTHROPIC_MODEL", "env-model")
    seen = _capture(monkeypatch, _ANTHROPIC_OK_BODY)
    ai_backends.get_backend("anthropic", model="arg-model")("p", 5)
    assert seen["payload"]["model"] == "arg-model"


def test_genuine_empty_content_string_is_preserved(monkeypatch):
    """A PRESENT but empty text field is a real, non-error zero — it returns "" (not raised)."""
    bid, env, key, url = _OPENAI_COMPAT[0]
    _arm(monkeypatch, bid, env, key)
    _capture(monkeypatch, {"choices": [{"message": {"content": ""}, "finish_reason": "stop"}]})
    assert ai_backends.get_backend("openai")("p", 5) == ""


# =====================================================================================================
# (3) FAIL-LOUD — missing key, non-200, error body, missing text field, empty choices, truncation
# =====================================================================================================
@pytest.mark.parametrize("bid,env,key,url", _ALL)
def test_missing_key_env_fails_loud_at_construction(monkeypatch, bid, env, key, url):
    """No key => AIAgentError at get_backend() time, with an actionable 'set X_API_KEY' message.
    Nothing is sent anywhere (urlopen is armed to explode if touched)."""
    for _, e, _k, _u in _ALL:
        monkeypatch.delenv(e, raising=False)

    def explode(*a, **kw):                                     # any egress attempt = test failure
        raise AssertionError("urlopen must not be called when the key is missing")
    monkeypatch.setattr(ai_backends.urllib.request, "urlopen", explode)

    with pytest.raises(ai_assist.AIAgentError) as ei:
        ai_backends.get_backend(bid)
    assert f"set {env}" in str(ei.value)


def test_empty_key_env_fails_loud(monkeypatch):
    """An empty/whitespace key env is a MISSING key, not a usable one."""
    bid, env, key, url = _ANTHROPIC
    _arm(monkeypatch, bid, env, "   ")
    with pytest.raises(ai_assist.AIAgentError) as ei:
        ai_backends.get_backend("anthropic")
    assert f"set {env}" in str(ei.value)


@pytest.mark.parametrize("bid,env,key,url", _ALL)
def test_non_200_fails_loud_with_provider_detail(monkeypatch, bid, env, key, url):
    _arm(monkeypatch, bid, env, key)

    def fake_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {},
                                     io.BytesIO(b'{"error":{"message":"invalid api key"}}'))
    monkeypatch.setattr(ai_backends.urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(ai_assist.AIAgentError) as ei:
        ai_backends.get_backend(bid)("p", 5)
    msg = str(ei.value)
    assert "HTTP 401" in msg and "invalid api key" in msg


@pytest.mark.parametrize("bid,env,key,url", _ALL)
def test_connection_refused_fails_loud(monkeypatch, bid, env, key, url):
    _arm(monkeypatch, bid, env, key)

    def fake_urlopen(req, timeout=None):
        raise urllib.error.URLError("Connection refused")
    monkeypatch.setattr(ai_backends.urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(ai_assist.AIAgentError) as ei:
        ai_backends.get_backend(bid)("p", 5)
    assert "unreachable" in str(ei.value)


@pytest.mark.parametrize("bid,env,key,url", _ALL)
def test_200_with_error_body_fails_loud(monkeypatch, bid, env, key, url):
    """A proxy-injected {"error": ...} under HTTP 200 must fail loud, never read as a clean zero."""
    _arm(monkeypatch, bid, env, key)
    _capture(monkeypatch, {"error": {"message": "model overloaded"}})
    with pytest.raises(ai_assist.AIAgentError) as ei:
        ai_backends.get_backend(bid)("p", 5)
    assert "model overloaded" in str(ei.value)


@pytest.mark.parametrize("bid,env,key,url", _ALL)
def test_200_missing_text_field_fails_loud(monkeypatch, bid, env, key, url):
    """A 200 body missing the expected text field entirely (choices / content) must raise."""
    _arm(monkeypatch, bid, env, key)
    _capture(monkeypatch, {"some": "other", "shape": True})
    with pytest.raises(ai_assist.AIAgentError) as ei:
        ai_backends.get_backend(bid)("p", 5)
    assert "silent empty" in str(ei.value)


@pytest.mark.parametrize("bid,env,key,url", _ALL)
def test_200_non_object_body_fails_loud(monkeypatch, bid, env, key, url):
    _arm(monkeypatch, bid, env, key)
    _capture(monkeypatch, json.dumps([1, 2, 3]))
    with pytest.raises(ai_assist.AIAgentError) as ei:
        ai_backends.get_backend(bid)("p", 5)
    assert "non-object JSON body" in str(ei.value)


@pytest.mark.parametrize("bid,env,key,url", _OPENAI_COMPAT)
def test_200_with_no_choices_fails_loud(monkeypatch, bid, env, key, url):
    """The exact '200-with-no-choices' masquerade: choices present but EMPTY must raise."""
    _arm(monkeypatch, bid, env, key)
    _capture(monkeypatch, {"choices": []})
    with pytest.raises(ai_assist.AIAgentError) as ei:
        ai_backends.get_backend(bid)("p", 5)
    assert "choices" in str(ei.value)


@pytest.mark.parametrize("bid,env,key,url", _OPENAI_COMPAT)
def test_null_message_content_fails_loud(monkeypatch, bid, env, key, url):
    """content: null (e.g. a tool-calls-only reply) is present-but-not-text — must raise, not str(None)."""
    _arm(monkeypatch, bid, env, key)
    _capture(monkeypatch, {"choices": [{"message": {"content": None}, "finish_reason": "stop"}]})
    with pytest.raises(ai_assist.AIAgentError) as ei:
        ai_backends.get_backend(bid)("p", 5)
    assert "not text" in str(ei.value)


@pytest.mark.parametrize("bid,env,key,url", _OPENAI_COMPAT)
def test_length_truncation_fails_loud(monkeypatch, bid, env, key, url):
    """finish_reason=length => the findings array may be cut mid-JSON; _parse_json would read that as []
    — a silent under-report. Truncation must therefore raise."""
    _arm(monkeypatch, bid, env, key)
    _capture(monkeypatch, {"choices": [{"message": {"content": '[{"line": 3,'},
                                        "finish_reason": "length"}]})
    with pytest.raises(ai_assist.AIAgentError) as ei:
        ai_backends.get_backend(bid)("p", 5)
    assert "TRUNCATED" in str(ei.value)


def test_anthropic_max_tokens_truncation_fails_loud(monkeypatch):
    bid, env, key, url = _ANTHROPIC
    _arm(monkeypatch, bid, env, key)
    _capture(monkeypatch, {"type": "message", "stop_reason": "max_tokens",
                           "content": [{"type": "text", "text": '[{"line": 3,'}]})
    with pytest.raises(ai_assist.AIAgentError) as ei:
        ai_backends.get_backend("anthropic")("p", 5)
    assert "TRUNCATED" in str(ei.value)


def test_anthropic_refusal_fails_loud(monkeypatch):
    """stop_reason=refusal: 'backend refused' and 'ran and found nothing' are different truths."""
    bid, env, key, url = _ANTHROPIC
    _arm(monkeypatch, bid, env, key)
    _capture(monkeypatch, {"type": "message", "stop_reason": "refusal", "content": []})
    with pytest.raises(ai_assist.AIAgentError) as ei:
        ai_backends.get_backend("anthropic")("p", 5)
    assert "REFUSED" in str(ei.value)


def test_anthropic_no_text_blocks_fails_loud(monkeypatch):
    """A content list with no text-type blocks (or an empty content list) has no text field to trust."""
    bid, env, key, url = _ANTHROPIC
    _arm(monkeypatch, bid, env, key)
    _capture(monkeypatch, {"type": "message", "stop_reason": "end_turn",
                           "content": [{"type": "tool_use", "name": "x", "input": {}}]})
    with pytest.raises(ai_assist.AIAgentError) as ei:
        ai_backends.get_backend("anthropic")("p", 5)
    assert "no text blocks" in str(ei.value)


def test_anthropic_error_envelope_fails_loud(monkeypatch):
    """The documented Anthropic error envelope {"type":"error","error":{...}} must raise."""
    bid, env, key, url = _ANTHROPIC
    _arm(monkeypatch, bid, env, key)
    _capture(monkeypatch, {"type": "error",
                           "error": {"type": "overloaded_error", "message": "Overloaded"}})
    with pytest.raises(ai_assist.AIAgentError) as ei:
        ai_backends.get_backend("anthropic")("p", 5)
    assert "Overloaded" in str(ei.value)


# =====================================================================================================
# (4) REDACTION INHERITANCE — the wire prompt is the redacted one, for EVERY cloud backend
# =====================================================================================================
@pytest.mark.parametrize("bid,env,key,url", _ALL)
def test_prompt_on_the_wire_is_redacted(monkeypatch, bid, env, key, url):
    """analyze_source -> propose(): the outbound payload carries the _redact_secrets-processed prompt.
    The planted secret must NEVER reach a cloud provider; the [REDACTED:*] marker must."""
    _arm(monkeypatch, bid, env, key)
    ok_body = _ANTHROPIC_OK_BODY if bid == "anthropic" else _OPENAI_OK_BODY
    seen = _capture(monkeypatch, ok_body)

    ai_assist.analyze_source(_SECRET_SRC, agent=ai_backends.get_backend(bid))

    wire_prompt = seen["payload"]["messages"][0]["content"]
    assert _GHP not in wire_prompt, f"raw secret leaked to the {bid} backend"
    assert "[REDACTED:github-token]" in wire_prompt
    # the untrusted-data fence + size-cap path also ran (the prompt is the full HS-03 pipeline output)
    assert "UNTRUSTED CODE" in wire_prompt


# =====================================================================================================
# (5) KEY HYGIENE — the key travels in headers ONLY, never in the JSON body
# =====================================================================================================
@pytest.mark.parametrize("bid,env,key,url", _ALL)
def test_api_key_never_in_request_body(monkeypatch, bid, env, key, url):
    _arm(monkeypatch, bid, env, key)
    ok_body = _ANTHROPIC_OK_BODY if bid == "anthropic" else _OPENAI_OK_BODY
    seen = _capture(monkeypatch, ok_body)
    ai_backends.get_backend(bid)("p", 5)
    assert key not in json.dumps(seen["payload"])
