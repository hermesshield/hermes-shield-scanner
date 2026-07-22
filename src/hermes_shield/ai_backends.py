"""
Hermes Shield — AI backend REGISTRY (first slice of the shared AI backend layer).

One job: map a backend id -> a `propose(prompt, timeout) -> raw_text` callable, the exact seam
`ai_assist.analyze_source(..., agent=)` / `ai_tier.apply(..., agent=)` already accept. Everything the AI
tier sends is redacted (`_redact_secrets`) and size-capped (`_cap_ai_source`) INSIDE analyze_source BEFORE
the prompt reaches this backend, so any backend plugged in through that seam is protected for free — this
module never sees raw source, only the already-redacted prompt string.

DISCIPLINE:
- "claude" reuses `ai_assist.claude_agent` VERBATIM — the historical default. With no backend selected the
  scan must be byte-identical to today, so get_backend("claude") returns exactly that callable.
- "ollama" is LOCAL / zero-egress (POST to localhost Ollama). FAIL-LOUD: any non-200 / timeout / refused
  connection raises `ai_assist.AIAgentError` — never a silent "" (the antipattern AIAgentError exists to kill:
  a broken tier that looks like "AI ran and found nothing").
- "anthropic" / "openai" / "venice" / "gemini" are USER-KEY cloud backends (Loop 5, multi-model). Each one
  sends the ALREADY-REDACTED prompt to that provider over HTTPS under the USER'S OWN key, read from the
  provider's standard env var (ANTHROPIC_API_KEY / OPENAI_API_KEY / VENICE_API_KEY / GEMINI_API_KEY) at
  backend-construction time and NEVER stored, logged, or shipped in the package. A missing key FAILS LOUD
  ("set X_API_KEY") — never a silent skip. Endpoints are HARD-CODED HTTPS (no env-overridable base URL: an
  overridable egress destination is the exact poisoning vector the ollama loopback guard exists to kill).
  Same fail-loud extraction discipline as ollama: non-200, error body, MISSING text field, empty choices,
  or a truncated reply (finish_reason=length / stop_reason=max_tokens — a cut-off JSON array would parse
  as [] and masquerade as a clean zero) all raise AIAgentError. Only a genuinely-present text field (even
  "") passes.

This is the PER-FILE ai_assist tier only, now backend-selectable. Advisory-only invariant unchanged: AI
surfaces stay ai_suspected / AI_SUSPECTED_REVIEW; the deterministic headline is untouched.
"""
from __future__ import annotations

import ipaddress
import json
import os
import urllib.error
import urllib.request
from urllib.parse import urlparse

from . import ai_assist

# The ids this registry knows. ALL are wired: claude (local CLI), ollama (local daemon), and four
# user-key cloud providers (anthropic / openai / venice / gemini).
KNOWN_BACKENDS = ("claude", "ollama", "anthropic", "openai", "venice", "gemini")
WIRED_BACKENDS = ("claude", "ollama", "anthropic", "openai", "venice", "gemini")

_OLLAMA_DEFAULT_HOST = "http://localhost:11434"
_OLLAMA_DEFAULT_MODEL = "llama3.1"

# --- Cloud backends (Loop 5): HARD-CODED HTTPS endpoints. Deliberately NOT env-overridable — a poisoned
# base-URL env var would redirect the (redacted) source code to an attacker host, the exact egress vector
# the ollama loopback guard blocks. Models ARE overridable (they don't change where bytes go).
_ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VERSION = "2023-06-01"
_ANTHROPIC_DEFAULT_MODEL = "claude-opus-4-8"
_ANTHROPIC_DEFAULT_MAX_TOKENS = 8192   # reply is a bounded JSON findings array; env-overridable below
_OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
_OPENAI_DEFAULT_MODEL = "gpt-4o-mini"
_VENICE_API_URL = "https://api.venice.ai/api/v1/chat/completions"
_VENICE_DEFAULT_MODEL = "llama-3.3-70b"
# Gemini is wired through its OpenAI-compatible chat/completions surface — the SAME request/extraction
# code path as openai/venice, so no bespoke (and bespoke-buggy) response parsing.
_GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
_GEMINI_DEFAULT_MODEL = "gemini-2.5-flash"

_LOOPBACK_HOSTNAMES = {"localhost"}


def _is_loopback_host(host: str) -> bool:
    """True only when `host` (a URL like http://localhost:11434, or a bare host[:port]) targets the loopback
    interface. We deliberately DO NOT resolve DNS names — a name could resolve off-box (or be poisoned), so
    only a literal loopback target ('localhost', 127.0.0.0/8, ::1) is trusted; everything else is 'remote'."""
    parsed = urlparse(host if "://" in host else f"http://{host}")
    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        return False
    if hostname in _LOOPBACK_HOSTNAMES:
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _ollama_agent(model: str | None = None):
    """LOCAL, zero-egress Ollama backend. Returns propose(prompt, timeout) -> raw_text.

    Talks to a locally-running Ollama daemon over stdlib urllib (no third-party deps, no outbound egress
    beyond localhost). Host + model are operator-controlled via HERMES_SHIELD_OLLAMA_HOST /
    HERMES_SHIELD_OLLAMA_MODEL. `model` (if passed by ai_assist) wins over the env default.

    FAIL-LOUD: a non-200 response, a timeout, or a refused connection raises ai_assist.AIAgentError with a
    human-readable reason. It NEVER returns "" — a broken local model must surface as an ai_status=failed
    tier, not masquerade as "AI ran and found nothing" (the exact silent-zero bug AIAgentError kills)."""
    host = (os.getenv("HERMES_SHIELD_OLLAMA_HOST") or _OLLAMA_DEFAULT_HOST).rstrip("/")
    chosen_model = model or os.getenv("HERMES_SHIELD_OLLAMA_MODEL") or _OLLAMA_DEFAULT_MODEL
    # ZERO-EGRESS GUARD: the prompt is secret-redacted, but it still carries the ENTIRE (stripped) file
    # source. A poisoned HERMES_SHIELD_OLLAMA_HOST pointing off-box would exfiltrate proprietary code — the
    # exact opposite of the "LOCAL / zero-egress" contract. Only loopback is allowed unless the operator
    # EXPLICITLY opts in via HERMES_SHIELD_OLLAMA_ALLOW_REMOTE=1. Fail-loud (never a silent default fallback).
    if not _is_loopback_host(host) and os.getenv("HERMES_SHIELD_OLLAMA_ALLOW_REMOTE") != "1":
        raise ai_assist.AIAgentError(
            f"HERMES_SHIELD_OLLAMA_HOST '{host}' is not loopback; the ollama backend is LOCAL/zero-egress by "
            f"default and refuses to send the (redacted) file source off-box. Set "
            f"HERMES_SHIELD_OLLAMA_ALLOW_REMOTE=1 to explicitly allow a remote ollama host.")

    def _propose(prompt: str, timeout: int) -> str:
        url = f"{host}/api/generate"
        payload = json.dumps({"model": chosen_model, "prompt": prompt, "stream": False}).encode("utf-8")
        req = urllib.request.Request(url, data=payload, method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = getattr(resp, "status", None) or resp.getcode()
                if status != 200:
                    raise ai_assist.AIAgentError(f"ollama returned HTTP {status} from {url}")
                body = resp.read().decode("utf-8", errors="replace")
        except ai_assist.AIAgentError:
            raise
        except urllib.error.HTTPError as e:
            # a non-200 arrives here as HTTPError — surface the status LOUD, never swallow it.
            raise ai_assist.AIAgentError(f"ollama returned HTTP {e.code} from {url}")
        except urllib.error.URLError as e:
            # connection refused / DNS / timeout at the socket layer.
            raise ai_assist.AIAgentError(f"ollama unreachable at {url}: {e.reason}")
        except TimeoutError:
            raise ai_assist.AIAgentError(f"ollama timed out after {timeout}s at {url}")
        except Exception as e:
            raise ai_assist.AIAgentError(f"ollama request failed: {e.__class__.__name__}: {e}")
        try:
            data = json.loads(body)
        except Exception as e:
            raise ai_assist.AIAgentError(f"ollama returned non-JSON body: {e.__class__.__name__}: {e}")
        # Ollama's /api/generate puts the model text in "response"; downstream _parse_json extracts the
        # JSON array. A 200 body that LACKS "response" (or carries an "error", e.g. {"error":"model not
        # found"} injected by a proxy) is NOT a real zero — returning "" there is the silent-empty
        # masquerade this module exists to kill. FAIL-LOUD instead; only a present "response" (even an empty
        # string — a genuine, non-error zero) is allowed through.
        if not isinstance(data, dict):
            raise ai_assist.AIAgentError(
                f"ollama returned a non-object JSON body (type {type(data).__name__}) from {url}")
        if data.get("error"):
            raise ai_assist.AIAgentError(f"ollama returned an error from {url}: {data['error']}")
        if "response" not in data:
            raise ai_assist.AIAgentError(
                f"ollama JSON body from {url} has no 'response' field (keys: {sorted(data)[:8]}) — refusing "
                f"to report a silent empty result")
        return data.get("response") or ""

    return _propose


def _require_key(env_name: str, backend_id: str) -> str:
    """USER-KEY discipline: the key comes from the user's environment at construction time, is held only in
    the returned closure for the lifetime of the scan, and is NEVER stored, logged, echoed in errors, or
    shipped in the package. A missing/empty key FAILS LOUD with an actionable message — a silent skip here
    would report 'AI ran and found nothing' for a tier that never ran (the exact false-assurance class this
    module exists to kill)."""
    key = (os.getenv(env_name) or "").strip()
    if not key:
        raise ai_assist.AIAgentError(
            f"the '{backend_id}' backend needs YOUR API key: set {env_name} in your environment. "
            f"hermes-shield never ships or stores a key — the (secret-redacted) code is sent to "
            f"{backend_id} under your own account.")
    return key


def _post_json(url: str, payload: dict, headers: dict, timeout: int, provider: str) -> dict:
    """Shared fail-loud HTTPS POST -> parsed JSON object, replicating the ollama transport discipline
    exactly: non-200 (direct or via HTTPError), refused/DNS/timeout, non-JSON body, and non-object JSON all
    raise AIAgentError with a human-readable reason — NEVER a silent ''. On an HTTPError the first bytes of
    the provider's error body are included (auth errors like 'invalid x-api-key' are actionable); the API
    key itself only ever travels in request headers, so it cannot appear in these messages."""
    body_headers = {"Content-Type": "application/json"}
    body_headers.update(headers)
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), method="POST",
                                 headers=body_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", None) or resp.getcode()
            if status != 200:
                raise ai_assist.AIAgentError(f"{provider} returned HTTP {status} from {url}")
            body = resp.read().decode("utf-8", errors="replace")
    except ai_assist.AIAgentError:
        raise
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = (e.read() or b"").decode("utf-8", errors="replace")[:200]
        except Exception:
            pass
        raise ai_assist.AIAgentError(
            f"{provider} returned HTTP {e.code} from {url}" + (f": {detail}" if detail.strip() else ""))
    except urllib.error.URLError as e:
        raise ai_assist.AIAgentError(f"{provider} unreachable at {url}: {e.reason}")
    except TimeoutError:
        raise ai_assist.AIAgentError(f"{provider} timed out after {timeout}s at {url}")
    except Exception as e:
        raise ai_assist.AIAgentError(f"{provider} request failed: {e.__class__.__name__}: {e}")
    try:
        data = json.loads(body)
    except Exception as e:
        raise ai_assist.AIAgentError(f"{provider} returned non-JSON body: {e.__class__.__name__}: {e}")
    if not isinstance(data, dict):
        raise ai_assist.AIAgentError(
            f"{provider} returned a non-object JSON body (type {type(data).__name__}) from {url}")
    return data


def _extract_openai_compat(data: dict, provider: str, url: str) -> str:
    """FAIL-LOUD extraction for the OpenAI-compatible chat/completions shape (openai / venice / gemini).
    A 200 body carrying an 'error', MISSING 'choices', an EMPTY choices list, a missing/None message
    content, or a length-truncated reply must all raise — each of those, passed through as '' or a partial
    string, would flow into _parse_json as [] and masquerade as 'AI ran and found nothing'. Only a
    genuinely-present string content (even '') passes."""
    if data.get("error"):
        err = data["error"]
        msg = err.get("message") if isinstance(err, dict) else err
        raise ai_assist.AIAgentError(f"{provider} returned an error from {url}: {msg}")
    if "choices" not in data:
        raise ai_assist.AIAgentError(
            f"{provider} JSON body from {url} has no 'choices' field (keys: {sorted(data)[:8]}) — "
            f"refusing to report a silent empty result")
    choices = data["choices"]
    if not isinstance(choices, list) or not choices:
        raise ai_assist.AIAgentError(
            f"{provider} returned a 200 with empty/invalid 'choices' from {url} — not a real zero; "
            f"refusing to report a silent empty result")
    first = choices[0]
    if not isinstance(first, dict):
        raise ai_assist.AIAgentError(f"{provider} returned a non-object choices[0] from {url}")
    if first.get("finish_reason") == "length":
        raise ai_assist.AIAgentError(
            f"{provider} reply was TRUNCATED (finish_reason=length) from {url} — a cut-off findings "
            f"array must not be parsed as a clean zero; raise the model's output limit")
    message = first.get("message")
    if not isinstance(message, dict) or "content" not in message:
        raise ai_assist.AIAgentError(
            f"{provider} choices[0] from {url} has no message.content — refusing to report a silent "
            f"empty result")
    content = message["content"]
    if not isinstance(content, str):
        raise ai_assist.AIAgentError(
            f"{provider} message.content from {url} is {type(content).__name__}, not text — refusing "
            f"to report a silent empty result")
    return content


def _extract_anthropic(data: dict, url: str) -> str:
    """FAIL-LOUD extraction for the Anthropic /v1/messages shape. An error envelope, a refusal, a
    max_tokens truncation, a missing/non-list 'content', or a content with NO text blocks all raise —
    never ''. Text blocks are joined; a present-but-empty text block is a genuine zero and passes."""
    if data.get("type") == "error" or data.get("error"):
        err = data.get("error")
        msg = err.get("message") if isinstance(err, dict) else err
        raise ai_assist.AIAgentError(f"anthropic returned an error from {url}: {msg}")
    stop = data.get("stop_reason")
    if stop == "refusal":
        raise ai_assist.AIAgentError(
            f"anthropic REFUSED the request (stop_reason=refusal) at {url} — 'backend refused' and "
            f"'ran and found nothing' are different truths; surfacing the refusal loud")
    if stop == "max_tokens":
        raise ai_assist.AIAgentError(
            f"anthropic reply was TRUNCATED (stop_reason=max_tokens) at {url} — a cut-off findings "
            f"array must not be parsed as a clean zero; raise HERMES_SHIELD_ANTHROPIC_MAX_TOKENS")
    if "content" not in data or not isinstance(data["content"], list):
        raise ai_assist.AIAgentError(
            f"anthropic JSON body from {url} has no 'content' list (keys: {sorted(data)[:8]}) — "
            f"refusing to report a silent empty result")
    texts = [b.get("text") for b in data["content"]
             if isinstance(b, dict) and b.get("type") == "text"]
    if not texts or not all(isinstance(t, str) for t in texts):
        raise ai_assist.AIAgentError(
            f"anthropic body from {url} contains no text blocks — refusing to report a silent empty "
            f"result")
    return "".join(texts)


def _anthropic_agent(model: str | None = None):
    """USER-KEY cloud backend: sends the (already-redacted) prompt to Anthropic's /v1/messages under
    ANTHROPIC_API_KEY. Model: `model` arg > HERMES_SHIELD_ANTHROPIC_MODEL > claude-opus-4-8. Fail-loud
    everywhere (see _post_json / _extract_anthropic); the key never leaves the request headers."""
    key = _require_key("ANTHROPIC_API_KEY", "anthropic")
    chosen_model = model or os.getenv("HERMES_SHIELD_ANTHROPIC_MODEL") or _ANTHROPIC_DEFAULT_MODEL
    try:
        max_tokens = int(os.getenv("HERMES_SHIELD_ANTHROPIC_MAX_TOKENS")
                         or _ANTHROPIC_DEFAULT_MAX_TOKENS)
    except ValueError:
        raise ai_assist.AIAgentError(
            "HERMES_SHIELD_ANTHROPIC_MAX_TOKENS is not an integer — refusing to guess")

    def _propose(prompt: str, timeout: int) -> str:
        payload = {"model": chosen_model, "max_tokens": max_tokens,
                   "messages": [{"role": "user", "content": prompt}]}
        headers = {"x-api-key": key, "anthropic-version": _ANTHROPIC_VERSION}
        return _extract_anthropic(
            _post_json(_ANTHROPIC_API_URL, payload, headers, timeout, "anthropic"),
            _ANTHROPIC_API_URL)

    return _propose


def _openai_compat_agent(backend_id: str, url: str, key_env: str, model_env: str, default_model: str,
                         model: str | None = None):
    """Shared USER-KEY factory for the OpenAI-compatible providers (openai / venice / gemini): Bearer-auth
    POST to a hard-coded HTTPS chat/completions endpoint, fail-loud transport + extraction. One code path,
    three providers — a fix to the discipline lands on all of them at once."""
    key = _require_key(key_env, backend_id)
    chosen_model = model or os.getenv(model_env) or default_model

    def _propose(prompt: str, timeout: int) -> str:
        payload = {"model": chosen_model,
                   "messages": [{"role": "user", "content": prompt}]}
        headers = {"Authorization": f"Bearer {key}"}
        return _extract_openai_compat(_post_json(url, payload, headers, timeout, backend_id),
                                      backend_id, url)

    return _propose


def get_backend(backend_id: str | None = None, model: str | None = None):
    """Resolve a backend id -> propose(prompt, timeout) -> raw_text callable.

    - None / "" / "claude": the historical default. Returns ai_assist.claude_agent(model) VERBATIM so an
      unset selection is byte-identical to today's behaviour.
    - "ollama": local zero-egress Ollama backend (fail-loud).
    - "anthropic" / "openai" / "venice" / "gemini": USER-KEY cloud backends — send the (redacted) prompt
      to that provider under the user's own key. A missing key env raises HERE, at construction, before
      any file is even read for the tier (fail-loud, never a silent skip).
    - any other id: AIAgentError (unknown backend) — fail-loud, never a silent fallback that would hide a
      typo behind the default backend."""
    bid = (backend_id or "claude").strip().lower()
    if bid == "claude":
        return ai_assist.claude_agent(model)
    if bid == "ollama":
        return _ollama_agent(model)
    if bid == "anthropic":
        return _anthropic_agent(model)
    if bid == "openai":
        return _openai_compat_agent("openai", _OPENAI_API_URL, "OPENAI_API_KEY",
                                    "HERMES_SHIELD_OPENAI_MODEL", _OPENAI_DEFAULT_MODEL, model)
    if bid == "venice":
        return _openai_compat_agent("venice", _VENICE_API_URL, "VENICE_API_KEY",
                                    "HERMES_SHIELD_VENICE_MODEL", _VENICE_DEFAULT_MODEL, model)
    if bid == "gemini":
        return _openai_compat_agent("gemini", _GEMINI_API_URL, "GEMINI_API_KEY",
                                    "HERMES_SHIELD_GEMINI_MODEL", _GEMINI_DEFAULT_MODEL, model)
    raise ai_assist.AIAgentError(
        f"unknown AI backend '{backend_id}' (known: {', '.join(KNOWN_BACKENDS)})")
