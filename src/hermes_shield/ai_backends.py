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
- "anthropic" / "openai" / "venice" are declared here as the pluggable interface but are NOT wired this slice
  — they raise a clearly-marked NotImplemented AIAgentError. No hosted egress is added in this slice.

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

# The ids this registry knows. "claude" + "ollama" are wired this slice; the rest are declared stubs.
KNOWN_BACKENDS = ("claude", "ollama", "anthropic", "openai", "venice")
WIRED_BACKENDS = ("claude", "ollama")

_OLLAMA_DEFAULT_HOST = "http://localhost:11434"
_OLLAMA_DEFAULT_MODEL = "llama3.1"

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


def _stub_backend(backend_id: str):
    """Declared-but-not-wired backend. Defines the interface (propose(prompt, timeout)->str) so the id is
    pluggable, but raises immediately — no hosted egress is added in this slice. When wired later, replace
    this with a real client that goes through the SAME redacted-prompt seam."""
    def _propose(prompt: str, timeout: int) -> str:
        raise ai_assist.AIAgentError(f"{backend_id} backend not yet wired")
    return _propose


def get_backend(backend_id: str | None = None, model: str | None = None):
    """Resolve a backend id -> propose(prompt, timeout) -> raw_text callable.

    - None / "" / "claude": the historical default. Returns ai_assist.claude_agent(model) VERBATIM so an
      unset selection is byte-identical to today's behaviour.
    - "ollama": local zero-egress Ollama backend (fail-loud).
    - "anthropic" / "openai" / "venice": declared interface, NotImplemented stub (raises on use).
    - any other id: AIAgentError (unknown backend) — fail-loud, never a silent fallback that would hide a
      typo behind the default backend."""
    bid = (backend_id or "claude").strip().lower()
    if bid == "claude":
        return ai_assist.claude_agent(model)
    if bid == "ollama":
        return _ollama_agent(model)
    if bid in ("anthropic", "openai", "venice"):
        return _stub_backend(bid)
    raise ai_assist.AIAgentError(
        f"unknown AI backend '{backend_id}' (known: {', '.join(KNOWN_BACKENDS)})")
