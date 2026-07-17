"""
entrypoints.py (S8.42) — detect REAL untrusted entrypoints, so taint is grounded in where untrusted input
ACTUALLY enters, not in a suggestively-named parameter. This is the fix that makes "reachable" trustworthy:
a sink is reachable-unguarded only if a real entrypoint's untrusted value reaches it.

Sound-leaning: unsure -> NOT an entrypoint (under-report, never over-mark). Two detected classes here (HTTP
route handlers + event/webhook handlers); agent-content reads and explicit source calls (req.body, LLM output,
store rows) are already grounded intrinsically in taint._is_source_call and are NOT re-detected here.
"""
from __future__ import annotations

# HTTP route decorator verbs: @app.post(...), @router.get(...), @app.route(...), @app.websocket(...)
_HTTP_VERBS = {"get", "post", "put", "delete", "patch", "route", "websocket", "api_route"}
# event/message/webhook callbacks — the ENTRY CONTRACT (name/decorator), far safer than a bare param name.
_EVENT_NAMES = {"on_message", "on_event", "on_update", "consume", "webhook", "handle_webhook",
                "process_message", "handle_event", "handle_update", "on_webhook"}
_EVENT_PREFIXES = ("handle_", "on_")
_EVENT_DECOS = {"on", "on_event", "event", "message", "webhook"}   # @bot.on, @app.on_event, @client.event
# `command` is AMBIGUOUS: @bot.command (chatbot handler, UNTRUSTED) vs @app.command / @click.command
# (operator CLI verb, developer-controlled, TRUSTED). Seed it as untrusted ONLY when it is NOT a Typer/Click
# CLI verb (call_graph._is_cli_command). This REMOVES the julep-style CLI false-reachable (and any static
# baseline surface mis-seeded the same way) while keeping genuine bot command handlers untrusted. S8.84.
_BOT_COMMAND_DECOS = {"command"}


def _deco_matches(decorators, tails: set) -> bool:
    for dec in decorators:
        if (dec or "").split(".")[-1] in tails:
            return True
    return False


def _untrusted_params(params):
    """params = [(name, has_depends)]. Untrusted = all except self/cls and Depends()/Security() injections."""
    out = []
    for name, has_dep in params:
        if name in ("self", "cls") or has_dep:
            continue
        out.append(name)
    return out


def detect_entrypoints(graphs: dict) -> dict:
    """graphs = {rel_path: FileGraph}. Returns {(rel, fn_name): {"type", "untrusted_params", "evidence"}}."""
    registry = {}
    for rel, g in graphs.items():
        if not getattr(g, "ok", False):
            continue
        for fn, info in g.funcs.items():
            decos = info.get("decorators", [])
            params = info.get("params", [])
            etype = evidence = None
            # (a) HTTP route handler — decorator verb
            if _deco_matches(decos, _HTTP_VERBS):
                etype, evidence = "http_route", "route decorator"
            # (b) event/message/webhook handler — name or decorator
            elif fn in _EVENT_NAMES or fn.startswith(_EVENT_PREFIXES) or _deco_matches(decos, _EVENT_DECOS):
                etype, evidence = "event_handler", "callback name/decorator"
            # (c) `@bot.command` chatbot handler — UNTRUSTED, but NOT a Typer/Click operator CLI verb (S8.84).
            elif _deco_matches(decos, _BOT_COMMAND_DECOS) and not info.get("cli_command"):
                etype, evidence = "event_handler", "bot command handler"
            if etype:
                up = _untrusted_params(params)
                if up:                                    # no untrusted params -> not a useful source
                    registry[(rel, fn)] = {"type": etype, "untrusted_params": set(up), "evidence": evidence}
    return registry
