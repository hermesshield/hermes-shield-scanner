"""Tool implementations for the agent. Each tool takes the raw `arg` string
that arrived from the HTTP request body (see server.py) via the registry
dispatch in registry.py. Untrusted end-to-end.
"""
import os
import subprocess

from _aliases import _ex


def shell_tool(arg):
    # PLANTED S01 — literal subprocess.run behind a wrapper, reached via the
    # TOOLS registry dispatch. Static SHOULD catch this (literal dotted call).
    return subprocess.run(arg, shell=True, capture_output=True)


def py_tool(code):
    # PLANTED S02 — arbitrary code execution via the re-exported `_ex` (exec).
    # No literal exec( appears; the primitive is aliased in _aliases.py.
    return _ex(code)


def raw_tool(arg):
    # PLANTED S03 — os.<method> selected by an attacker-controlled verb, bound
    # via getattr into a local then invoked. e.g. arg = "system rm -rf /".
    verb, _, rest = arg.partition(" ")
    fn = getattr(os, verb)          # verb == "system"
    return fn(rest)


def echo_tool(arg):
    # DECOY D01 — benign: formats and returns text, no capability.
    return {"echo": str(arg).strip()}


class TextOps:
    """Benign text transforms — no capability of any kind."""

    def upper(self, s):
        return s.upper()

    def lower(self, s):
        return s.lower()

    def reverse(self, s):
        return s[::-1]


_TEXT = TextOps()


def text_tool(arg):
    # DECOY D08 — dynamic dispatch that RESOLVES TO A BENIGN target. Identical
    # getattr-assigned shape to raw_tool (S03) and admin do_op (S17), but the
    # receiver is a benign text-ops object, not `os`. A finder must resolve the
    # dispatch target and see there is no capability — it must NOT flag the
    # dispatch shape alone. Static already ignores getattr-assigned forms.
    verb, _, rest = arg.partition(" ")
    fn = getattr(_TEXT, verb)       # attacker verb, benign receiver
    return fn(rest)
