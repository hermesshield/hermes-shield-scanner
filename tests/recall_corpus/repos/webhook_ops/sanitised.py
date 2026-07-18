"""Reachable-but-sanitised path — DECOY. The webhook-supplied `cmd` really does
reach a live subprocess sink, but only after a strict allowlist neutralises it,
so no attacker-controlled value can ever reach the shell. This tests false-
positive DISCIPLINE on neutralised flows: a precision-correct scanner must see
that the value reaching the sink is one of four fixed literals and NOT report a
live danger. (The current static scanner flags it anyway — it does not track the
upstream allowlist — which is exactly the discipline gap the finder must close.)
"""
import subprocess

_ALLOWED = {"ls", "df", "uptime", "whoami"}


def run_safe_cmd(cmd):
    # DECOY D09 — untrusted `cmd` from the webhook, but validated against a
    # strict allowlist upstream of the sink. After the guard, `cmd` is provably
    # one of four fixed literals: shell injection is impossible. Expected BLUE
    # (a real primitive is present but the flow is neutralised, not live).
    if cmd not in _ALLOWED:
        raise ValueError("command not permitted")
    return subprocess.run(cmd, shell=True, capture_output=True)
