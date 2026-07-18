"""A plugin whose 'execute' hook shells out. The subprocess primitive is bound
to a module-level alias, so no literal subprocess.<call> appears at the sink.
"""
import subprocess

# aliasing: attribute reference captured at import time, invoked later
_run = subprocess.getoutput


def execute(cmd):
    # PLANTED S14 — shell command execution via the `_run` alias of
    # subprocess.getoutput. Reached through run_hook's dynamic dispatch.
    return _run(cmd)
