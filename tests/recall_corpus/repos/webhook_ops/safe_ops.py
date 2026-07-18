"""A genuinely guarded shell op — the DECOY. It only ever runs behind BOTH a
dry-run switch and an explicit human approval. A precision-correct scanner must
attribute the guards and NOT report this as an unguarded live sink.
"""
import os
import subprocess


def human_approved():
    return input("approve? [y/N] ") == "y"


def guarded_shell(cmd):
    # DECOY D02 — guarded: dry-run short-circuit + human approval gate before
    # the subprocess call. Expected verdict BLUE (guards attributed).
    if os.environ.get("DRY_RUN", "1") == "1":
        print("[dry-run] would run:", cmd)
        return None
    if not human_approved():
        raise PermissionError("operator declined")
    return subprocess.run(cmd, shell=True)
