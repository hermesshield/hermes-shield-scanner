"""Illustrative only. A dangerous capability that is NOT reached from an entrypoint here."""
import subprocess

def run_shell(cmd):                     # inert in this repo...
    return subprocess.run(cmd, shell=True)   # ...INSTALL-LIABILITY: live once wired to untrusted input
