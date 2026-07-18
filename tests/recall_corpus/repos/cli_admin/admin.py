"""Admin CLI. UNTRUSTED INGRESS: argv sub-command + argument. Three privileged
verbs reach dangerous primitives through three different indirections.
"""
import os
import sys

# import-aliasing: os.system re-imported under an innocuous name
from os import system as shell_exec

# string-registry: verb -> os attribute name
_OS_OPS = {"purge": "system", "spawn": "popen"}


def do_shell(arg):
    # PLANTED S15 — os.system via an import alias (`shell_exec`). Static resolves
    # the import and SHOULD catch it.
    return shell_exec(arg)


def do_eval(src):
    # PLANTED S16 — compile the CLI-supplied source then exec it. Both builtins;
    # static SHOULD catch the exec.
    code = compile(src, "<admin-cli>", "exec")
    namespace = {}
    exec(code, namespace)
    return namespace


def do_op(verb, arg):
    # PLANTED S17 — the os method is looked up in a string registry, bound to a
    # local via getattr, then invoked. Assigned-form dynamic dispatch — missed.
    method = _OS_OPS[verb]          # "system"
    fn = getattr(os, method)
    return fn(arg)


def do_status():
    # DECOY D07 — benign: prints a status line, no capability.
    print("admin ok; pid", os.getpid())
    return 0


def main(argv):
    cmd = argv[1]
    if cmd == "shell":
        return do_shell(argv[2])
    if cmd == "eval":
        return do_eval(argv[2])
    if cmd == "op":
        return do_op(argv[2], argv[3])
    if cmd == "status":
        return do_status()


if __name__ == "__main__":
    main(sys.argv)
