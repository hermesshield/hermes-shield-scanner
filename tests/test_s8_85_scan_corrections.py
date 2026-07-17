#!/usr/bin/env python3
"""
S8.85 — three sound-leaning, REMOVE-ONLY corrections that de-inflate the 12-repo framework scan (they can only
drop false positives, never add a finding). Locks in:

  1. patterns.DEV_HINT / SKIP_DIRS reclassify demo + vendored trees as non-prod: demos?/ cookbook/ recipes?/
     tutorials?/ notebooks?/ are dev; vendor/ third_party/ contrib/ are skipped. (samples/ examples/ already dev.)
  2. cap_normalise no longer FORCE-FITS bare `execute`/`compile` data-plane phrases to code_exec (RCE): only a
     GENUINE exec/eval/code-exec/execute-code/subprocess/compile-code token promotes.
  3. `sys.stdin.read()` inside a CLI `__main__` module is trusted parent/operator IPC, not an untrusted taint
     source (the julep _resolve_child.py:258 false reachable). A stdin read with NO __main__ guard stays a source.

Read-only; no live actions.
"""
from __future__ import annotations
import ast

from hermes_shield import patterns as PAT, repo_scanner
from hermes_shield import taint as T
from hermes_shield.call_graph import _has_main_guard
from hermes_shield.cap_normalise import normalise_capability

_RCE = {"code_exec", "deserialize", "subprocess_exec", "ssti"}


# ---- FIX 1: demo trees are dev, vendored trees are skipped ----

def test_01_demo_dirs_are_dev_context():
    for rel in ("cookbook/level_4_team.py", "demos/quickstart.py", "demo/run.py",
                "recipes/chain.py", "recipe/x.py", "tutorials/intro.py", "tutorial/a.py",
                "notebooks/explore.py", "notebook/b.py"):
        assert repo_scanner._context(rel) == "dev", rel
    # pre-existing dev dirs unchanged
    assert repo_scanner._context("examples/run.py") == "dev"
    assert repo_scanner._context("pkg/samples/demo.py") == "dev"


def test_02_vendored_dirs_are_skipped():
    for d in ("vendor", "third_party", "contrib"):
        assert d in PAT.SKIP_DIRS
        assert set(("pkg", d, "mod.py")) & PAT.SKIP_DIRS


def test_03_real_prod_paths_unchanged():
    # a genuine package path with no demo/vendor marker stays prod (the fix must not over-broaden)
    assert repo_scanner._context("agno/agent/live.py") == "prod"
    assert repo_scanner._context("julep/execution/activities.py") == "prod"
    assert not PAT.DEV_HINT.search("src/cookbookery.py")   # 'cookbookery' != a cookbook/ dir
    assert not PAT.DEV_HINT.search("src/recipe_engine.py") # 'recipe_engine' != a recipes/ dir


# ---- FIX 2: cap_normalise force-fit removed ----

def test_04_dataplane_execute_compile_not_rce():
    for cap in ("execute sql", "execute query", "execute workflow", "execute statement",
                "compile template", "compile regex", "compile report", "execute", "compile"):
        canon, mapped = normalise_capability(cap)
        assert not (mapped and canon in _RCE), f"{cap!r} force-fit to RCE {canon}"


def test_05_genuine_code_exec_tokens_still_promote():
    for cap in ("execute-code", "code-execution", "exec", "eval", "code-exec",
                "expression eval", "enable-code-execution", "compile code", "code compilation"):
        canon, mapped = normalise_capability(cap)
        assert mapped and canon == "code_exec", f"{cap!r} lost its genuine code_exec mapping ({canon})"
    assert normalise_capability("subprocess") == ("subprocess_exec", True)
    assert normalise_capability("deserialize/eval") == ("deserialize", True)


# ---- FIX 3: stdin-in-a-CLI-__main__ is trusted IPC, not a source ----

_STDIN_CLI = (
    "import sys, json\n"
    "def main():\n"
    "    raw = sys.stdin.read()\n"
    "    payload = json.loads(raw)\n"
    "    interpret(payload.get('value'))\n"
    "if __name__ == '__main__':\n"
    "    raise SystemExit(main())\n"
)
_STDIN_NO_MAIN = (
    "import sys\n"
    "def handle():\n"
    "    raw = sys.stdin.read()\n"
    "    interpret(raw)\n"
)


def test_06_has_main_guard_detection():
    assert _has_main_guard(ast.parse(_STDIN_CLI)) is True
    assert _has_main_guard(ast.parse(_STDIN_NO_MAIN)) is False


def test_07_stdin_source_suppressed_in_cli_main():
    tree = ast.parse(_STDIN_CLI)
    # WITH the CLI __main__ signal, sys.stdin is trusted -> the interpret() call line carries no taint
    edges_cli = T.analyze(tree, cli_main=True)
    interp_line = next(n.lineno for n in ast.walk(tree)
                       if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "interpret")
    assert interp_line not in edges_cli, "stdin in a CLI __main__ must not seed taint"


def test_08_stdin_still_a_source_without_main_guard():
    tree = ast.parse(_STDIN_NO_MAIN)
    edges = T.analyze(tree, cli_main=False)   # no __main__ -> stdin stays untrusted (server/handler read)
    interp_line = next(n.lineno for n in ast.walk(tree)
                       if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "interpret")
    assert interp_line in edges, "sys.stdin.read() with no __main__ guard must remain an untrusted source"
