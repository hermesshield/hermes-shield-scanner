#!/usr/bin/env python3
"""
S8.84 — three sound-leaning corrections that stop LOCAL developer/operator input channels being seeded as
attacker front doors (the "false reachable" is the fatal error for a SOUND-LEANING scanner):

  1. patterns.DEV_HINT classifies `samples/` dirs as demonstration code (like `examples/`), so input()-in-
     samples demos are NOT scanned as attacker-reachable prod (and the AI tier never targets them).
  2. ai_tier surfaces inherit the REAL path classification (repo_scanner._context) instead of hard-coding
     "prod" — defence-in-depth so a demo/sample file can never be mis-seeded as a prod attack surface.
  3. entrypoints stops seeding Typer/Click operator-CLI verbs (@app.command / @click.command) as untrusted
     entrypoints, while KEEPING genuine chatbot @bot.command handlers untrusted. This removes false
     untrusted-seeds only — the static reachable count can only stay the same or DROP.

Read-only; no live actions.
"""
from __future__ import annotations
import sys
from pathlib import Path


from hermes_shield import patterns as PAT, repo_scanner  # noqa: E402
from hermes_shield.call_graph import FileGraph, _is_cli_command  # noqa: E402
from hermes_shield.entrypoints import detect_entrypoints  # noqa: E402
import ast  # noqa: E402


def _fn(src, name):
    tree = ast.parse(src)
    return next(n for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name)


def _entrypoints(src, rel="svc.py"):
    return detect_entrypoints({rel: FileGraph(src)})


# ---- FIX 1: DEV_HINT classifies samples/ as demonstration code ----

def test_01_samples_dir_is_dev_context():
    assert repo_scanner._context("samples/quickstart.py") == "dev"
    assert repo_scanner._context("pkg/sample/demo.py") == "dev"
    # examples/ (pre-existing) still dev — no regression
    assert repo_scanner._context("examples/run.py") == "dev"


def test_02_prod_paths_unchanged_by_dev_hint():
    # a real prod path with no dev/test/report marker stays prod (fix must not over-broaden)
    assert repo_scanner._context("src/hermes/live_sender.py") == "prod"
    assert not PAT.DEV_HINT.search("src/hermes/sampler_live.py")  # 'sampler' != a samples/ dir


# ---- FIX 3: Typer/Click CLI verbs are NOT untrusted entrypoints; @bot.command still is ----

_TYPER_CLI = (
    "import typer\n"
    "app = typer.Typer()\n"
    "@app.command()\n"
    "def deploy(name: str = typer.Argument(...), force: bool = typer.Option(False)):\n"
    "    run_shell(name)\n"
)

_CLICK_CLI = (
    "import click\n"
    "@click.command()\n"
    "@click.option('--name')\n"
    "def deploy(name):\n"
    "    run_shell(name)\n"
)

_BOT_COMMAND = (
    "@bot.command()\n"
    "async def deploy(ctx, name):\n"
    "    run_shell(name)\n"
)


def test_03_typer_cli_command_not_untrusted_entrypoint():
    assert _is_cli_command(_fn(_TYPER_CLI, "deploy")) is True
    eps = _entrypoints(_TYPER_CLI)
    assert ("svc.py", "deploy") not in eps, "Typer @app.command must NOT be an untrusted entrypoint"


def test_04_click_cli_command_not_untrusted_entrypoint():
    assert _is_cli_command(_fn(_CLICK_CLI, "deploy")) is True
    eps = _entrypoints(_CLICK_CLI)
    assert ("svc.py", "deploy") not in eps, "Click @click.command must NOT be an untrusted entrypoint"


def test_05_bot_command_still_untrusted_entrypoint():
    # a genuine chatbot handler has NO click/typer signal -> stays an untrusted entrypoint (sound-leaning
    # correction must not silence real bot front doors)
    assert _is_cli_command(_fn(_BOT_COMMAND, "deploy")) is False
    eps = _entrypoints(_BOT_COMMAND)
    assert ("svc.py", "deploy") in eps
    assert eps[("svc.py", "deploy")]["type"] == "event_handler"
    assert "name" in eps[("svc.py", "deploy")]["untrusted_params"]


def test_06_genuine_event_handlers_unchanged():
    # @client.event on_message and webhook decorators keep working (fix touches only the `command` tail)
    src = (
        "@client.event\n"
        "async def on_message(message):\n"
        "    handle(message)\n"
        "@app.webhook('/hook')\n"
        "def hook(payload):\n"
        "    handle(payload)\n"
    )
    eps = _entrypoints(src)
    assert ("svc.py", "on_message") in eps
    assert ("svc.py", "hook") in eps


def test_07_removal_only_never_adds_seeds():
    # The guard can only REMOVE the CLI form; every function that WAS an entrypoint pre-fix (via a non-command
    # deco or a name) must still be one. A Typer command is the ONLY thing removed here.
    src = _TYPER_CLI + (
        "@bot.command()\n"
        "async def chat(ctx, text):\n"
        "    handle(text)\n"
    )
    eps = _entrypoints(src)
    assert ("svc.py", "deploy") not in eps          # CLI verb removed
    assert ("svc.py", "chat") in eps                # bot command kept
