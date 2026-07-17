"""Markdown/JSON writers for scanner outputs. Writes ONLY under the given report dir."""
from __future__ import annotations
import json
from pathlib import Path


def write_json(obj, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, default=str), encoding="utf-8")


def matrix_markdown(rows) -> str:
    head = ("| lane/tool | capability | ingress | live | kill | gate | fence | hash | dry-run | "
            "approval | csrf | cert | tests | scope | verdict |\n"
            "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n")
    body = ""
    for r in rows:
        body += ("| " + " | ".join(str(x) for x in r) + " |\n")
    return head + body
