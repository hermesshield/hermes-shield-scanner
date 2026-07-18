"""Tool registry + dispatcher. The name comes straight from the request body,
so `TOOLS[name]` is attacker-selected dynamic dispatch.
"""
from tools import echo_tool, py_tool, raw_tool, shell_tool, text_tool

TOOLS = {
    "shell": shell_tool,
    "python": py_tool,
    "raw": raw_tool,
    "echo": echo_tool,
    "text": text_tool,
}


def run_tool(name, arg):
    handler = TOOLS[name]           # attacker-controlled key
    return handler(arg)
