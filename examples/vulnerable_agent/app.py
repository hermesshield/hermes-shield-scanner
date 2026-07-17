"""Illustrative only — a deliberately-unsafe toy agent for the sample scan. Not real code."""
from flask import Flask, request

app = Flask(__name__)

@app.post("/run")                       # untrusted HTTP entrypoint
def run():
    task = request.json.get("task")     # untrusted input
    return str(eval(task))              # REACHABLE code-exec -> UNGUARDED_CRITICAL_LIVE_SINK
