"""HTTP entrypoint. UNTRUSTED INGRESS: the JSON request body carries both the
tool name and its argument, handed straight to the registry dispatcher.
"""
from flask import Flask, request

from registry import run_tool

app = Flask(__name__)


@app.route("/invoke", methods=["POST"])
def invoke():
    body = request.get_json(force=True)
    name = body["tool"]      # untrusted
    arg = body["arg"]        # untrusted
    return {"result": str(run_tool(name, arg))}


if __name__ == "__main__":
    app.run(port=8080)
