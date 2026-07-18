"""Flask webhook receiver. UNTRUSTED INGRESS: the entire event JSON is
attacker-controlled and flows to handlers.dispatch.
"""
from flask import Flask, request

from handlers import dispatch

app = Flask(__name__)


@app.route("/webhook", methods=["POST"])
def webhook():
    event = request.get_json(force=True)   # untrusted
    return {"ok": True, "result": str(dispatch(event))}


if __name__ == "__main__":
    app.run(port=8081)
