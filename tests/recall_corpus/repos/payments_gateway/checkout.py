"""Checkout endpoint. UNTRUSTED INGRESS: amount, token, mode and action all
arrive in the HTTP request and flow into the factory-selected gateway.
"""
from flask import Flask, request

from factory import make_gateway

app = Flask(__name__)


@app.route("/checkout", methods=["POST"])
def checkout():
    body = request.get_json(force=True)
    gw = make_gateway(body.get("mode", "live"))   # untrusted mode
    # amount/token untrusted; action forwarded to DynamicGateway when present
    if "action" in body:
        return {"charge": str(gw.charge(body["amount"], body["token"], body["action"]))}
    return {"charge": str(gw.charge(body["amount"], body["token"]))}


if __name__ == "__main__":
    app.run(port=8082)
