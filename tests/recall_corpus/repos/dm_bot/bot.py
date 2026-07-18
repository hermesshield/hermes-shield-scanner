"""Incoming-DM command loop. UNTRUSTED INGRESS: the text of an inbound direct
message is parsed as a command and its target/body forwarded to the senders.
"""
import asyncio

from senders import broadcast, send_dm, send_tg


class Bot:
    def __init__(self, api, tg_client):
        self.api = api
        self.tg_client = tg_client

    def on_message(self, event):
        # event.text is attacker-controlled (an inbound DM)
        cmd, _, rest = event["text"].partition(" ")
        if cmd == "!reply":
            target, _, body = rest.partition(" ")
            return send_dm(self.api, target, body)
        if cmd == "!tg":
            channel, _, body = rest.partition(" ")
            return asyncio.run(send_tg(self.tg_client, channel, body))
        if cmd == "!broadcast":
            targets, _, body = rest.partition(" ")
            return broadcast(self.api, targets.split(","), body)
        return None
