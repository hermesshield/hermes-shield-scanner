"""Outbound message senders. Wrappers around X (tweepy) and Telegram (telethon)
send primitives, plus a broadcast path that binds the send method by reference.
"""
import tweepy
from telethon import TelegramClient


def send_dm(api, user_id, text):
    # PLANTED S09 — direct message send via tweepy. `send_direct_message` is a
    # distinctive DM verb; static SHOULD catch it even on an unresolved receiver.
    return api.send_direct_message(user_id, text)


async def send_tg(client, channel, text):
    # PLANTED S10 — Telegram send via telethon's generic `send_message` verb on
    # a locally-passed client. Static tends to miss generic verbs on unresolved
    # receivers.
    return await client.send_message(channel, text)


def broadcast(api, user_ids, text):
    # PLANTED S11 — the send method is bound to a local by attribute reference
    # then called in a loop. No literal .send_direct_message call site here.
    _sender = api.send_direct_message
    return [_sender(uid, text) for uid in user_ids]


def preview_dm(user_id, text):
    # DECOY D05 — benign: builds a preview string, sends nothing.
    return "DM -> %s: %s" % (user_id, text)
