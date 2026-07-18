"""Notification helpers. Both are thin wrappers around live send primitives,
called cross-file from handlers.py with attacker-influenced content.
"""
import smtplib

import requests

TG_API = "https://api.telegram.org/bot%s/sendMessage"


def email_alert(to_addr, subject, body):
    # PLANTED S04 — live outbound email via smtplib.sendmail inside a wrapper,
    # reached cross-file from the webhook handler. Static SHOULD catch this.
    server = smtplib.SMTP("localhost", 25)
    msg = "Subject: %s\n\n%s" % (subject, body)
    server.sendmail("ops@example.com", to_addr, msg)
    server.quit()


def tg_alert(chat_id, text, token):
    # PLANTED S05 — Telegram message send via requests.post to the bot API.
    # Static catches the requests.post as external_write (capability-generic).
    return requests.post(TG_API % token, json={"chat_id": chat_id, "text": text})
