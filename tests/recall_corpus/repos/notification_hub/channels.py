"""Notification channels selected by config. Slack posts via requests, Email
sends via SendGrid's generic `send`, Shell runs a templated command.
"""
import subprocess

import requests
import sendgrid


class SlackChannel:
    def __init__(self, webhook_url):
        self.webhook_url = webhook_url

    def send(self, message):
        # PLANTED S18 — outbound webhook post via requests.post, factory-selected.
        # Static catches requests.post as external_write.
        return requests.post(self.webhook_url, json={"text": message})


class EmailChannel:
    def __init__(self, api_key):
        self.sg = sendgrid.SendGridAPIClient(api_key)

    def send(self, message):
        # PLANTED S19 — email send via SendGrid's generic `send` on an attribute
        # receiver. Generic verb on an unresolved object — static tends to miss.
        return self.sg.send(message)


class ShellChannel:
    def send(self, message):
        # PLANTED S21 — templated shell notification: the attacker-controlled
        # message is interpolated into a shell string. Literal subprocess call;
        # static SHOULD catch it.
        return subprocess.check_output("notify-send " + message, shell=True)
