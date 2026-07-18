"""Event router. Selects an op based on the webhook event type and forwards
the untrusted payload fields to the relevant helper.
"""
from compute import run_formula
from notify import email_alert, tg_alert
from safe_ops import guarded_shell
from sanitised import run_safe_cmd


def dispatch(event):
    kind = event.get("type")
    data = event.get("data", {})
    if kind == "email":
        return email_alert(data["to"], data["subject"], data["body"])
    if kind == "telegram":
        return tg_alert(data["chat_id"], data["text"], data["token"])
    if kind == "formula":
        return run_formula(data["expr"], data.get("vars", {}))
    if kind == "shell":
        return guarded_shell(data["cmd"])
    if kind == "safecmd":
        return run_safe_cmd(data["cmd"])
    return {"ignored": kind}
