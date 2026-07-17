from shield_kill_switch import live_actions_blocked
def send():
    try:
        if live_actions_blocked():
            return
    except Exception:
        raise
    service.users().messages().send(userId='me', body={})
