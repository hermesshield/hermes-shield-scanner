from shield_kill_switch import assert_live_action_allowed as _ks
def send():
    try:
        _ks({'surface': 'x'})
    except Exception:
        raise
    service.users().messages().send(userId='me', body={})
