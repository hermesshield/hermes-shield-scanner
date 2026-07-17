from shield_kill_switch import assert_live_action_allowed
def send(live=False):
    if not live:
        return "dry_run_no_send"
    assert_live_action_allowed({"surface": "gmail"})   # GLOBAL KILL SWITCH before send
    service.users().messages().send(userId="me", body={})
