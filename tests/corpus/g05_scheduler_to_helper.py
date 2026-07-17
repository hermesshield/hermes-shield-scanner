from hermes_global_kill_switch import assert_live_action_allowed as _ks
def send_dm(page, text):              # public helper: browser submit sink
    return page.keyboard.press("Enter")
def scheduler_entry(page, text):      # allowed scheduler entry guards first
    try:
        _ks({"surface": "linkedin", "action": "dm"})
    except Exception:
        raise
    return send_dm(page, text)
