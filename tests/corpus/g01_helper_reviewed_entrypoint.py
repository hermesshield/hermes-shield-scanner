from hermes_global_kill_switch import assert_live_action_allowed as _ks
def upload(text):                     # public helper: live post sink, no in-file guard
    return client.create_tweet(text=text)
def entry(text):                      # allowed caller guards BEFORE the helper call
    try:
        _ks({"surface": "x", "action": "post"})
    except Exception:
        raise
    return upload(text)
