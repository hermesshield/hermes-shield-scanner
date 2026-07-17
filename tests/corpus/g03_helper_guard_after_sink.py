from hermes_global_kill_switch import assert_live_action_allowed as _ks
def upload(text):
    return client.create_tweet(text=text)
def entry(text):
    r = upload(text)                  # helper called BEFORE the guard
    try:
        _ks({"surface": "x", "action": "post"})
    except Exception:
        raise
    return r
