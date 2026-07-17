from hermes_global_kill_switch import assert_live_action_allowed as _ks
def _upload(text):                    # PRIVATE helper -> cross-module full-path proof (not entrypoint)
    return client.create_tweet(text=text)
def entry(text):
    try:
        _ks({"surface": "x", "action": "post"})
    except Exception:
        raise
    return _upload(text)
