from shield_kill_switch import assert_live_action_allowed
def post(human_approved, content_hash, approved_hash):
    assert_live_action_allowed({"surface": "x", "action": "post"})   # GLOBAL KILL SWITCH
    if not human_approved or content_hash != approved_hash:
        return "blocked"
    client.create_tweet(text="hello world")
