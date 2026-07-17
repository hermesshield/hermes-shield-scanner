from shield_kill_switch import assert_live_action_allowed
def _do_post():
    client.create_tweet(text='x')
def publish():
    assert_live_action_allowed({'surface':'x'})
    _do_post()
