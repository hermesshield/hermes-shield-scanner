from shield_kill_switch import assert_live_action_allowed
def publish():
    assert_live_action_allowed({'surface':'x'})
    client.create_tweet(text='x')
