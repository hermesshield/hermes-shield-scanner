from shield_kill_switch import assert_live_action_allowed
def publish():
    client.create_tweet(text='x')
    assert_live_action_allowed({'surface':'x'})
