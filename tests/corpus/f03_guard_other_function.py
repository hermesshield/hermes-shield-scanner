from shield_kill_switch import assert_live_action_allowed
def gate():
    assert_live_action_allowed({'surface':'x'})
def publish():
    client.create_tweet(text='x')
