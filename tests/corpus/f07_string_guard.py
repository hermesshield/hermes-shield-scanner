def publish():
    note = "call assert_live_action_allowed before posting"
    client.create_tweet(text=note)
