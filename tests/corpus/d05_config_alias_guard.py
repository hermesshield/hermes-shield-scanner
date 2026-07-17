from final_action_gate import allow_action as _gate
def publish():
    _gate({'surface': 'x'})
    client.create_tweet(text='x')
