from final_action_gate import allow_action as _gate
def publish():
    # config-aliased gate — its decision is CONSUMED by the early-exit (a bare `_gate({...})` would discard
    # the return value: the ignored-return no-op the guard-credit cluster closes). Tests alias resolution.
    if not _gate({'surface': 'x'}):
        return
    client.create_tweet(text='x')
