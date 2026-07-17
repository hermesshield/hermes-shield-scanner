class GlobalKillSwitchBlocked(Exception):
    pass
def assert_live_action_allowed(context=None):   # real gate: raises on block
    if _engaged():
        raise GlobalKillSwitchBlocked("blocked")
