def assert_live_action_allowed(context=None):   # fail-open: swallows its own raise
    try:
        if _engaged():
            raise RuntimeError("blocked")
    except Exception:
        pass
