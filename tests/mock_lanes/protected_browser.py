from shield_kill_switch import assert_live_action_allowed
def act(page):
    assert_live_action_allowed({"surface": "browser", "action": "click"})
    page.click("#submit")
