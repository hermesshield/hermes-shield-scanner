from shield_kill_switch import assert_live_action_allowed
from xmod.mod_b_helper import _send_clean
from xmod.mod_b_shared import _send_shared
def publish(text):
    assert_live_action_allowed({'surface':'x'})
    _send_clean(text)
def publish_shared(text):
    assert_live_action_allowed({'surface':'x'})
    _send_shared(text)
