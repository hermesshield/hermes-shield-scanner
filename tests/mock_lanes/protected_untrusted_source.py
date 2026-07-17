from hermes_untrusted import make_untrusted_content, wrap_for_action_prompt
def handle(external_post_text):
    o = make_untrusted_content("x_post", external_post_text)   # fenced/quarantined
    return wrap_for_action_prompt(o, "draft a reply")
