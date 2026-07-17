def handle(external_post_text):
    prompt = "Draft a reply to this post text: " + external_post_text   # unfenced ingress
    return llm(prompt)
