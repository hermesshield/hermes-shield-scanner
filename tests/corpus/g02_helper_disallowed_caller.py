def upload(text):
    return client.create_tweet(text=text)
def rogue(text):                      # caller NOT in allowed_callers
    return upload(text)
