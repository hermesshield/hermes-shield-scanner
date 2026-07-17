def upload(text):                     # public helper, no entrypoint config -> stays unproven
    return client.create_tweet(text=text)
def entry(text):
    return upload(text)
