def post():
    client.create_tweet(text="hello world")   # no kill-switch guard -> should BLOCK
