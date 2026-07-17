def _send_shared(text):
    client.create_tweet(text=text)   # called by a guarded AND an unguarded entry -> not provable
