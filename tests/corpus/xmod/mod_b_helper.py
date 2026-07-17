def _send_clean(text):
    client.create_tweet(text=text)   # ONLY called by a guarded entry -> provable cross-module
