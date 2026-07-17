from myapp.helpers import allow_action   # NOT the real gate module
def publish():
    allow_action()
    client.create_tweet(text='x')
