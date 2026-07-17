def send():
    service.users().messages().send(userId="me", body={})   # no guard -> BLOCK
