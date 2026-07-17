def send(service):
    return service.users().messages().send(userId="me", body={}).execute()
