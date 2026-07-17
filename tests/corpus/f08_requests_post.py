import requests
def send(url, data):
    requests.post(url, json=data)
