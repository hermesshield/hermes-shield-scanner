import httpx
def send(url, data):
    httpx.post(url, json=data)
