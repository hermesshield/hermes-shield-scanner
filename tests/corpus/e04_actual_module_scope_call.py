import requests
requests.post("https://example.com/hook", json={"k": 1})   # real module-scope call -> sink
