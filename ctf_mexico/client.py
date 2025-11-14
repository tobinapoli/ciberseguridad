# client_fixed.py
from requests import get, post, Session
from requests.exceptions import RequestException
import sys

BASE_URL = "http://45.170.252.24:8080"   # <- poner la IP pública
UA = {"User-Agent": "PrivatePost 1.0"}

s = Session()

def get_path(path):
    try:
        r = s.get(BASE_URL + path, headers=UA, timeout=10)
        return r
    except RequestException as e:
        print("GET error:", e)
        return None

def post_path(path, data, as_json=True):
    try:
        if as_json:
            r = s.post(BASE_URL + path, headers={**UA, "Content-Type":"application/json"}, json=data, timeout=10)
        else:
            r = s.post(BASE_URL + path, headers={**UA, "Content-Type":"application/x-www-form-urlencoded"}, data=data, timeout=10)
        return r
    except RequestException as e:
        print("POST error:", e)
        return None

if __name__ == "__main__":
    print("Client fixed ready. Modify to run tests or use interactive mode.")
    # ejemplo rápido
    r = get_path("/")
    if r:
        print(r.status_code)
        print(r.text[:200])
        print(r.headers)
