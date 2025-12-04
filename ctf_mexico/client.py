<<<<<<< HEAD
from PIL import Image

def extraer_mensaje(imagen_entrada):
    img = Image.open(imagen_entrada)
    img = img.convert("RGB")
    pixels = img.load()

    ancho, alto = img.size
    bits = []

    # Recorremos solo píxeles pares
    for y in range(alto):
        for x in range(ancho):
            idx = y * ancho + x
            if idx % 2 == 0: # píxeles pares
                r, g, b = pixels[x, y]
                bits.append(b & 1)

    # Agrupar bits en bytes
    mensaje = ""
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) < 8:
            continue
        caracter = chr(int("".join(map(str, byte)), 2))
        mensaje += caracter
    if mensaje.endswith("###"): # delimitador de fin
        return mensaje[:-3]

    return mensaje


if __name__ == "__main__":
    entrada = "sully.png" # imagen con el mensaje oculto
    mensaje = extraer_mensaje(entrada)
    print(f"✅ Mensaje revelado: {mensaje}")
=======
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
>>>>>>> 946e05e41d388b49000b03c02ed742df928a6588
