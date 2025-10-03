#!/usr/bin/env python3
# solve_11002_auto.py
from pwn import remote
import base64, re

HOST = "ic.catedras.linti.unlp.edu.ar"
PORT = 11002

def extract_word(banner_bytes):
    s = banner_bytes.decode('latin1', errors='replace')
    # intenta capturar "base64 ... palabra: <palabra>"
    m = re.search(r'base64.*?palabra[:\s]*([^\s]+)', s, flags=re.I)
    if m:
        return m.group(1).strip()
    # fallback: última token de la última línea no vacía
    lines = [line for line in s.splitlines() if line.strip()]
    if lines:
        return lines[-1].split()[-1].strip()
    return None

def main():
    r = remote(HOST, PORT, timeout=4)
    try:
        # leemos el banner rápido
        banner = r.recv(timeout=1.0)
        print("BANNER:\n", banner.decode('latin1', errors='replace'))

        palabra = extract_word(banner)
        if not palabra:
            print("No pude extraer la palabra del banner. Copiá la salida del banner y la vemos.")
            return

        print("Palabra detectada:", palabra)
        b64 = base64.b64encode(palabra.encode('utf-8')).decode('ascii')
        # enviar como bytes (evita BytesWarning)
        r.sendline(b64.encode('ascii'))
        print("Enviado:", b64)

        # leer respuesta final
        resp = r.recv(timeout=2.0)
        print("RESPUESTA:\n", resp.decode('latin1', errors='replace'))
    finally:
        r.close()

if __name__ == "__main__":
    main()
