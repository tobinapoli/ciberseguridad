#!/usr/bin/env python3

import binascii
from Crypto.Cipher import AES

# Clave base que usa el .pyc
k = "P4s5w0rd"

# AES necesita 16/24/32 bytes -> duplicamos la clave (8*2 = 16 bytes)
key = (k * 2).encode("utf-8")

# IV extraído del .pyc
iv = b"thisIsNotTheFlag"

# Ciphertext (el secret_hex que ya habías sacado)
cipher_hex = "f92d0786425761806008f985a2fcc4a1f04e142b6b7dadd0998083c35135dc21"
cipher = binascii.unhexlify(cipher_hex)

# Crear el objeto AES en modo CBC y desencriptar
aes = AES.new(key, AES.MODE_CBC, iv)
pt = aes.decrypt(cipher)

# Quitar padding PKCS#7
pad = pt[-1]
if 1 <= pad <= 16:
    pt = pt[:-pad]

# Mostrar flag
print(pt.decode())
