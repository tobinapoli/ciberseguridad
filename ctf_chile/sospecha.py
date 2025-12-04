def strange_encrypt(text):
    result = ""
    for i, c in enumerate(text):
        result += chr(ord(c) ^ (i + 5))
    return result.encode("utf-8").hex()

def strange_decrypt(hex_text):
    """Descifra el resultado de strange_encrypt"""
    data = bytes.fromhex(hex_text)
    result = ""
    for i, byte in enumerate(data):
        result += chr(byte ^ (i + 5))
    return result

# Prueba con "admin"
username = "admin"
cipher = strange_encrypt(username)
print(f"Encrypted 'admin': {cipher}")

# Descifra
decrypted = strange_decrypt(cipher)
print(f"Decrypted: {decrypted}")

# La flag será el valor descifrado correcto
print(f"FLAG: {decrypted}")