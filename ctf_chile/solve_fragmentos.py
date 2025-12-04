import base64
from pathlib import Path

# Leer fragmentos
fragmentos_path = Path(__file__).resolve().parent / "fragmentos.txt"
fragmentos = {}

with open(fragmentos_path, "r") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        idx, payload = line.split(":", 1)
        fragmentos[int(idx)] = payload

print(f"[*] Fragmentos cargados: {len(fragmentos)}")

def xor_bytes(data, key):
    """XOR data con una clave de 1 byte"""
    return bytes(b ^ key for b in data)

def try_key(key):
    """Intenta descodificar con la clave dada"""
    try:
        mensaje = ""
        for idx in sorted(fragmentos.keys()):
            b64_payload = fragmentos[idx]
            # Decodificar Base64
            encrypted = base64.b64decode(b64_payload)
            # Aplicar XOR
            decrypted = xor_bytes(encrypted, key)
            # Convertir a string
            mensaje += decrypted.decode("utf-8", errors="ignore")
        return mensaje
    except Exception:
        return None

# Probar todas las claves
print("[*] Probando claves XOR (0–255)...")
for key in range(256):
    msg = try_key(key)
    if msg and "CTF{" in msg:
        print(f"\n[✓] ¡Clave encontrada! Key = {key}")
        print(f"[✓] Mensaje: {msg}")
        # Extraer flag
        start = msg.find("CTF{")
        end = msg.find("}", start) + 1
        if start != -1 and end > start:
            flag = msg[start:end]
            print(f"[✓] FLAG: {flag}")
        break
else:
    print("[!] No se encontró la flag con ninguna clave")