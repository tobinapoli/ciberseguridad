#!/usr/bin/env python3
import hashlib

# Hash encontrado en el binario
target_hash = "fcf730b6d95236ecd3c9fc2d92d7b6b2bb061514961aec041d6c7a7192f592e44"

print("[*] Buscando hash en bases de datos online...")
print(f"[*] Hash objetivo: {target_hash}")
print()

# Intentar con varias APIs
apis = [
    ("https://api.md5crack.com/api.php?hash={hash}&email=test@example.com", "API md5crack"),
    ("https://hash.online-convert.com/hash_lookup?hash={hash}", "Online Convert"),
]

try:
    import urllib.request
    import json
    
    for api_url, api_name in apis:
        try:
            url = api_url.format(hash=target_hash)
            print(f"[?] Intentando con {api_name}...")
            
            # Hacer request
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                data = response.read().decode()
                print(f"    Respuesta: {data[:100]}")
                
                if target_hash not in data and "notfound" not in data.lower() and "error" not in data.lower():
                    if len(data) > 10:
                        print(f"[+] Posible resultado: {data}")
        
        except Exception as e:
            print(f"    Error: {str(e)[:50]}")

except ImportError:
    print("[-] urllib no disponible")

# Diccionario expandido más agresivo
print()
print("[*] Ejecutando fuerza bruta expandida...")

# Probar palabras comunes en español + inglés
common_spanish = [
    "contraseña", "clave", "acceso", "usuario", "seguridad", "privado",
    "secreto", "protegido", "bloqueado", "desbloquear", "ataque", "defensa",
]

common_english = [
    "password", "admin", "flag", "ctf", "crackme", "test", "secret",
    "key", "unlock", "access", "user", "root", "hack", "pwn",
]

# También números de años
for year in range(2020, 2026):
    common_english.append(str(year))
    common_english.append(f"pass{year}")
    common_english.append(f"admin{year}")

# Combinar todo
all_words = common_spanish + common_english + [
    "P@ssw0rd", "P@ssword123", "Admin@123", "Security123",
    "FLAG{found}", "CTF{flag}", "CRACKME{pass}", "Unlock123!",
    "Hacking123", "SecurePass", "ChallengePass", "SolveMe123",
]

count = 0
for password in all_words:
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()
    count += 1
    
    if sha256_hash == target_hash:
        print(f"[+] ¡¡¡ENCONTRADO!!! La contraseña es: '{password}'")
        print(f"[+] Hash SHA-256: {sha256_hash}")
        exit(0)

print(f"[-] No encontrado en {count} palabras adicionales")
print()
print("⚠️  El hash no se encuentra en diccionarios comunes")
print("💡 Posibilidades:")
print("   1. La contraseña es aleatoria/compleja")
print("   2. Es una pista/hint (ej: nombre del reto, autor, etc)")
print("   3. Necesita GPU/herramienta profesional (hashcat)")
print()
print(f"Para buscar online, copia este hash:")
print(target_hash)
