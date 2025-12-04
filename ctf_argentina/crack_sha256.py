#!/usr/bin/env python3
import hashlib

# Hash encontrado en el binario
target_hash = "fcf730b6d95236ecd3c9fc2d92d7b6b2bb061514961aec041d6c7a7192f592e44"

# Lista de palabras comunes para crackme
common_passwords = [
    "password",
    "admin",
    "123456",
    "password123",
    "admin123",
    "ctf",
    "flag",
    "crackme",
    "secret",
    "test",
    "letmein",
    "monkey",
    "dragon",
    "master",
    "password1",
    "admin@123",
    "1234567890",
    "qwerty",
    "changeme",
    "12345678",
    "security",
    "welcome",
    "sunshine",
    "football",
    "123123",
    "1q2w3e4r",
    "passw0rd",
    "P@ssword",
    "abc123",
    "shadow",
]

print("[*] Intentando crackear el SHA-256...")
print(f"[*] Hash objetivo: {target_hash}")
print()

for password in common_passwords:
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()
    print(f"[?] {password:20} -> {sha256_hash}")
    
    if sha256_hash == target_hash:
        print()
        print(f"[+] ¡ENCONTRADO! La contraseña es: {password}")
        print(f"[+] Hash SHA-256: {sha256_hash}")
        break
else:
    print()
    print("[-] No se encontró coincidencia con las palabras comunes")
    print("[*] Probando con variaciones...")
