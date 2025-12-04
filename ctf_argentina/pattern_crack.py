#!/usr/bin/env python3
import hashlib

# Hash encontrado en el binario
target_hash = "fcf730b6d95236ecd3c9fc2d92d7b6b2bb061514961aec041d6c7a7192f592e44"

print("[*] Fuerza bruta con patrones CTF...")
print(f"[*] Hash objetivo: {target_hash}")
print()

# Pistas del reto:
# "Hashing is the correct way to store passwords :)"
# La contraseña podría ser relacionada con:
# - SHA256 (ya está en el hash)
# - Hashing
# - Criptografía
# - UNLP (universidad)
# - CTF Argentina

passwords_to_try = [
    # Variaciones directas
    "sha256", "SHA256", "Sha256", "hashing", "Hashing", "HASHING",
    "hash", "Hash", "HASH",
    "crypto", "Crypto", "CRYPTO", "cryptography", "Cryptography",
    
    # Retos/Universidad
    "unlp", "UNLP", "Unlp", "argentina", "Argentina", "ARGENTINA",
    "ctf_argentina", "CTF_Argentina", "ctfargentina", "CTFArgentina",
    
    # Combinaciones
    "hash256", "Hash256", "sha_256", "SHA_256", "sha-256", "SHA-256",
    "hashsha256", "HashSHA256", "shasha256", "SHASHA256",
    "password_hash", "passwordhash", "PasswordHash",
    
    # Con números
    "sha256pass", "SHA256pass", "hash123", "Hash123",
    "hashing123", "Hashing123", "hashpass", "Hashpass",
    
    # Frases
    "correctway", "correctway123", "correct_way", "Correctway",
    "thewayto", "thewayto123", "store_passwords", "storepasswords",
    "storing_passwords", "storingpasswords",
    
    # Pistas cifradas/ocultas
    "h45h1ng", "h4sh1ng", "h@sh", "p@ssw0rd", "p4ssw0rd",
    "cr4ft0", "cr1pt0", "s3cur1ty", "s3curity",
    
    # Comunes en CTF Argentina
    "flag", "Flag", "FLAG", "challenge", "Challenge", "CHALLENGE",
    "crackme", "Crackme", "CRACKME", "reverse", "Reverse", "REVERSE",
    "engineering", "Engineering", "ENGINEERING", "reverseeng",
    
    # Año
    "2024", "2025", "password2024", "password2025", "hash2024", "hash2025",
    
    # Random comunes
    "admin123", "Admin123", "test123", "Test123", "root123", "Root123",
    "qwerty123", "Qwerty123", "letmein", "Letmein", "LETMEIN",
    "welcome", "Welcome", "WELCOME", "changeme", "Changeme", "CHANGEME",
    
    # Posibles pistas del reto específico
    "passw0rdhashing", "hashingiskey", "hashingisright", "securepassword",
    "correcthashing", "properhashing", "correctlyhashed", "wellhashed",
]

print(f"[*] Probando {len(passwords_to_try)} candidatos...")
print()

found = False
for i, password in enumerate(passwords_to_try):
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()
    
    if i % 20 == 0:
        print(f"[?] Probadas {i}... {password}")
    
    if sha256_hash == target_hash:
        print()
        print(f"[+] ¡¡¡ENCONTRADO!!! La contraseña es: '{password}'")
        print(f"[+] Hash SHA-256: {sha256_hash}")
        print()
        print("=" * 60)
        print(f"USERNAME: admin")
        print(f"PASSWORD: {password}")
        print("=" * 60)
        found = True
        break

if not found:
    print()
    print("[-] No encontrado en candidatos específicos del CTF")
    print()
    print("[RECOMENDACIÓN]")
    print("El hash NO está en diccionarios comunes.")
    print()
    print("Opciones:")
    print("1. Usar Hashcat (GPU):")
    print("   hashcat -m 1400 hash.txt /path/to/rockyou.txt")
    print()
    print("2. Buscar online:")
    print(f"   → Copia el hash: {target_hash}")
    print("   → Pégalo en: https://crackstation.net/")
    print()
    print("3. John the Ripper:")
    print("   john --format=raw-sha256 --wordlist=rockyou.txt hash.txt")
    print()
    print("4. Fuerza bruta local (muy lento sin GPU)")
    print("   → Máximo 6-7 caracteres realista")
