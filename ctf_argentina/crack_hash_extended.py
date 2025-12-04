#!/usr/bin/env python3
"""
Generador de diccionario expandido para crackear el hash
Genera combinaciones de palabras comunes + números
"""

import hashlib
import itertools

hash_target = "fcf730b6d95236ecd3c9fc2d92d7b6b2bb061514961aec041d6c7a7192f592e4"

# Base de palabras
base_words = [
    "password", "admin", "welcome", "login", "user", "test",
    "secret", "flag", "crack", "hash", "pass", "admin", "root",
    "guest", "demo", "temp", "new", "default", "simple",
    "qwerty", "abc", "test", "system", "admin", "root",
    "password", "admin", "123456", "letmein", "monkey", "dragon",
    "master", "shadow", "sunshine", "secret", "welcome",
]

# Sufijos comunes
suffixes = ["", "1", "2", "3", "123", "456", "789", "000", "111", "!"]

print(f"[*] Generando diccionario extendido para crackear SHA-256...\n")
print(f"    Hash objetivo: {hash_target[:32]}...\n")

count = 0
found = False

# Generar combinaciones
for word in base_words:
    for suffix in suffixes:
        candidate = word + suffix
        candidate_hash = hashlib.sha256(candidate.encode()).hexdigest()
        count += 1
        
        if candidate_hash.lower() == hash_target.lower():
            print(f"\n[+] ¡¡¡ENCONTRADO!!!")
            print(f"[+] Palabra: {candidate}")
            print(f"[+] SHA-256: {candidate_hash}")
            print(f"\n[+] FLAG: UNLP{{{candidate}}}\n")
            
            with open("crackme02_result.txt", "w") as f:
                f.write(f"Password: {candidate}\n")
                f.write(f"SHA-256: {candidate_hash}\n")
                f.write(f"Flag: UNLP{{{candidate}}}\n")
            
            print("[+] Resultado guardado en crackme02_result.txt")
            found = True
            break
        
        if count % 100 == 0:
            print(f"    [{count}] {candidate:20s} → {candidate_hash[:16]}...")
    
    if found:
        break

if not found:
    print(f"\n[-] No encontrado en {count} combinaciones")
    print("\n[*] Intentando con fuerza bruta de caracteres...")
    
    # Intentar brute force simple (solo números y letras cortas)
    import string
    
    for length in range(1, 6):
        print(f"\n[*] Probando longitud {length}...")
        
        chars = string.ascii_lowercase + string.digits
        attempts = 0
        
        for combo in itertools.product(chars, repeat=length):
            candidate = ''.join(combo)
            candidate_hash = hashlib.sha256(candidate.encode()).hexdigest()
            attempts += 1
            
            if candidate_hash.lower() == hash_target.lower():
                print(f"\n[+] ¡¡¡ENCONTRADO!!!")
                print(f"[+] Palabra: {candidate}")
                print(f"[+] SHA-256: {candidate_hash}")
                print(f"\n[+] FLAG: UNLP{{{candidate}}}\n")
                
                with open("crackme02_result.txt", "w") as f:
                    f.write(f"Password: {candidate}\n")
                    f.write(f"SHA-256: {candidate_hash}\n")
                    f.write(f"Flag: UNLP{{{candidate}}}\n")
                
                found = True
                break
            
            if attempts % 10000 == 0:
                print(f"    {attempts:6d} intentos... ({candidate})")
                if attempts > 100000:
                    print("    [abandoning - demasiados intentos]")
                    break
        
        if found or attempts > 100000:
            break

if not found:
    print("\n[-] No se encontró la contraseña")
    print("[*] Opciones:")
    print("    1. Descarga rockyou.txt desde: https://github.com/zacheller/rockyou/raw/master/rockyou.txt")
    print("    2. O el archivo comprimido: https://www.kaggle.com/wjburns/common-password-list-rockyoutxt")
    print("    3. Luego ejecuta: hashcat -m 1400 hash.txt rockyou.txt -o resultado.txt")
