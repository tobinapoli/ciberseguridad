#!/usr/bin/env python3
import hashlib

# Hash encontrado en el binario
target_hash = "fcf730b6d95236ecd3c9fc2d92d7b6b2bb061514961aec041d6c7a7192f592e44"

print("[*] Buscando en rockyou.txt (si existe)...")
print(f"[*] Hash objetivo: {target_hash}")
print()

# Primero intentaremos descargar rockyou.txt
# Si no está disponible, usaremos palabras comunes

rockyou_path = "rockyou.txt"

try:
    with open(rockyou_path, 'r', encoding='latin-1', errors='ignore') as f:
        count = 0
        for line in f:
            password = line.strip()
            if not password:
                continue
            
            sha256_hash = hashlib.sha256(password.encode()).hexdigest()
            count += 1
            
            if count % 100000 == 0:
                print(f"[?] Probadas {count} palabras... última: {password[:50]}")
            
            if sha256_hash == target_hash:
                print()
                print(f"[+] ¡¡¡ENCONTRADO!!! La contraseña es: {password}")
                print(f"[+] Hash SHA-256: {sha256_hash}")
                print(f"[+] Total palabras probadas: {count}")
                exit(0)
        
        print(f"[-] No encontrado después de {count} palabras")

except FileNotFoundError:
    print(f"[-] {rockyou_path} no encontrado")
    print("[*] Descargando rockyou.txt...")
    
    import urllib.request
    import shutil
    
    # Intentar descargar desde un espejo
    url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100000.txt"
    
    try:
        print(f"[*] Descargando desde {url}...")
        urllib.request.urlretrieve(url, "wordlist.txt")
        print("[+] Descargado exitosamente")
        
        with open("wordlist.txt", 'r', encoding='latin-1', errors='ignore') as f:
            count = 0
            for line in f:
                password = line.strip()
                if not password:
                    continue
                
                sha256_hash = hashlib.sha256(password.encode()).hexdigest()
                count += 1
                
                if count % 10000 == 0:
                    print(f"[?] Probadas {count} palabras...")
                
                if sha256_hash == target_hash:
                    print()
                    print(f"[+] ¡¡¡ENCONTRADO!!! La contraseña es: {password}")
                    print(f"[+] Hash SHA-256: {sha256_hash}")
                    print(f"[+] Total palabras probadas: {count}")
                    exit(0)
        
        print(f"[-] No encontrado en wordlist descargado ({count} palabras)")
    
    except Exception as e:
        print(f"[-] Error al descargar: {e}")
        print("[*] Intenta con: hashcat -m 1400 hash.txt rockyou.txt")
