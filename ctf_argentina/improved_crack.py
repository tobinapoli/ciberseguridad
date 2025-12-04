#!/usr/bin/env python3
import hashlib
import json

# Hash encontrado en el binario
target_hash = "fcf730b6d95236ecd3c9fc2d92d7b6b2bb061514961aec041d6c7a7192f592e44"

print("[*] Intentando reverse lookup del hash...")
print(f"[*] Hash objetivo: {target_hash}")
print()

# Crear diccionario local más completo
print("[*] Generando diccionario local...")

passwords = set()

# Palabras comunes CTF/Security
ctf_base = [
    "admin", "password", "flag", "ctf", "crackme", "unlock", "secret", "key",
    "hash", "cipher", "crypto", "security", "hack", "root", "user", "test",
    "challenge", "solve", "reverse", "engineering", "binary", "exploit",
    "buffer", "overflow", "injection", "xss", "sql", "rsa", "aes", "des",
    "sha256", "sha512", "md5", "base64", "hex", "encode", "decode", "encrypt",
    "decrypt", "brute", "force", "wordlist", "hacker", "attacker", "defender",
    "pwn", "gdb", "ida", "ghidra", "strace", "ltrace", "objdump", "strings",
    "file", "nm", "ldd", "readelf", "binwalk", "steganography", "forensic",
    "network", "protocol", "tcp", "udp", "dns", "http", "https", "ssh",
    "ftp", "smtp", "pop3", "imap", "telnet", "rlogin", "rsh", "snmp",
]

# Agregar al conjunto
for word in ctf_base:
    passwords.add(word)
    passwords.add(word.upper())
    passwords.add(word.capitalize())
    passwords.add(word + "123")
    passwords.add("123" + word)
    passwords.add(word + "!")
    passwords.add(word + "@123")
    passwords.add(word + "2024")
    passwords.add(word + "2025")

print(f"[*] Diccionario con {len(passwords)} contraseñas generadas")
print()

found = False
count = 0

for i, password in enumerate(sorted(passwords)):
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()
    count += 1
    
    if i % 100 == 0:
        print(f"[?] Probadas {count}... {password}")
    
    if sha256_hash == target_hash:
        print()
        print(f"[+] ¡¡¡ENCONTRADO!!! La contraseña es: '{password}'")
        print(f"[+] Hash SHA-256: {sha256_hash}")
        found = True
        break

if not found:
    print()
    print("[-] No encontrado en diccionario local mejorado")
    print(f"[*] Probadas {count} combinaciones")
    print()
    print("[*] ALTERNATIVAS:")
    print("1. Usar hashcat con rockyou.txt:")
    print("   hashcat -m 1400 hash.txt rockyou.txt")
    print()
    print("2. Buscar online en:")
    print("   - https://crackstation.net/")
    print("   - https://www.md5online.org/ (también SHA-256)")
    print("   - https://duckduckgo.com/?q=!<hash>")
    print()
    print("3. Usar john the ripper:")
    print("   echo 'fcf730b6d95236ecd3c9fc2d92d7b6b2bb061514961aec041d6c7a7192f592e44' > hash.txt")
    print("   john --format=raw-sha256 hash.txt")
    print()
    print(f"[*] Hash a buscar: {target_hash}")
