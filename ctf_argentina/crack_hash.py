#!/usr/bin/env python3
"""
Crackear SHA-256: fcf730b6d95236ecd3c9fc2d92d7b6b2bb061514961aec041d6c7a7192f592e4

Script auxiliar para intentar crackear con un diccionario expandido
"""

import hashlib

hash_target = "fcf730b6d95236ecd3c9fc2d92d7b6b2bb061514961aec041d6c7a7192f592e4"

# Diccionario expandido con variaciones comunes
wordlist = [
    # Contraseñas por defecto/simples
    "password", "admin", "123456", "letmein", "welcome", "monkey", "dragon", 
    "master", "shadow", "sunshine", "secret", "qwerty", "test", "root",
    
    # Variaciones numéricas
    "password1", "password12", "password123", "password1234", "password123456",
    "admin1", "admin12", "admin123", "admin1234",
    "root1", "root12", "root123", "root1234",
    
    # Con números al final
    "123456789", "1234567890", "12345", "1234", "12345678",
    
    # Palabras comunes + números
    "test1", "test12", "test123", "test1234",
    "pass", "pass1", "pass12", "pass123", "pass1234", "pass123456",
    
    # Palabras temáticas
    "flag", "crack", "hash", "security", "cipher", "crypto",
    "hack", "hacker", "network", "server", "database",
    
    # Strings cortos
    "a", "ab", "abc", "abcd", "abcdef",
    "user", "username", "login", "pwd", "passwd",
    
    # Palabras capítalizadas
    "Admin", "Admin123", "Password", "Password123", "Welcome", "Secret",
    
    # Combinaciones aleatorias típicas de CTF
    "flag123", "ctf", "ctf123", "capture", "flag", "unlp", "unlp123",
    "crackme", "crackme02", "crackme123",
    
    # Palabras en español
    "contraseña", "bandera", "seguridad", "clave", "secreto",
    
    # Más diccionario
    "princess", "123123", "superman", "batman", "iloveyou", "starwars",
    "chocolate", "shadow123", "sunshine123", "welcome123", "letmein123",
    "master123", "dragon123", "monkey123", "football", "baseball",
    "soccer", "hockey", "basketball", "tennis", "swimming",
    
    # Palabras comunes en inglés
    "hello", "world", "hello123", "world123", "python", "java", "javascript",
    "ruby", "golang", "rust", "cpp", "c", "linux", "windows", "macos",
]

print(f"[*] Intentando crackear: {hash_target}\n")
print(f"[*] Diccionario: {len(wordlist)} palabras\n")

count = 0
found = False

for word in wordlist:
    word_hash = hashlib.sha256(word.encode()).hexdigest()
    count += 1
    
    if word_hash.lower() == hash_target.lower():
        print(f"\n[+] ¡¡¡ENCONTRADO!!!")
        print(f"[+] Palabra #{count}: {word}")
        print(f"[+] SHA-256: {word_hash}")
        print(f"\n[+] FLAG: UNLP{{{word}}}\n")
        
        with open("crackme02_result.txt", "w") as f:
            f.write(f"Password: {word}\n")
            f.write(f"SHA-256: {word_hash}\n")
            f.write(f"Flag: UNLP{{{word}}}\n")
        
        print("[+] Resultado guardado en crackme02_result.txt")
        found = True
        break
    
    if count % 50 == 0:
        print(f"    [{count:3d}] Probado: {word:20s} → {word_hash[:16]}...")

if not found:
    print(f"\n[-] No encontrado en {count} palabras")
    print("[*] El hash puede requerir un diccionario más grande")
    print("[*] Descarga rockyou.txt o seclists para más palabras")
