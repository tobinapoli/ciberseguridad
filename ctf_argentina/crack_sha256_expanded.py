#!/usr/bin/env python3
import hashlib
import requests
import json

# Hash encontrado en el binario
target_hash = "fcf730b6d95236ecd3c9fc2d92d7b6b2bb061514961aec041d6c7a7192f592e44"

print("[*] Intentando reverse lookup del SHA-256...")
print(f"[*] Hash objetivo: {target_hash}")
print()

# Intentar con apiOnline ht[hashcrack.com](hashcrack.com) (sin API key)
urls = [
    f"https://hash.online-convert.com/sha256-generator",  # No es reverse, pero puede ayudar
]

print("[*] Probando diccionarios locales extendidos...")

# Diccionario expandido
passwords_expanded = [
    "password", "admin", "123456", "password123", "admin123", "ctf", "flag", "crackme",
    "secret", "test", "letmein", "monkey", "dragon", "master", "password1", "admin@123",
    "1234567890", "qwerty", "changeme", "12345678", "security", "welcome", "sunshine",
    "football", "123123", "1q2w3e4r", "passw0rd", "P@ssword", "abc123", "shadow",
    # Agregando más
    "root", "toor", "pass", "pass123", "admin123", "user", "test123", "temp",
    "password@123", "123", "1234", "12345", "123456789", "1234567",
    "admin1", "user123", "root123", "tester", "adminadmin", "testtest",
    "demo", "demo123", "guest", "guest123", "login", "login123",
    "default", "default123", "sys", "system", "admin123456",
    "unlock", "unlock123", "crackme123", "ctf123", "flag123",
    "security123", "password!", "admin!", "test!", "pass@123",
    "11111111", "22222222", "33333333", "444444444", "555555555",
    "666666666", "777777777", "888888888", "999999999", "0000000000",
]

found = False
for i, password in enumerate(passwords_expanded):
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()
    
    if i % 10 == 0:
        print(f"[?] Probando... {password:20} ({i+1}/{len(passwords_expanded)})")
    
    if sha256_hash == target_hash:
        print()
        print(f"[+] ¡ENCONTRADO! La contraseña es: {password}")
        print(f"[+] Hash SHA-256: {sha256_hash}")
        found = True
        break

if not found:
    print()
    print("[-] No se encontró con diccionarios locales")
    print("[*] El hash podría ser de una contraseña custom o requiere fuerza bruta")
    print(f"[*] Hash para buscar online: {target_hash}")
