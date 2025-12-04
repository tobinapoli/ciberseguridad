#!/usr/bin/env python3
"""
Script para probar el desafío del archivo .pyc
Decompilado:
- get_passwd(): pide contraseña
- check(s): verifica contra "0w5" + "r" y manipulación de índices
- get_secret(k): desencripta un secreto con AES-CBC
"""

import binascii
from Crypto.Cipher import AES
import time

# Constantes del archivo original
y = "0w5r"
secret_hex = "f92d0786425761806008f985a2fcc4a1f04e142b6b7dadd0998083c35135dc21"
iv = b"thisIsNotTheFlag"

def get_passwd():
    """Obtener contraseña del usuario"""
    return input("Password: ")

def check(s):
    """
    Verificar la contraseña
    Lógica original:
    z = "0w5r"
    x = s[1:2] + s[4:5] + s[2:3] + s[3:4] + s[5:6] + s[0:1] + s[6:7][::-1]
    return x == z
    """
    z = y  # "0w5r"
    
    # Reordenar caracteres según índices
    try:
        x = s[1:2] + s[4:5] + s[2:3] + s[3:4] + s[5:6] + s[0:1] + s[6:7][::-1]
    except:
        return False
    
    print(f"[*] Input: {s}")
    print(f"[*] Reordenado: {x}")
    print(f"[*] Esperado: {z}")
    
    return x == z

def get_secret(k):
    """
    Desencriptar el secreto con AES-CBC
    k: clave (contraseña)
    """
    try:
        key = binascii.unhexlify(secret_hex)
        key_material = (k * 2).encode('utf-8')  # Expandir clave
        
        # Usar solo los primeros 32 bytes como clave AES-256
        key = key_material[:32]
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(key)
        
        return decrypted.decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"[-] Error desencriptando: {e}")
        return None

def solve():
    """Resolver el desafío"""
    
    print("[*] Desafío: encontrar contraseña que cumpla check()\n")
    
    # La lógica de check es:
    # s[1] + s[4] + s[2] + s[3] + s[5] + s[0] + s[6][::-1] == "0w5r"
    # 
    # Entonces si queremos "0w5r":
    # s[1] = '0'
    # s[4] = 'w'
    # s[2] = '5'
    # s[3] = 'r'
    # s[5] = ? (sin usar)
    # s[0] = ? (sin usar)
    # s[6][::-1] = ? (sin usar, o debe ser reversible)
    #
    # Intentemos: s = "?0r5?w??"
    
    candidates = [
        "r0r5aw11",
        "a0r5bw22",
        "b0r5cw33",
        "c0r5dw44",
        "d0r5ew55",
        "e0r5fw66",
        "f0r5gw77",
        "g0r5hw88",
        "h0r5iw99",
        "i0r5jw00",
        "j0r5kw11",
        # Más sistemático
        "x0r5yw1z",
        "a0r5bwcd",
    ]
    
    # También probar fuerza bruta simple
    print("[*] Probando contraseñas candidatas...\n")
    
    for pwd in candidates:
        if len(pwd) >= 7:
            result = check(pwd)
            if result:
                print(f"\n[+] ¡ENCONTRADA! Contraseña: {pwd}")
                
                # Desencriptar el secreto
                print(f"\n[*] Desencriptando secreto...")
                secret = get_secret(pwd)
                if secret:
                    print(f"[+] Secreto: {secret}")
                    print(f"[+] FLAG: {secret}")
                
                return pwd
            print()
    
    # Si no se encontró, pedir al usuario
    print("\n[*] Ingresa una contraseña manualmente:")
    pwd = get_passwd()
    
    if check(pwd):
        print(f"\n[+] ¡Contraseña correcta!")
        secret = get_secret(pwd)
        if secret:
            print(f"[+] Secreto: {secret}")
            print(f"[+] FLAG: {secret}")
        return pwd
    else:
        print("[*] Esperando 1 segundo...")
        time.sleep(1)
        print("Invalid password!")
        return None

if __name__ == "__main__":
    print("="*70)
    print("Script para resolver el desafío del .pyc")
    print("="*70)
    print()
    
    solve()
