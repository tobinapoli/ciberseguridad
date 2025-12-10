#!/usr/bin/env python3
"""
Titanic 100 - Reverse Engineering + Criptografía
Categoría: Reverse Engineering (Python Bytecode)

Objetivo: Recuperar la flag mediante:
1. Análisis estático del .pyc para encontrar la contraseña
2. Desencriptar AES-CBC con la contraseña encontrada
"""

from Crypto.Cipher import AES as AES_Cipher
import binascii

def reverse_engineer_password():
    
    print("[*] Analizando función de validación...")
    
    # Constante encontrada en el bytecode
    z = '0w5s4Pdr'
    
    # Paso 1: Deshacer el reverse
    reconstructed = z[::-1]  # 'rdP4s5w0'
    print(f"[*] Después de deshacer reverse: {reconstructed}")
    
    # Paso 2: Mapear fragmentos
    # El código hace: s[6:8] + s[0:3] + s[3:6]
    # Nuestro 'reconstructed' está en ese orden
    fragment1 = reconstructed[0:2]    # s[6:8] = 'rd'
    fragment2 = reconstructed[2:5]    # s[0:3] = 'P4s'
    fragment3 = reconstructed[5:8]    # s[3:6] = '5w0'
    
    print(f"[*] Fragmento 1 (s[6:8]): {fragment1}")
    print(f"[*] Fragmento 2 (s[0:3]): {fragment2}")
    print(f"[*] Fragmento 3 (s[3:6]): {fragment3}")
    
    # Paso 3: Reconstruir en orden de índices
    password = fragment2 + fragment3 + fragment1
    print(f"[+] Contraseña recuperada: {password}\n")
    
    return password

def decrypt_flag(password):
    """
    Desencripta el payload AES-CBC
    
    Parámetros:
    - Key: Contraseña repetida 2 veces (para llegar a 16 bytes)
    - IV: 'thisIsNotTheFlag'
    - Ciphertext: Hexadecimal
    """
    
    print("[*] Desencriptando payload AES...")
    
    # Configuración criptográfica extraída del análisis
    key = (password * 2).encode('utf-8')
    iv = b'thisIsNotTheFlag'
    
    # Ciphertext en hexadecimal
    hex_ciphertext = 'f92d0786425761806008f985a2fcc4a1f04e142b6b7dadd0998083c35135dc21'
    ciphertext = binascii.unhexlify(hex_ciphertext)
    
    print(f"[*] Key (32 bytes): {key}")
    print(f"[*] IV (16 bytes): {iv}")
    print(f"[*] Ciphertext: {hex_ciphertext}\n")
    
    try:
        # AES en modo CBC
        cipher = AES_Cipher.new(key, AES_Cipher.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)
        
        # Eliminar padding y decodificar
        # Buscar el último carácter imprimible
        flag = decrypted.decode('utf-8', errors='ignore')
        flag = flag.rstrip('\x00').split('}')[0] + '}'
        
        return flag
        
    except Exception as e:
        print(f"[-] Error en desencriptación: {e}")
        return None

def main():
    print("[*] Titanic 100 - Python Reverse Engineering\n")
    print("="*70)
    
    # Paso 1: Recuperar contraseña
    password = reverse_engineer_password()
    
    # Paso 2: Desencriptar flag
    print("="*70)
    flag = decrypt_flag(password)
    
    print("="*70)
    if flag:
        print(f"\n[+] FLAG ENCONTRADA:")
        print(f"    {flag}\n")
        
        # Guardar resultado
        with open("titanic_flag.txt", "w") as f:
            f.write(f"Contraseña: {password}\n")
            f.write(f"Flag: {flag}\n")
        
        print(f"[+] Resultado guardado en: titanic_flag.txt")
    else:
        print("[-] No se pudo obtener la flag")

if __name__ == "__main__":
    main()
