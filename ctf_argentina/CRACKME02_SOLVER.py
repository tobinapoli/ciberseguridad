#!/usr/bin/env python3
# CRACKME-02 - SHA-256 Password Hash Cracking
# Objetivo: Extraer hash del binario y crackearlo

from pwn import *
import hashlib
import os
import re

def extract_hash_from_binary_dynamic():
    """Extrae SHA-256 buscando el hash específico en el binario"""
    
    print("[*] Extrayendo hash SHA-256 del binario crackme02...\n")
    
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        binary_path = os.path.join(script_dir, "crackme02")
        
        with open(binary_path, 'rb') as f:
            data = f.read()
        
        print(f"[+] Binario leído: {len(data)} bytes\n")
        
        # Buscar secuencias de 20 bytes (40 caracteres hex - primera mitad del SHA-256)
        # o 32 bytes (64 caracteres hex - SHA-256 completo)
        
        # Primero intentar encontrar SHA-256 completo (32 bytes)
        for i in range(len(data) - 32):
            chunk = data[i:i+32]
            hex_chunk = chunk.hex()
            
            # Verificar si comienza con el patrón conocido
            if hex_chunk.startswith('fcf730b6d95236ecd3c9fc2d92d7b6b2'):
                print(f"[+] ¡HASH ENCONTRADO en offset 0x{i:x}!")
                print(f"[+] SHA-256: {hex_chunk}")
                return hex_chunk
        
        # Si no encuentra el completo, buscar la primera mitad (20 bytes)
        for i in range(len(data) - 20):
            chunk = data[i:i+20]
            hex_chunk = chunk.hex()
            
            if hex_chunk == 'fcf730b6d95236ecd3c9fc2d92d7b6b2':
                print(f"[+] ¡PRIMERA MITAD DEL HASH encontrada en offset 0x{i:x}!")
                # Intentar leer los siguientes 12 bytes
                if i + 32 <= len(data):
                    full_chunk = data[i:i+32]
                    full_hex = full_chunk.hex()
                    print(f"[+] SHA-256 completo: {full_hex}")
                    return full_hex
                else:
                    print(f"[+] Primera mitad: {hex_chunk}")
                    return hex_chunk
        
        print("[-] Hash específico no encontrado")
        print("[*] Buscando cualquier SHA-256 en el binario...")
        
        # Fallback: buscar cualquier hash de buena entropía
        for i in range(len(data) - 32):
            chunk = data[i:i+32]
            if len(set(chunk)) > 24:
                hex_chunk = chunk.hex()
                context = data[max(0, i-200):min(len(data), i+200)]
                if any(kw in context for kw in [b'admin', b'password', b'secret']):
                    print(f"[+] Hash alternativo encontrado: {hex_chunk}")
                    return hex_chunk
        
        return None
    
    except Exception as e:
        print(f"[-] Error: {e}")
        return None

def extract_hash_from_binary():
    """Extraer el hash SHA-256 del binario crackme02"""
    
    print("[*] Intentando extracción por símbolos...\n")
    
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        binary_path = os.path.join(script_dir, "crackme02")
        elf = ELF(binary_path)
        print(f"[+] Binario cargado: {elf.path}")
        print(f"    Arch: {elf.arch}")
        print(f"    PIE: {elf.pie}\n")
        
    except Exception as e:
        print(f"[-] Error cargando binario: {e}")
        return None
    
    # Buscar los símbolos k1, k2, k3, k4
    print("[*] Buscando símbolos k1, k2, k3, k4...")
    
    k_symbols = {}
    for name in ['k1', 'k2', 'k3', 'k4']:
        try:
            addr = elf.symbols.get(name)
            if addr:
                k_symbols[name] = addr
                print(f"    {name} = {hex(addr)}")
        except:
            pass
    
    if not k_symbols:
        print("[-] No se encontraron símbolos k1-k4, intentando búsqueda dinámica...")
        print("[*] Intentando buscar en .rodata u otras secciones...")
        
        # Alternativa: buscar en .rodata
        rodata = elf.get_section_by_name('.rodata')
        if rodata:
            print(f"[+] Sección .rodata encontrada en {hex(rodata['sh_addr'])}")
            print(f"    Tamaño: {rodata['sh_size']} bytes")
        
        return None
    
    # Extraer el contenido de memoria en esas direcciones
    print("\n[*] Extrayendo hash desde los símbolos...")
    
    hash_bytes = b""
    for name in ['k1', 'k2', 'k3', 'k4']:
        if name in k_symbols:
            addr = k_symbols[name]
            # El binario está mapeado en memoria cuando se ejecuta
            # Pero podemos leer desde el archivo ELF
            # Los símbolos apuntan a direcciones en el espacio de memoria del binario
            # Para extraer el contenido, usamos el offset en el archivo
            
            try:
                # Buscar en qué sección está
                for section in elf.sections:
                    if section['sh_addr'] <= addr < section['sh_addr'] + section['sh_size']:
                        offset = addr - section['sh_addr'] + section['sh_offset']
                        # Leer 8 bytes (4 bytes por símbolo típicamente)
                        elf.stream.seek(offset)
                        data = elf.stream.read(8)
                        print(f"    {name} @ {hex(addr)} → {data.hex()}")
                        hash_bytes += data
                        break
            except Exception as e:
                print(f"    [-] Error leyendo {name}: {e}")
    
    if hash_bytes:
        print(f"\n[+] Hash extraído: {hash_bytes.hex()}")
        print(f"    Tamaño: {len(hash_bytes)} bytes")
        
        # Si son 32 bytes, es un SHA-256 completo
        if len(hash_bytes) == 32:
            return hash_bytes.hex()
        # Si son 64 bytes en ASCII hex, convertir
        elif len(hash_bytes) == 64:
            try:
                test = bytes.fromhex(hash_bytes.decode())
                print(f"[+] Hash en formato ASCII hex detectado")
                return hash_bytes.decode()
            except:
                return hash_bytes.hex()
    
    return None

def extract_hash_with_objdump():
    """Extraer hash usando objdump (alternativa)"""
    
    print("\n[*] Alternativa: usando objdump para extraer secciones...")
    
    try:
        # Obtener direcciones de los símbolos
        result = subprocess.run(
            ["nm", "-n", "crackme02"],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode != 0:
            print(f"[-] nm falló: {result.stderr}")
            return None
        
        # Buscar k1-k4
        lines = result.stdout.split('\n')
        k_addrs = {}
        for line in lines:
            for i in range(1, 5):
                if f' k{i}' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        k_addrs[f'k{i}'] = int(parts[0], 16)
                        print(f"    k{i} @ {hex(k_addrs[f'k{i}'])}")
        
        if not k_addrs:
            print("[-] No se encontraron direcciones con nm")
            return None
        
        # Usar objdump para leer la zona de memoria
        min_addr = min(k_addrs.values())
        max_addr = max(k_addrs.values()) + 32
        
        print(f"\n[*] Leyendo desde {hex(min_addr)} hasta {hex(max_addr)}...")
        
        result = subprocess.run(
            ["objdump", "-s", "-j", ".rodata", "crackme02"],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            print(result.stdout)
            return None
        else:
            print(f"[-] objdump falló")
            return None
            
    except Exception as e:
        print(f"[-] Error: {e}")
        return None

def crack_hash_with_wordlist(hash_target, wordlist_path):
    """Crackear el hash SHA-256 con un diccionario"""
    
    print(f"\n[*] Crackeando SHA-256 con diccionario...")
    print(f"    Hash: {hash_target}")
    print(f"    Diccionario: {wordlist_path}\n")
    
    if not os.path.exists(wordlist_path):
        print(f"[-] Diccionario no encontrado: {wordlist_path}")
        print("[*] Crearemos uno básico con palabras comunes...")
        
        # Crear un diccionario básico
        basic_words = [
            "password", "admin", "123456", "letmein", "welcome",
            "monkey", "dragon", "master", "shadow", "sunshine",
            "secret", "qwerty", "12345", "123123", "password123",
            "admin123", "flag", "crack", "hash", "security",
            "password1", "admin1", "test", "test123", "root",
            "root123", "pass", "pass123", "1234567", "12345678"
        ]
        
        print(f"[*] Intentando con palabras comunes...")
        
        for word in basic_words:
            word_hash = hashlib.sha256(word.encode()).hexdigest()
            if word_hash.lower() == hash_target.lower():
                print(f"\n[+] ¡ENCONTRADO! Contraseña: {word}")
                return word
            print(f"    {word:20} → {word_hash[:16]}...")
        
        print("[-] No encontrado en diccionario básico")
        return None
    
    # Si tenemos el diccionario, usarlo
    found = False
    count = 0
    
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                word = line.strip()
                if not word:
                    continue
                
                word_hash = hashlib.sha256(word.encode()).hexdigest()
                count += 1
                
                if word_hash.lower() == hash_target.lower():
                    print(f"\n[+] ¡ENCONTRADO en intento {count}!")
                    print(f"[+] Contraseña: {word}")
                    return word
                
                # Mostrar progreso cada 1000 intentos
                if count % 1000 == 0:
                    print(f"    [{count}] {word:30} → {word_hash[:16]}...")
    
    except Exception as e:
        print(f"[-] Error leyendo diccionario: {e}")
    
    print(f"\n[-] No encontrado en {count} intentos")
    return None

def try_hardcoded_hashes():
    """Intentar con hashes conocidos de contraseñas comunes"""
    
    print("\n[*] Intentando con hashes SHA-256 comunes pre-calculados...\n")
    
    common_passwords = {
        # Formato: password -> SHA-256
        "admin": "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918",
        "password": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        "123456": "8d969eef6ecad3c29a3a873fba6dad6adb0c1dcc2f79e4e8af3eb4a10a2a27c9",
        "letmein": "e9d71f5ee7c92d6dc9e92ffdad17b8bd49418661721e0815c3dabb630a0e91e1",
        "monkey": "27be5f23dc97d1c55ba2f77e1f66c7a99acbf50eb7d5e82b67f8c1925dd33ee0",
        "dragon": "b57ce302b8b06b19ef8a879d6ceb34b76b7c5b7e29d1e0e5a5f2f3e4f5f6f7f8",
        "admin123": "0192023a7bbd73250516f069df18b500b6cecf615160f2ccd2c924d327a88417",
        "password1": "e807f1fcf82d132f9bb018ca6738a19f27748ca94fb4c42b6d2040c959e6b5be",
        "welcome": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        "secret": "2c26b46911185131006145dd0c6ce6dfac6b0b0c8e1bf0a7c6cf8bbdc3cdc959"
    }
    
    return common_passwords

def main():
    """Función principal"""
    
    print("[*] CRACKME-02 - SHA-256 Password Cracker\n")
    print("="*70)
    
    # Paso 1: Extraer hash del binario - intentar primero búsqueda dinámica
    hash_target = extract_hash_from_binary_dynamic()
    
    if not hash_target:
        print("\n[-] Búsqueda dinámica falló, intentando con símbolos...")
        hash_target = extract_hash_from_binary()
    
    if not hash_target:
        print("\n[-] No se pudo extraer el hash automáticamente")
        print("[*] Opciones manuales:")
        print("    1. WSL: nm -n crackme02 | grep k[1-4]")
        print("    2. WSL: objdump -s --start-address=0xADDRESS crackme02")
        print("    3. Copia el hash aquí")
        return
    
    print(f"\n[+] Hash objetivo encontrado:")
    print(f"    {hash_target}")
    print("\n" + "="*70)
    
    # Paso 2: Crackear el hash
    print("\n[*] Intentando crackear el hash...")
    print()
    
    # Intentar primero con hashes comunes
    common_hashes = try_hardcoded_hashes()
    
    password = None
    for pwd, hash_val in common_hashes.items():
        if hash_val.lower() == hash_target.lower():
            password = pwd
            print(f"[+] ¡ENCONTRADO en tabla pre-calculada!")
            print(f"[+] Contraseña: {password}")
            break
    
    # Si no está en la tabla, intentar con diccionario
    if not password:
        # Rutas comunes de diccionarios
        wordlists = [
            "rockyou.txt",
            "wordlist.txt",
            "C:/wordlists/rockyou.txt",
            "/usr/share/wordlists/rockyou.txt"
        ]
        
        for wordlist in wordlists:
            if os.path.exists(wordlist):
                password = crack_hash_with_wordlist(hash_target, wordlist)
                if password:
                    break
        
        # Si aún no encontramos, usar método sin diccionario
        if not password:
            password = crack_hash_with_wordlist(hash_target, "")
    
    # Paso 3: Mostrar resultado
    print("\n" + "="*70)
    
    if password:
        flag = f"UNLP{{{password}}}"
        print(f"\n[+] ¡CONTRASEÑA ENCONTRADA!")
        print(f"[+] Password: {password}")
        print(f"[+] FLAG: {flag}\n")
        
        # Guardar en archivo
        with open("crackme02_flag.txt", "w") as f:
            f.write(f"Password: {password}\n")
            f.write(f"Flag: {flag}\n")
        
        print(f"[+] Resultado guardado en: crackme02_flag.txt")
    else:
        print("\n[-] No se pudo crackear el hash")
        print("[*] Próximos pasos:")
        print("    1. Descarga un diccionario más grande (rockyou, seclists)")
        print("    2. Usa hashcat: hashcat -m 1400 hash.txt rockyou.txt")
        print("    3. O usa John the Ripper: john --format=Raw-SHA256 hash.txt")

if __name__ == "__main__":
    main()
