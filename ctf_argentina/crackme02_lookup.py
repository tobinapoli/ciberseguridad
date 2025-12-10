#!/usr/bin/env python3
# CRACKME-02 - Resolver el ejercicio sin hardcoding

import os
import hashlib

def extract_all_hashes_from_binary():
    """Extrae TODOS los posibles SHA-256 del binario"""
    
    print("[*] Extrayendo todos los posibles SHA-256 del binario...\n")
    
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        binary_path = os.path.join(script_dir, "crackme02")
        
        with open(binary_path, 'rb') as f:
            data = f.read()
        
        print(f"[+] Binario leído: {len(data)} bytes\n")
        
        hashes = []
        
        # Buscar TODOS los bloques de 32 bytes con buena entropía
        # (sin saber cuál es el correcto)
        for i in range(len(data) - 32):
            chunk = data[i:i+32]
            unique_bytes = len(set(chunk))
            
            # SHA-256 típicamente tiene > 24 bytes diferentes
            if unique_bytes > 24:
                # Verificar contexto
                context_start = max(0, i-300)
                context_end = min(len(data), i+300)
                context = data[context_start:context_end]
                
                if any(kw in context for kw in [b'admin', b'password', b'secret', b'verify']):
                    hex_chunk = chunk.hex()
                    hashes.append((i, hex_chunk, unique_bytes))
        
        return hashes
    
    except Exception as e:
        print(f"[-] Error: {e}")
        return []

def crack_hash_local(hash_value):
    """Intenta crackear el hash con diccionario local (palabras comunes)"""
    
    print(f"[*] Intentando crackear con diccionario local...\n")
    
    # Diccionario expandido de palabras comunes
    words = [
        # Clásicos/básicos
        "password", "admin", "123456", "secret", "letmein", "welcome",
        "monkey", "dragon", "master", "shadow", "sunshine", "qwerty",
        "12345", "123123", "password123", "admin123", "flag", "crack",
        "hash", "security", "password1", "admin1", "test", "test123",
        "root", "root123", "pass", "pass123", "1234567", "12345678",
        "secret123", "admin@123", "password@123", "123@admin",
        # Números y variaciones
        "111111", "666666", "888888", "999999", "1111111", "2222222",
        "0000000", "000000", "1234567890", "9876543210", "qwerty123",
        "123qwerty", "asdfgh", "zxcvbn", "password12", "pass@123",
        # Nombres y palabras comunes
        "john", "alex", "david", "michael", "robert", "james", "william",
        "richard", "joseph", "thomas", "charles", "daniel", "matthew",
        "anthony", "mark", "paul", "steven", "andrew", "kenneth",
        "maria", "mary", "patricia", "linda", "barbara", "elizabeth",
        "susan", "jessica", "sarah", "karen", "nancy", "lisa",
        # Palabras naturales
        "computer", "internet", "network", "server", "system", "database",
        "application", "software", "hardware", "program", "code", "debug",
        "compile", "execute", "function", "variable", "string", "integer",
        "boolean", "array", "object", "class", "method", "property",
        # Más palabras comunes
        "baseball", "football", "soccer", "hockey", "tennis", "basketball",
        "cricket", "volleyball", "swimming", "fishing", "hunting", "camping",
        "hiking", "cycling", "running", "walking", "jumping", "playing",
        # Números con texto
        "admin2024", "password2024", "user2024", "test2024", "admin2023",
        "password2023", "user2023", "test2023", "admin2022", "password2022",
        # Palabras con sufijos comunes
        "welcome123", "admin2021", "pass2024", "test2021", "root2024",
        "hacker", "hacker123", "hacker2024", "linux", "unix", "windows",
        "macos", "android", "iphone", "tablet", "laptop", "desktop",
        # Palabras más variadas
        "sunshine123", "moonlight", "starlight", "daylight", "midnight",
        "afternoon", "morning", "evening", "weekend", "weekday",
        "january", "february", "march", "april", "may", "june",
        "july", "august", "september", "october", "november", "december",
        # Colores y elementos
        "red", "blue", "green", "yellow", "orange", "purple", "pink",
        "black", "white", "gray", "brown", "silver", "gold",
        # Animales
        "cat", "dog", "bird", "fish", "lion", "tiger", "bear",
        "elephant", "zebra", "giraffe", "snake", "eagle", "wolf",
        # Frutas y alimentos
        "apple", "banana", "orange", "grape", "mango", "pear",
        "peach", "melon", "watermelon", "strawberry", "blueberry",
        # Deportes y actividades
        "sport", "game", "play", "win", "lose", "match", "team",
        "coach", "player", "champion", "medal", "trophy", "award",
        # Palabras técnicas
        "exploit", "vulnerability", "breach", "attack", "defense",
        "firewall", "antivirus", "malware", "virus", "worm", "trojan",
        # Más variaciones numéricas
        "12341234", "56785678", "11111111", "00000000", "99999999",
        "1q2w3e4r", "qweasd", "1234abcd", "abcd1234", "test@123",
        "admin@456", "pass@456", "password@2024", "admin#2024",
        # Palabras con números intercalados
        "p4ssw0rd", "p@ssw0rd", "4dm1n", "@dm1n", "t3st", "t35t",
        "h4ck3r", "h@ck3r", "s3cur1ty", "s3cur1ty123",
        # Palabras inglesas comunes adicionales
        "love", "hate", "happy", "sad", "angry", "calm", "cool",
        "hot", "cold", "warm", "bright", "dark", "light", "heavy",
        "fast", "slow", "quick", "quick123", "special", "unique",
        # Palabras relacionadas a sistemas
        "userpassword", "systemadmin", "root123456", "toor", "toor123",
        "password1234", "admin1234", "system123", "database123"
    ]
    
    for word in words:
        word_hash = hashlib.sha256(word.encode()).hexdigest()
        if word_hash == hash_value:
            print(f"[+] ¡ENCONTRADO!")
            print(f"[+] Contraseña: {word}\n")
            return word
    
    print("[-] No encontrado en diccionario local\n")
    return None

def main():
    print("[*] CRACKME-02 - Resolver el ejercicio\n")
    print("="*70)
    
    # Paso 1: Extraer TODOS los hashes (sin saber cuál es)
    all_hashes = extract_all_hashes_from_binary()
    
    if not all_hashes:
        print("[-] No se encontraron hashes")
        return
    
    print(f"[+] Se encontraron {len(all_hashes)} posibles SHA-256 en el binario\n")
    
    # Paso 2: Intentar crackear cada uno
    password = None
    for offset, hex_hash, entropy in all_hashes:
        print(f"\n[*] Probando hash en offset 0x{offset:x} (entropía: {entropy}/32)")
        print(f"    {hex_hash}")
        
        result = crack_hash_local(hex_hash)
        if result:
            password = result
            break
    
    print("="*70)
    
    if password:
        flag = f"UNLP{{{password}}}"
        print(f"\n[+] ¡EJERCICIO RESUELTO!")
        print(f"[+] Contraseña: {password}")
        print(f"[+] FLAG: {flag}\n")
        
        # Guardar
        with open("crackme02_flag.txt", "w") as f:
            f.write(f"Password: {password}\n")
            f.write(f"Flag: {flag}\n")
        
        print(f"[+] Resultado guardado en: crackme02_flag.txt")
    else:
        print("\n[-] No se pudo resolver con diccionario local")
        print("[*] Próximo paso: usa CrackStation o un diccionario más grande")

if __name__ == "__main__":
    main()
