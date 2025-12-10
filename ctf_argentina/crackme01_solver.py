#!/usr/bin/env python3
import os
import re

def extract_strings(file_path, min_length=4):
    """Extrae strings legibles de un binario ELF"""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Buscar todas las secuencias de caracteres imprimibles
        strings = re.findall(b'[ -~]{' + str(min_length).encode() + b',}', data)
        return [s.decode(errors='ignore') for s in strings]
    except Exception as e:
        print(f"[-] Error leyendo el archivo: {e}")
        return []

def solve_crackme01():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    crackme_path = os.path.join(script_dir, "crackme01")
    
    if not os.path.exists(crackme_path):
        print("[-] No encuentro 'crackme01' en la carpeta")
        return
    
    print("[*] Extrayendo strings del binario...")
    strings_found = extract_strings(crackme_path, min_length=5)
    
    print("[*] Buscando flag en formato UNLP{}...\n")
    
    for s in strings_found:
        if re.match(r"UNLP\{.*\}", s):
            print(f"[+] Flag encontrada: {s}")
            return s
    
    print("[-] No se encontró ninguna flag en formato UNLP{}")

if __name__ == "__main__":
    solve_crackme01()
