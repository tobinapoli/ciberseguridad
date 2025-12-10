#!/usr/bin/env python3
import os
import re
import sys

def extract_strings(file_path, min_length=4):
    """Extrae strings legibles de un binario (ELF, PE, etc)"""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        strings = re.findall(b'[ -~]{' + str(min_length).encode() + b',}', data)
        return [s.decode(errors='ignore') for s in strings]
    except Exception as e:
        print(f"[-] Error: {e}")
        return []

def find_flags(file_path):
    """Busca flags en formato UNLP{...} en un binario"""
    if not os.path.exists(file_path):
        print(f"[-] No encuentro '{file_path}'")
        return
    
    print(f"[*] Analizando: {os.path.basename(file_path)}")
    print("[*] Extrayendo strings...\n")
    
    strings_found = extract_strings(file_path, min_length=5)
    flags = []
    
    for s in strings_found:
        if re.match(r"UNLP\{.*\}", s):
            print(f"[+] {s}")
            flags.append(s)
    
    if not flags:
        print("[-] No se encontraron flags en formato UNLP{}")
    
    return flags

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_file = sys.argv[1]
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        target_file = os.path.join(script_dir, "windows_app.exe")
    
    find_flags(target_file)
