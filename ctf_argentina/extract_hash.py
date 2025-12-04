#!/usr/bin/env python3
"""
CRACKME-02 - Extractor de Hash SHA-256
Solo extrae el hash del binario, sin guardar nada
"""

from pwn import *

context.arch = "amd64"

try:
    elf = ELF("crackme02")
    
    # Obtener direcciones de k1, k2, k3, k4
    k_symbols = {}
    for name in ['k1', 'k2', 'k3', 'k4']:
        addr = elf.symbols.get(name)
        if addr:
            k_symbols[name] = addr
    
    # Extraer bytes desde los símbolos
    hash_bytes = b""
    for name in ['k1', 'k2', 'k3', 'k4']:
        if name in k_symbols:
            addr = k_symbols[name]
            for section in elf.sections:
                if section['sh_addr'] <= addr < section['sh_addr'] + section['sh_size']:
                    offset = addr - section['sh_addr'] + section['sh_offset']
                    elf.stream.seek(offset)
                    data = elf.stream.read(8)
                    hash_bytes += data
                    break
    
    # Devolver el hash en hexadecimal
    hash_hex = hash_bytes.hex()
    print(hash_hex)

except Exception as e:
    print(f"Error: {e}", file=__import__('sys').stderr)
