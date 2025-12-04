#!/usr/bin/env python3
"""
RETOSF - Offset Discovery Script

Este script descubre automáticamente:
1. El offset en el que el printf comienza a leer nuestro input (%x para leak)
2. El offset entre el buffer y el return address en el stack

Pasos:
1. Se ejecuta localmente
2. Envía payloads con %x para leer la stack
3. Compara output y deduce dónde está el buffer y dónde el return
"""

from pwn import *

context.arch = "i386"
context.log_level = "WARNING"

def discover_offsets():
    """
    Ejecuta un exploit local simulado para descubrir los offsets.
    
    Envía: AAAA.%x.%x.%x.%x.%x.%x.%x.%x
    Recibe en printf: todo eso con %x reemplazado por los valores en stack
    
    Con FmtStr, podemos automatizar todo.
    """
    
    print("[*] Intentando cargar el binario compilado...")
    try:
        elf = ELF("retosf")
        print(f"[+] Binario cargado: {elf.path}")
        print(f"    Arch: {elf.arch}")
        print(f"    PIE: {elf.pie}")
        
        win_addr = elf.symbols.get('win')
        vuln_addr = elf.symbols.get('vuln')
        main_addr = elf.symbols.get('main')
        
        print(f"    win()  = {hex(win_addr) if win_addr else 'NOT FOUND'}")
        print(f"    vuln() = {hex(vuln_addr) if vuln_addr else 'NOT FOUND'}")
        print(f"    main() = {hex(main_addr) if main_addr else 'NOT FOUND'}")
        
        # Listar símbolos disponibles
        print("\n[*] Símbolos en el binario:")
        for sym in ['win', 'vuln', 'main', 'printf', 'fgets', 'exit', 'puts']:
            addr = elf.symbols.get(sym)
            if addr:
                print(f"    {sym:15} = {hex(addr)}")
        
        return True
        
    except FileNotFoundError:
        print("[-] No se encontró 'retosf' en el directorio actual")
        print("[*] Necesitas compilar el binario con:")
        print("    gcc code-bfs.c -w -O0 -std=c99 -fno-pie -fno-stack-protector -z norelro -z execstack -o retosf")
        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("[*] RETOSF - Offset Discovery Tool\n")
    discover_offsets()
