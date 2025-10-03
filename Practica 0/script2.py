from pwn import *
import re
import time

# context.log_level = 'debug'   # descomentá para ver el byte-stream si necesitás debug

HOST = "ic.catedras.linti.unlp.edu.ar"
PORT = 10002

con = remote(HOST, PORT, timeout=5)

# Consumir intro hasta los ":" que antecede a la 1ra cuenta
con.recvuntil(b":")
con.recvuntil(b"\n")

# Regex para operaciones (en bytes)
pat = re.compile(rb'(-?\d+)\s*([+\-*])\s*(-?\d+)')

# Regex para prompts que queremos IGNORAR (evita prints repetidos)
ignore_prompts = re.compile(rb'^(Correcto! A resolver![:]*\s*)+$', re.I)

buffer = b''
last_math_time = time.time()
MAX_IDLE = 30.0   # si pasan MAX_IDLE segundos sin una operación, salimos

try:
    while True:
        # recibir chunk (espera hasta timeout)
        try:
            chunk = con.recv(timeout=5)
        except EOFError:
            break
        if not chunk:
            # si el servidor no envía nada más -> terminar
            break

        buffer += chunk

        # Si el buffer contiene sólo prompts repetidos -> no imprimirlos ni resetear timers
        if ignore_prompts.fullmatch(buffer.strip()):
            # vaciar buffer (ya lo ignoramos)
            buffer = b''
            # seguimos esperando sin resetear last_math_time
            continue

        # procesar todas las operaciones encontradas
        any_math = False
        for m in pat.finditer(buffer):
            any_math = True
            a = int(m.group(1))
            op = m.group(2).decode()
            b = int(m.group(3))

            if op == '+':
                res = a + b
            elif op == '*':
                res = a * b
            else:
                res = a - b

            # enviar la respuesta YA
            con.sendline(str(res).encode())

            # actualizar tiempo de última operación procesada
            last_math_time = time.time()

        # quitar del buffer lo que ya procesamos (todo hasta la última coincidencia)
        last = 0
        for m in pat.finditer(buffer):
            last = m.end()
        if last:
            buffer = buffer[last:]
        else:
            # Si no había operaciones, imprimimos mensajes útiles (no repetidos)
            text = buffer.decode(errors='replace').strip()
            if text:
                # Evitar spam: imprimimos sólo si no es el prompt repetido
                print(text)
            buffer = b''

        # Si hace demasiado que no llegan operaciones, terminamos para no quedar en loop
        if time.time() - last_math_time > MAX_IDLE:
            print(f"No se recibieron operaciones en los últimos {MAX_IDLE} s — cerrando.")
            break

except KeyboardInterrupt:
    print("Interrumpido por usuario.")
except EOFError:
    print("Servidor cerró la conexión.")
finally:
    # recibir lo que quede (flag/mensaje final)
    try:
        resto = con.recvall(timeout=2)
        if resto:
            print(resto.decode(errors='replace'))
    except Exception:
        pass
    con.close()
