from pwn import *
# context.log_level = 'debug'  # activalo si querés ver EXACTAMENTE qué manda el server

con = remote("ic.catedras.linti.unlp.edu.ar", 10001, timeout=5)

# Leer hasta los dos puntos que preceden a la cuenta, tolerando CRLF
con.recvuntil(b":")             # no dependemos del texto exacto del banner
con.recvuntil(b"\n")            # consumimos el salto de línea (puede venir \r\n)

# Ahora viene la línea con la cuenta (ej: b'297 + 155\n')
linea = con.recvline()
cuenta = linea.decode(errors="replace").strip()
# Por si viniera con más espacios o CRLF
partes = cuenta.split()         # ej: ['297', '+', '155']

op1 = int(partes[0])
op2 = int(partes[2])
op = partes[1]

if op == '+':
    res = op1 + op2
elif op == '*':
    res = op1 * op2
else:
    res = op1 - op2

# Enviar el resultado seguido de newline
con.sendline(str(res).encode())

# Leer la respuesta final (flag o confirmación) y mostrarla
print(con.recvall(timeout=2).decode(errors="replace"))
con.close()
