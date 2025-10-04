from pwn import *
from Crypto.Util.number import long_to_bytes
import sympy

HOST = "ic.catedras.linti.unlp.edu.ar"
PORT = 11017

con = remote(HOST, PORT, timeout=5)

try:
    con.recvuntil(b"texto:\n", timeout=3)
    n = int(con.recvline(timeout=3).decode(errors="replace").strip().split("=", 1)[1].strip())
    e = int(con.recvline(timeout=3).decode(errors="replace").strip().split("=", 1)[1].strip())
    c = int(con.recvline(timeout=3).decode(errors="replace").strip().split("=", 1)[1].strip())
    p, q = sympy.factorint(n)
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    m = pow(c, d, n)
    m_bytes = long_to_bytes(m)
    con.sendline(m_bytes)
    respuesta = con.recvall(timeout=3)
    if respuesta:
        print(respuesta.decode(errors="replace"))
    
except Exception as e:
    print("Ocurrió:", type(e).__name__, e)
finally:
    con.close()
    