from pwn import *
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, inverse

HOST = "ic.catedras.linti.unlp.edu.ar"
PORT = 11012

con = remote(HOST, PORT, timeout=5)

try:
    con.recvuntil(b"texto:\n", timeout=3)
    p = int(con.recvline(timeout=3).decode(errors="replace").strip().split("=", 1)[1].strip())
    q = int(con.recvline(timeout=3).decode(errors="replace").strip().split("=", 1)[1].strip())
    e = int(con.recvline(timeout=3).decode(errors="replace").strip().split("=", 1)[1].strip())
    c = int(con.recvline(timeout=3).decode(errors="replace").strip().split("=", 1)[1].strip())
    n = p * q
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    m = pow(c, d, n)
    m_bytes = long_to_bytes(m)
    print("Mensaje (ASCII ignorando errores):", m_bytes.decode(errors="ignore"))
    
    con.sendline(m_bytes)
    respuesta = con.recvall(timeout=3)
    if respuesta:
        print(respuesta.decode(errors="replace"))
    
except Exception as e:
    print("Ocurrió:", type(e).__name__, e)
finally:
    con.close()