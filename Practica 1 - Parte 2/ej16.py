from pwn import *

HOST = "ic.catedras.linti.unlp.edu.ar"
PORT = 11018

con = remote(HOST, PORT, timeout=5)
try:
    con.recvuntil(b"Hellman:\n", timeout=3)
    p = int(con.recvline(timeout=3).decode(errors="replace").strip().split("=", 1)[1].strip())
    g = int(con.recvline(timeout=3).decode(errors="replace").strip().split("=", 1)[1].strip())
    public_alice = int(con.recvline(timeout=3).decode(errors="replace").strip().split("=", 1)[1].strip())
    private_bob = int(con.recvline(timeout=3).decode(errors="replace").strip().split("=", 1)[1].strip())
    clave = pow(public_alice, private_bob, p)
    con.sendline(str(clave).encode())
    respuesta = con.recvall(timeout=3)
    if respuesta:
        print(respuesta.decode(errors="replace"))
    
    
except Exception as e:
    print("Ocurrió:", type(e).__name__, e)
finally:
    con.close()
