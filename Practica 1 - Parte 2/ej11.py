from pwn import remote
import re
from itertools import cycle

HOST, PORT = "ic.catedras.linti.unlp.edu.ar", 11015
con = remote(HOST, PORT, timeout=5)

def xor_rep(d,k): return bytes(b ^ k[i % len(k)] for i,b in enumerate(d))

try:
    con.recvuntil(b"la primer palabra es:\n", timeout=5)
    line = con.recvline().decode(errors="replace").strip()
    hexs = con.recvline().decode(errors="replace").strip()
    crib = re.search(r'([A-Za-zÑñÁÉÍÓÚáéíóú]+)', line).group(1).encode()
    ct = bytes.fromhex(re.search(r'[0-9a-fA-F]+', hexs).group(0))

    for pos in range(len(ct)-len(crib)+1):
        key = [None]*4; ok=True
        for i,ch in enumerate(crib):
            p=(pos+i)%4; cand = ct[pos+i]^ch
            if key[p] is None: key[p]=cand
            elif key[p]!=cand: ok=False; break
        if not ok or any(k is None for k in key): continue
        keyb = bytes(key); pt = xor_rep(ct, keyb)
        if pt[pos:pos+len(crib)]==crib:
            print("Clave:", keyb)
            print(pt.decode(errors="replace"))
            con.sendline(pt)
            respuesta = con.recvall(timeout=5)
            if respuesta:
                print(respuesta.decode(errors="replace"))

finally:
    con.close()
