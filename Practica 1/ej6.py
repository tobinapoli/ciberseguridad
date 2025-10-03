from pwn import *
from hashlib import md5




con = remote("ic.catedras.linti.unlp.edu.ar", 11006, timeout=5)
try:
    raw = con.recvuntil(b"palabra:\n", timeout=3)
    print(raw.decode(errors="replace"))  # muestra la versión como texto
    word_line = con.recvline(timeout=3)
    print(word_line) # Linea en bytes
    word = word_line.decode(errors="replace").strip()
    print("Palabra:", word)
    valor = md5(word.encode()).hexdigest()
    con.sendline(valor)
    
    respuesta = con.recvall(timeout=3)
    if respuesta:
        print(respuesta.decode(errors="replace"))
except Exception as e:
    print("Ocurrió:", type(e).__name__, e)
finally:
    con.close()