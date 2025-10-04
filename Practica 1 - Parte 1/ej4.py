from pwn import remote
import re, string

HOST = "ic.catedras.linti.unlp.edu.ar"
PORT = 11004

def rot_n(text, n):
    n = n % 26
    abc = string.ascii_lowercase
    ABC = string.ascii_uppercase
    trans = str.maketrans(abc + ABC, abc[n:] + abc[:n] + ABC[n:] + ABC[:n])
    return text.translate(trans)

con = remote(HOST, PORT, timeout=8)
try:
    banner = con.recvuntil(b"frase:\n", timeout=5).decode(errors="ignore")
    m = re.search(r'\bROT\s*[:\-]?\s*(\d{1,3})\b', banner, flags=re.IGNORECASE)
    if not m:
        raise ValueError("No se encontró número ROT en el banner:\n" + banner)
    rot_num = int(m.group(1))
    print("ROT detectado:", rot_num)

    frase = con.recvline(timeout=3).decode(errors="ignore").strip()
    print("Frase recibida:", frase)

    respuesta = rot_n(frase, rot_num)
    con.sendline(respuesta.encode())
    print("Envié:", respuesta)
    print(con.recvall(timeout=2).decode(errors="ignore"))
finally:
    con.close()
