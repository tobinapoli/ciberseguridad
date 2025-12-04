from pwn import *
from hashlib import sha256

"El servidor informa el hash SHA-256 de una contraseña. El servicio pide que se crackee y devuelva la password que se usó para generarlo. Pista: La password está entre las primeras 100 passwords del diccionario rockyou."

HOST = "ic.catedras.linti.unlp.edu.ar"
PORT = 11007

rockyou = Path(__file__).resolve().parent/"rockyou.txt"

hashmap = {}

for line in open(rockyou, "r", errors="ignore").readlines()[:100]:
    word = line.strip()
    valor = sha256(word.encode()).hexdigest()
    hashmap[valor] = word




con = remote(HOST, PORT, timeout=5)

try:
    raw = con.recvuntil(b":\n", timeout=3)
    print(raw.decode(errors="replace"))
    line = con.recvline(timeout=3)
    print(line.decode())
    valorAEnviar = hashmap.get(line.decode().strip(), "no_encontrado")
    con.sendline(valorAEnviar)
    respuesta = con.recvall(timeout=3)
    if respuesta:
        print(respuesta.decode(errors="replace"))
    
    
            
        
    

except Exception as e:
    print("Ocurrió:", type(e).__name__, e)
finally:
    con.close()