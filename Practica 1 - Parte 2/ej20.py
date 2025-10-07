from pwn import remote
from pathlib import Path
import subprocess, sys

HOST = "ic.catedras.linti.unlp.edu.ar"
PORT = 12003

base = Path(__file__).resolve().parent
archivo_txt = base / "encriptar.txt"
clave_pub  = base / "public.gpg"

subprocess.run(["gpg","--batch","--yes","--import", str(clave_pub)],
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

proc = subprocess.run(["gpg","--with-colons","--list-keys"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
fingerprint = next((l.split(":")[9] for l in proc.stdout.decode().splitlines() if l.startswith("fpr:")), None)


if not fingerprint:
    print("No se encontró fingerprint"); sys.exit(1)

p = subprocess.run(
    ["gpg","--batch","--yes","--trust-model","always","--encrypt","--armor","--recipient",fingerprint,"--output","-", str(archivo_txt)],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE
)
if p.returncode != 0:
    print("Error gpg:", p.stderr.decode(errors="ignore")); sys.exit(1)

armor = p.stdout.decode("utf-8", errors="ignore")


con = remote(HOST, PORT, timeout=5)
try:
    con.send(armor.encode())         
    respuesta = con.recvall(timeout=5)
    if respuesta:
        print(respuesta.decode(errors="ignore"))
except Exception as e:
    print("Ocurrió:", type(e).__name__, e)
finally:
    con.close()
