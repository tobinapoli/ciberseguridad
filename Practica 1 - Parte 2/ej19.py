# brute_gpg_simple_multithread_exact.py
from pathlib import Path
import subprocess, sys
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

here = Path(__file__).resolve().parent
dic_path = here / "diccionario"
flag_path = here / "flag.txt.gpg"
out_path = here / "flag_decrypted.txt"

if not dic_path.exists():
    print("No encuentro el diccionario:", dic_path); sys.exit(1)
if not flag_path.exists():
    print("No encuentro el flag:", flag_path); sys.exit(1)

with dic_path.open("r", encoding="utf-8", errors="ignore") as f:
    palabras = [l.rstrip("\n") for l in f if l.rstrip("\n")]

if not palabras:
    print("Diccionario vacío."); sys.exit(1)

total = len(palabras)
MAX_WORKERS = 5
TIMEOUT = 8

def worker_try(i, pw, flag_path):
    """
    Prueba exactamente la pass `pw` usando UTF-8 (NO modifica case ni hace variantes).
    Devuelve (i, pw, returncode, stdout_bytes, stderr_bytes) o rc None en timeout.
    """
    try:
        p = subprocess.run(
            ["gpg", "--batch", "--yes", "--pinentry-mode", "loopback",
             "--passphrase-fd", "0", "--decrypt", str(flag_path)],
            input=(pw + "\n").encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=TIMEOUT
        )
        return (i, pw, p.returncode, p.stdout, p.stderr)
    except subprocess.TimeoutExpired:
        return (i, pw, None, b"", b"TIMEOUT")

it = iter(enumerate(palabras, start=1))
in_flight = {}   # future -> (i,pw)
tried = 0

try:
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        for _ in range(MAX_WORKERS):
            try:
                i, pw = next(it)
            except StopIteration:
                break
            print(f"[{i}/{total}] Probando: {pw}", flush=True)
            fut = ex.submit(worker_try, i, pw, flag_path)
            in_flight[fut] = (i, pw)

        while in_flight:
            done, _ = wait(in_flight.keys(), return_when=FIRST_COMPLETED)
            for fut in done:
                i, pw = in_flight.pop(fut)
                try:
                    i_ret, pw_ret, rc, outb, errb = fut.result()
                except Exception as e:
                    print(f"[ERR] {pw} -> exception: {e}", flush=True)
                    rc = None
                    outb = b""
                    errb = str(e).encode("utf-8", errors="ignore")

                tried += 1

                if rc is None:
                    print(" -> timeout (saltando)", flush=True)
                else:
                    if rc == 0 and outb:
                        texto = outb.decode(errors="ignore")
                        if "IC{" in texto or "flag{" in texto.lower() or "CTF{" in texto:
                            print(f"\n***** PASS FOUND: {pw_ret} *****\n", flush=True)
                            print(texto, flush=True)
                            with open(out_path, "w", encoding="utf-8", errors="ignore") as of:
                                of.write(texto)
                            for f in list(in_flight):
                                try:
                                    f.cancel()
                                except Exception:
                                    pass
                            sys.exit(0)
                        else:
                            texto = outb.decode(errors="ignore")
                            printable = sum(1 for ch in texto if 32 <= ord(ch) < 127)
                            if len(texto) > 0 and printable / max(1, len(texto)) > 0.6 and len(texto) > 10:
                                maybe = here / f"maybe_{i}.txt"
                                print(f" -> salida legible sin tag. Guardada en {maybe}", flush=True)
                                with maybe.open("w", encoding="utf-8", errors="ignore") as mf:
                                    mf.write(texto)
                            else:
                                print(f"[DONE] {pw_ret} -> no", flush=True)
                    else:
                        print(f"[DONE] {pw_ret} -> no", flush=True)

                try:
                    i2, pw2 = next(it)
                    print(f"[{i2}/{total}] Probando: {pw2}", flush=True)
                    fut2 = ex.submit(worker_try, i2, pw2, flag_path)
                    in_flight[fut2] = (i2, pw2)
                except StopIteration:
                    pass

                if tried % 500 == 0:
                    print(f"Probadas {tried} palabras...", flush=True)

        print("Terminó: no se encontró pass en el diccionario.", flush=True)

except KeyboardInterrupt:
    print("\nInterrumpido por usuario (Ctrl+C). Cancelando...", flush=True)
    try:
        for fut in list(in_flight):
            fut.cancel()
    except Exception:
        pass
    sys.exit(1)
