from pathlib import Path
import base64

alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# 1) Leer archivo
txt = Path("file.txt").read_text(encoding="utf-8", errors="ignore")
lines = txt.splitlines()

# 2) Quedarnos con las primeras 6 líneas “cuadradas”
lines6 = lines[:6]
width = len(lines6[0])

# Sanity check: todas del mismo largo
assert all(len(l) == width for l in lines6), "Las 6 primeras líneas no tienen el mismo largo"

# 3) Convertir columnas a valores de 0..63
vals = []
for c in range(width):
    v = 0
    for r in range(6):
        if lines6[r][c] != ' ':
            # bit más significativo = fila 0
            v |= 1 << (5 - r)
    vals.append(v)

# 4) Mapear a caracteres base64 (si v==0 lo podemos mapear a espacio)
b64_raw = ''.join(alphabet[v] if v > 0 else ' ' for v in vals)

print("Posible base64 con espacios:")
print(b64_raw[:200], "...\n")

# 5) Limpiar espacios
b64_clean = ''.join(ch for ch in b64_raw if ch != ' ')

print("Base64 compactado (primeros 200 chars):")
print(b64_clean[:200])

# 6) Probar decodificar con padding (por si falta '=')
for pad in range(4):
    try:
        decoded = base64.b64decode(b64_clean + "=" * pad)
        print(f"\n[+] Pad {pad}: len={len(decoded)}")
        print(decoded[:200])
    except Exception as e:
        print(f"Pad {pad} error:", e)
