# extrae_stego.py
# Uso: python extrae_stego.py sully.png
# Propósito: recorrer planos de bits en RGB (6,0,4,2), reconstruir bytes desde los bits por píxel
# y mostrar cadenas ASCII potenciales; también lee tEXt/iTXt del PNG.

import sys
from PIL import Image, PngImagePlugin
import string
from pathlib import Path

PRINTABLE = set(bytes(string.printable, "utf-8"))

def bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte_bits = bits[i:i+8]
        if len(byte_bits) < 8: break
        val = 0
        for b in byte_bits:
            val = (val << 1) | b
        out.append(val)
    return bytes(out)

def score_ascii(data: bytes):
    if not data: return 0.0
    good = sum(1 for c in data if c in PRINTABLE or c in (10,13,9))
    return good / len(data)

def try_plane(img, channel_idx, bit_idx):
    """Extrae el bit `bit_idx` del canal `channel_idx` de todos los píxeles (escaneo fila por fila)."""
    px = img.load()
    w, h = img.size
    bits = []
    for y in range(h):
        for x in range(w):
            r, g, b = px[x, y][:3]
            c = (r, g, b)[channel_idx]
            bits.append((c >> bit_idx) & 1)
    data = bits_to_bytes(bits)
    return data

def dump_plane_image(img, channel_idx, bit_idx, out_path):
    """Guarda la imagen del plano de bits para inspección visual."""
    w, h = img.size
    out = Image.new("L", (w, h))
    ipx = img.load()
    opx = out.load()
    for y in range(h):
        for x in range(w):
            r, g, b = ipx[x, y][:3]
            c = (r, g, b)[channel_idx]
            v = 255 if ((c >> bit_idx) & 1) else 0
            opx[x, y] = v
    out.save(out_path)

def read_png_text(path):
    im = Image.open(path)
    info = im.info
    # PngImagePlugin guarda tEXt/iTXt en info (puede estar vacío)
    if info:
        print("\n[Metadatos de texto PNG]")
        for k, v in info.items():
            if isinstance(v, str) and any(ch.isprintable() for ch in v):
                print(f"- {k}: {v[:200]}")
    im.close()

def main():
    if len(sys.argv) < 2:
        print("Uso: python extrae_stego.py <imagen.png>")
        sys.exit(1)

    path = sys.argv[1]
    im = Image.open(path).convert("RGB")

    # Pista del enunciado: “don’t be sad” → no te quedes solo con Blue.
    channel_names = ["R", "G", "B"]
    # Pista de las esquinas: 6 (arriba-izq), 0 (arriba-der), 4 (abajo-izq), 2 (abajo-der)
    bit_order = [6, 0, 4, 2]

    best_hits = []
    for ch in range(3):
        for bit in bit_order:
            data = try_plane(im, ch, bit)
            score = score_ascii(data)
            label = f"{channel_names[ch]} bit{bit}"
            # Mostrar primeras 200 imprimibles para olfatear
            printable_preview = bytes(c if c in PRINTABLE else 0x2E for c in data[:800])
            print(f"\n===== Plano {label}  (legibilidad ~{score:.2%}) =====")
            try:
                txt = printable_preview.decode("utf-8", errors="ignore")
            except:
                txt = printable_preview.decode("latin-1", errors="ignore")
            print(txt)

            # Heurística: guardar hits buenos y los que contengan 'flagmx{'
            if b"flagmx{" in data.lower() or score > 0.70:
                best_hits.append((score, label, data))

            # También guardamos la imagen del plano para leer texto oculto a simple vista
            out_png = Path(f"plane_{channel_names[ch]}_{bit}.png")
            dump_plane_image(im, ch, bit, out_png)

    # Resumen de mejores candidatos
    if best_hits:
        print("\n### Candidatos fuertes:")
        best_hits.sort(reverse=True, key=lambda t: t[0])
        for score, label, data in best_hits[:6]:
            try:
                txt = data.decode("utf-8", errors="ignore")
            except:
                txt = data.decode("latin-1", errors="ignore")
            # recortamos pero buscamos flagmx
            frag = txt
            if "flagmx{" in txt:
                start = txt.lower().find("flagmx{")
                end = txt.find("}", start)
                if end != -1:
                    print(f"- {label} ({score:.1%}): {txt[start:end+1]}")
                else:
                    print(f"- {label} ({score:.1%}): {txt[start:start+80]}...")
            else:
                print(f"- {label} ({score:.1%}): {txt[:120]}...")

    # Leer tEXt/iTXt
    read_png_text(path)

    print("\nListo. Revisá también los archivos plane_R_*.png / plane_G_*.png / plane_B_*.png generados.")

if __name__ == "__main__":
    main()
