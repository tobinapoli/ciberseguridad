from PIL import Image
from pathlib import Path

base = Path(__file__).resolve().parent
img_path = base / "flag_img.png"

img = Image.open(img_path)
pixels = img.load()
width, height = img.size

print(f"Tamaño: {width}x{height}")
print(f"Modo: {img.mode}")

# Intentar diferentes métodos de extracción

# Método 1: LSB estándar (bit 0)
print("\n[*] Método 1: LSB estándar (bit 0)...")
mensaje = ""
for y in range(height):
    for x in range(width):
        pixel = pixels[x, y]
        if isinstance(pixel, tuple):
            for channel in pixel[:3]:
                mensaje += str(channel & 1)

texto = ''.join(chr(int(mensaje[i:i+8], 2)) for i in range(0, len(mensaje)-7, 8))
print(f"Resultado: {texto[:100]}")
if "CTF" in texto:
    print(f"✓ FLAG: {texto}")

# Método 2: Bit 1
print("\n[*] Método 2: Bit 1...")
mensaje = ""
for y in range(height):
    for x in range(width):
        pixel = pixels[x, y]
        if isinstance(pixel, tuple):
            for channel in pixel[:3]:
                mensaje += str((channel >> 1) & 1)

texto = ''.join(chr(int(mensaje[i:i+8], 2)) for i in range(0, len(mensaje)-7, 8))
print(f"Resultado: {texto[:100]}")
if "CTF" in texto:
    print(f"✓ FLAG: {texto}")

# Método 3: Solo canal R
print("\n[*] Método 3: Solo canal R...")
mensaje = ""
for y in range(height):
    for x in range(width):
        pixel = pixels[x, y]
        if isinstance(pixel, tuple):
            mensaje += str(pixel[0] & 1)

texto = ''.join(chr(int(mensaje[i:i+8], 2)) for i in range(0, len(mensaje)-7, 8))
print(f"Resultado: {texto[:100]}")
if "CTF" in texto:
    print(f"✓ FLAG: {texto}")