from PIL import Image

def extraer_mensaje(imagen_entrada):
    img = Image.open(imagen_entrada)
    img = img.convert("RGB")
    pixels = img.load()

    ancho, alto = img.size
    bits = []

    # Recorremos solo píxeles pares
    for y in range(alto):
        for x in range(ancho):
            idx = y * ancho + x
            if idx % 2 == 0: # píxeles pares
                r, g, b = pixels[x, y]
                bits.append(b & 1)

    # Agrupar bits en bytes
    mensaje = ""
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) < 8:
            continue
        caracter = chr(int("".join(map(str, byte)), 2))
        mensaje += caracter
    if mensaje.endswith("###"): # delimitador de fin
        return mensaje[:-3]

    return mensaje


if __name__ == "__main__":
    entrada = "sully.png" # imagen con el mensaje oculto
    mensaje = extraer_mensaje(entrada)
    print(f"✅ Mensaje revelado: {mensaje}")