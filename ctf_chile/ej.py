# Recibimos un volcado de un servidor antiguo que sufrió un fallo curioso. Dentro hay un fichero con tres valores: N, e y c. Los administradores nos dicen que N está formado por primos tan grandes que hoy nadie podrá factorizarlo, y que el atacante (o un admin despistado) parece haber usado un esquema RSA “no del todo estándar”. Tu misión: analiza el fichero mensage.txt, descifra lo que contiene y entrega la bandera.

N = 24456434670652740808871235035015868871079945108709411203080335968054215469857053510490572992496655753896480924347257535741912006451767333857348827657468869070039519960397098392242474551750035887081414632062973808277325329331684398172307815961100024785923344990406293900864792254598803868053882793355349544166664503924083979223383779325209797354309580173495761125149147761154466281648652753066456092075626313081025724194124227065928355323082397072250617854553081666214512646369817917449951681097496322194578093023200398876739155278069607155597038524332648273001852342033408621785065276764602149333105249223345618237296
e = 20
c = 592622905436543835044895387649942676104614087565421707093677997965373363122896755606588416658262107383615197159492893146727120619115937079582374692341717900383331020684637134410289345036123646471971762751500037884165505155692992777691412650420811018465626117618888779355329585599491856520276267096339244145733111556404490715387201

try:
    from gmpy2 import iroot
    m = int(iroot(c, e)[0])
except ImportError:
    # Fallback: Newton-Raphson más robusto
    def integer_root(n, k):
        if n == 0:
            return 0
        x = n
        y = (x + n // (x ** (k - 1))) // k
        while y < x:
            x = y
            y = (x + n // (x ** (k - 1))) // k
        return x
    m = integer_root(c, e)

# Probar candidatos en rango más amplio
encontrado = False
for delta in range(-5, 6):
    candidate = m + delta
    if pow(candidate, e, N) == c:
        m = candidate
        encontrado = True
        print(f"✓ Encontrado con delta={delta}")
        break

if not encontrado:
    print("⚠ No se encontró match exacto, usando m como está")

# Convertir a bytes
try:
    mensaje = m.to_bytes((m.bit_length() + 7) // 8, byteorder='big')
    print(f"Mensaje descifrado: {mensaje}")
    print(f"Decodificado: {mensaje.decode(errors='ignore')}")
except Exception as e:
    print(f"Error al convertir: {e}")
    print(f"m = {m}")


