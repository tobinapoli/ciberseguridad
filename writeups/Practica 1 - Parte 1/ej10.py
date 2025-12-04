from xor_cipher import xor
msg = "08296632232822342f27356637332366252f2034273466252928661e09146a66252e236866162334296624332328296a662a2766202a272166222366233532236634233229662335660f053d092c7619257628193e7634676767737e7f737f73737f192527352f192e27252d232334343b"

for i in range(256):
    texto_descifrado = xor(bytes.fromhex(msg), i)
    if b"flag" in texto_descifrado:
        print(f"Clave (entero): {i}")
        print(texto_descifrado.decode(errors="ignore"))
        break