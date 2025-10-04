from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, inverse

"Revele el mensaje cifrado con RSA, esta vez no tenemos P ni Q. Pista: Hay que factorizar o encontrar un buen lugar donde lo hagan…"
n = 1452449184624535635757449085988204487494222248509493899299759
e = 65537
c = 1280743944712857143060627969938538851911171950125979945026152
p=1153324775179431312178120797679
q=1259358348907893108175391571521
phi = (p - 1) * (q - 1)
d = inverse(e, phi)
m = pow(c, d, n)
m_bytes = long_to_bytes(m)
print("Mensaje (ASCII ignorando errores):", m_bytes.decode(errors="ignore"))