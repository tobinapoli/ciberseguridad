from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, inverse

p = 1411681044962247700471424630708374925648758544093881877
q = 1025477764739116170232001755962926569489838949121232767
e = 65537
c = 244800329353906336350382253088680972646706962639783844335948234085022348400763256559770095538177770365047075

n = p * q
phi = (p - 1) * (q - 1)
d = inverse(e, phi)

m = pow(c, d, n)
m_bytes = long_to_bytes(m)

print("Mensaje (hex):", m_bytes.hex())
print("Mensaje (ASCII ignorando errores):", m_bytes.decode(errors="ignore"))



