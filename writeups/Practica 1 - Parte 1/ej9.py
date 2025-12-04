from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
clave = "CLAVE RE SECRETA"
texto = "dV5t6M4m2AcjYWsxC9iO+YXlc0r0ClfwyTGtpuWdPh9fvH+8cejJWOHYq1qH7qA+Kj7Lci133Awj3rnoq42p532+fvbN64oZ8R/TlMkhw47nmIM5gPN+rt45985jeiIDbdpCu1ig09Rzepl4/kawM1AzFtoMzTvadmx11qSFp+UD81yiRz6HjaFLIIIIQnbzFrmcOIOGEQ6LBEYz2cTW6JPBs7MHpqDrcrzZoLcb7Ah2jQSIId+YZ90JmRt83yTe66a60kqL5SoW7/463Suyyp9xDhrgFu6YS3ScNDgOamADIcKmLUTxrvYooZIjL7s+thek3aBPrv/yB84YNUhX7MOxjiTiP02nBJ1E1dOA0ew75BeARB4cHKVfLMnPMkjSYyiQ2eTWqYd4cZ+14Z9joNVA1Uei8Pg4KITPfJYy3Mc="
texto_bytes = base64.b64decode(texto)

cipher = Cipher(algorithms.AES(clave.encode()), modes.ECB())
decryptor = cipher.decryptor()
texto_descifrado = decryptor.update(texto_bytes) + decryptor.finalize()
print(texto_descifrado.decode())

