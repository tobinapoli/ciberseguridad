import re

data = "05110006_08130308020418_001115070001041908021418"

# saco los "_"
data = data.replace("_", "")

# separo en tripletas
tripletas = [data[i:i+3] for i in range(0, len(data), 3)]

# decodifico cada tripleta como octal
texto = ""
for t in tripletas:
    try:
        texto += chr(int(t, 8))
    except ValueError:
        print("Tripleta inválida:", t)  # por si hay algún '8' o '9'
print(texto)
