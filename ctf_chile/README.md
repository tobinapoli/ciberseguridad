## 📖 Descripción

Durante una auditoría se encontraron fragmentos de un mensaje roto y mezclado.  
Cada fragmento está en la forma:

```
<index>:<payload>
```

donde `<index>` indica la posición del fragmento en el mensaje original y `<payload>` es un texto codificado.

El proceso usado para ocultar el mensaje fue:
1. Tomar el texto original (que contiene la flag en formato `CTF{...}`).
2. Dividirlo en varios fragmentos.
3. Aplicar a cada fragmento un **XOR con una misma clave de 1 byte (0–255)**.
4. Codificar cada resultado en **Base64**.
5. Desordenar los fragmentos.

Tu tarea consiste en reconstruir el mensaje original.

---

## 🎯 Objetivo

1. Descubrir la **clave XOR** usada para codificar los fragmentos.  
2. Decodificar todos los fragmentos, ordenarlos según el índice (`<index>`).  
3. Concatenar el resultado y encontrar la flag en formato:

```
CTF{...}
```

---

## 🧪 Entrada

Archivo: `fragments.txt`

Ejemplo de contenido:

```
3:Y2UICggPRxp/dH4=
0:blJfGktPU1lRGlhIVU1UGlxVQhpQT1dKSQ==
2:VltAQxpeVV0UGnlufEF8aHt9d390bmllaH92ew==
1:GlVMX0gaTlJfGg==
```

---
¡Buena suerte!
