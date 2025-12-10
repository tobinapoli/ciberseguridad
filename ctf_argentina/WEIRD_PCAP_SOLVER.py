#!/usr/bin/env python3
"""
Weird PCAP - 100pts
Covert Channel Detection: DNS Exfiltration via in-addr.arpa queries

Descripción:
El cliente genera tráfico "normal" (DNS queries a github.com, facebook.com, etc.)
pero la flag real está escondida en consultas DNS reverse (in-addr.arpa) fraudulentas.

En vez de usar IPs reales en reverse lookups como "1.2.3.4.in-addr.arpa",
el atacante usa números decimales que son códigos ASCII.

Ejemplo: "85787680.in-addr.arpa" -> 85, 78, 76, 80 -> U, N, L, P

Solución:
1. Leer el PCAP
2. Extraer todas las consultas DNS con dominio terminado en "in-addr.arpa"
3. Extraer los números antes de "in-addr.arpa"
4. Convertir cada número decimal a carácter ASCII
5. Concatenar todo en orden
"""

from scapy.all import rdpcap, DNS, DNSQR
import re

def extract_flag_from_pcap(pcap_file):
    """Extrae la flag de consultas DNS in-addr.arpa en el PCAP"""
    
    print("[*] Analizando PCAP:", pcap_file)
    pcap = rdpcap(pcap_file)
    
    ascii_codes = []
    
    # Iterar sobre todos los paquetes
    for i, pkt in enumerate(pcap):
        if DNS in pkt and pkt[DNS].qd:
            # Obtener el nombre consultado
            qname = pkt[DNS].qd.qname.decode().rstrip('.')
            
            # Buscar consultas in-addr.arpa
            if 'in-addr.arpa' in qname:
                # Extraer la parte numérica antes de "in-addr.arpa"
                # Ejemplo: "85787680.in-addr.arpa" -> "85787680"
                match = re.match(r'^([\d\.]+)\.in-addr\.arpa$', qname)
                if match:
                    numbers_str = match.group(1)
                    
                    # Separar los números individuales
                    numbers = numbers_str.split('.')
                    
                    print(f"  [Query {i}] {qname} -> números: {numbers}")
                    
                    # Convertir cada número a carácter ASCII
                    for num_str in numbers:
                        try:
                            ascii_code = int(num_str)
                            if 32 <= ascii_code <= 126:  # Rango ASCII imprimible
                                char = chr(ascii_code)
                                ascii_codes.append((ascii_code, char))
                                print(f"           {num_str} (0x{ascii_code:02x}) -> '{char}'")
                        except ValueError:
                            pass
    
    # Construir la flag
    print("\n[+] Flag construida:")
    flag = ''.join(char for _, char in ascii_codes)
    print(f"    {flag}")
    
    return flag

def main():
    pcap_file = 'ctf_argentina/weird.pcap'
    
    try:
        flag = extract_flag_from_pcap(pcap_file)
        
        print("\n[*] Análisis completado")
        print(f"[+] FLAG: {flag}")
        
        # Validar formato
        if flag.startswith('UNLP{'):
            print("Flag encontrada!")
        
    except FileNotFoundError:
        print(f"[-] Archivo no encontrado: {pcap_file}")
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
