#!/usr/bin/env python3

import subprocess
import socket

def run_dig_command(domain, record_type):
    """Ejecutar dig o nslookup para consultar DNS"""
    try:
        result = subprocess.run(
            ['dig', domain, record_type, '+short'],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.stdout.strip() if result.stdout else None
    except FileNotFoundError:
        try:
            result = subprocess.run(
                ['nslookup', '-type=' + record_type, domain],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.stdout if result.stdout else None
        except:
            return None
    except Exception as e:
        print(f"[-] Error: {e}")
        return None

def analyze_domain(domain):
    """Consultar registros DNS del dominio"""
    
    print(f"\n{'='*70}")
    print(f"ANÁLISIS DNS: {domain}")
    print(f"{'='*70}\n")
    
    # NS Records
    print("[*] Registros NS...")
    ns_records = run_dig_command(domain, 'NS')
    if ns_records:
        print(f"[+] NS encontrados:")
        for line in ns_records.split('\n'):
            if line.strip():
                print(f"    - {line.strip()}")
    else:
        print("[-] Sin registros NS")
    
    # SPF Records
    print("\n[*] SPF Records...")
    txt_records = run_dig_command(domain, 'TXT')
    if txt_records:
        print(f"[+] Registros TXT:")
        for line in txt_records.split('\n'):
            if line.strip():
                print(f"    - {line.strip()}")
    else:
        print("[-] Sin SPF")
    
    # DKIM
    print("\n[*] DKIM Records...")
    dkim_domains = ['default._domainkey', 'selector1._domainkey', 'selector2._domainkey']
    dkim_found = False
    for dkim_prefix in dkim_domains:
        dkim_domain = f"{dkim_prefix}.{domain}"
        dkim_records = run_dig_command(dkim_domain, 'TXT')
        if dkim_records and dkim_records.strip():
            print(f"[+] DKIM ({dkim_prefix}):")
            for line in dkim_records.split('\n'):
                if line.strip():
                    print(f"    - {line.strip()}")
            dkim_found = True
    if not dkim_found:
        print("[-] Sin DKIM")
    
    # DMARC
    print("\n[*] DMARC Policy...")
    dmarc_domain = f"_dmarc.{domain}"
    dmarc_records = run_dig_command(dmarc_domain, 'TXT')
    if dmarc_records and dmarc_records.strip():
        print(f"[+] DMARC encontrado:")
        for line in dmarc_records.split('\n'):
            if line.strip():
                print(f"    - {line.strip()}")
    else:
        print("[-] Sin DMARC")
    
    # MX Records
    print("\n[*] MX Records...")
    mx_records = run_dig_command(domain, 'MX')
    if mx_records:
        print(f"[+] Servidores de Mail:")
        for line in mx_records.split('\n'):
            if line.strip():
                print(f"    - {line.strip()}")
    else:
        print("[-] Sin MX")
    
    # A Records
    print("\n[*] A Records...")
    a_records = run_dig_command(domain, 'A')
    if a_records:
        print(f"[+] IPs:")
        for line in a_records.split('\n'):
            if line.strip():
                print(f"    - {line.strip()}")
    else:
        print("[-] Sin A records")

def extract_flag(domain):
    """Extraer flag de los registros DNS"""
    flag_parts = []
    
    txt_records = run_dig_command(domain, 'TXT')
    if txt_records and 'UNLP{' in txt_records:
        start_idx = txt_records.index('UNLP{')
        end_idx = txt_records.index('"', start_idx) if '"' in txt_records[start_idx:] else len(txt_records)
        part1 = txt_records[start_idx:end_idx]
        flag_parts.append(part1)
    
    dmarc_domain = f"_dmarc.{domain}"
    dmarc_records = run_dig_command(dmarc_domain, 'TXT')
    if dmarc_records and '_part' in dmarc_records:
        start_idx = dmarc_records.index('_part')
        end_idx = dmarc_records.index('}', start_idx) + 1 if '}' in dmarc_records[start_idx:] else len(dmarc_records)
        part2 = dmarc_records[start_idx:end_idx]
        flag_parts.append(part2)
    
    return ''.join(flag_parts) if flag_parts else None

def generate_report(domain):
    """Generar reporte de seguridad"""
    
    print(f"\n{'='*70}")
    print("REPORTE DE VULNERABILIDADES")
    print(f"{'='*70}\n")
    
    vulnerabilities = []
    
    txt_records = run_dig_command(domain, 'TXT')
    has_spf = txt_records and 'v=spf1' in txt_records.lower()
    
    if not has_spf:
        vulnerabilities.append("❌ SIN SPF")
    else:
        vulnerabilities.append("✓ SPF")
    
    dkim_found = False
    for prefix in ['default._domainkey', 'selector1._domainkey']:
        if run_dig_command(f"{prefix}.{domain}", 'TXT'):
            dkim_found = True
            break
    if not dkim_found:
        vulnerabilities.append("❌ SIN DKIM")
    else:
        vulnerabilities.append("✓ DKIM")
    
    dmarc_records = run_dig_command(f"_dmarc.{domain}", 'TXT')
    dmarc_found = dmarc_records and dmarc_records.strip()
    if not dmarc_found:
        vulnerabilities.append("❌ SIN DMARC")
    else:
        vulnerabilities.append("✓ DMARC")
    
    print("Hallazgos:")
    for vuln in vulnerabilities:
        print(f"  {vuln}")
    
    print("\nImpacto:")
    print("  - Sin SPF: Spoofing de emails posible")
    print("  - Sin DKIM: Imposible verificar integridad")
    print("  - Sin DMARC: No hay política de validación")
    
    print("\n" + "="*70)
    flag = extract_flag(domain)
    if flag:
        print(f"FLAG: {flag}")
    else:
        print("[-] Flag no encontrada")
    print("="*70)


if __name__ == "__main__":
    domain = "bankination.ctf.cert.unlp.edu.ar"
    
    print("\n" + "="*70)
    print("BANKINATION - ANÁLISIS DNS")
    print("="*70)
    
    try:
        analyze_domain(domain)
        generate_report(domain)
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()

