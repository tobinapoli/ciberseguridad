#!/usr/bin/env python3
"""
Bankination - DNS Security Analysis
100pts

Objetivo: Analizar registros DNS para encontrar vulnerabilidades de spoofing
- Registros NS
- SPF records
- DKIM records
- DMARC policy
"""

import subprocess
import socket

def run_dig_command(domain, record_type):
    """Ejecutar comando dig para consultar DNS"""
    try:
        result = subprocess.run(
            ['dig', domain, record_type, '+short'],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.stdout.strip() if result.stdout else None
    except FileNotFoundError:
        # dig no está disponible, intentar con nslookup
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
    """Análisis completo del dominio"""
    
    print(f"\n{'='*70}")
    print(f"ANÁLISIS DE SEGURIDAD DNS: {domain}")
    print(f"{'='*70}\n")
    
    # 1. Registros NS
    print("[*] Consultando Registros NS...")
    ns_records = run_dig_command(domain, 'NS')
    if ns_records:
        print(f"[+] Registros NS encontrados:")
        for line in ns_records.split('\n'):
            if line.strip():
                print(f"    - {line.strip()}")
    else:
        print("[-] No se encontraron registros NS")
    
    # 2. SPF Records (TXT)
    print("\n[*] Consultando SPF Records...")
    txt_records = run_dig_command(domain, 'TXT')
    if txt_records:
        print(f"[+] Registros TXT encontrados:")
        for line in txt_records.split('\n'):
            if line.strip():
                print(f"    - {line.strip()}")
                if 'v=spf1' in line.lower():
                    print("      ✓ SPF record presente")
    else:
        print("[-] No se encontraron registros TXT (SIN SPF)")
    
    # 3. DKIM Records
    print("\n[*] Consultando DKIM Records...")
    dkim_domains = ['default._domainkey', 'selector1._domainkey', 'selector2._domainkey']
    dkim_found = False
    for dkim_prefix in dkim_domains:
        dkim_domain = f"{dkim_prefix}.{domain}"
        dkim_records = run_dig_command(dkim_domain, 'TXT')
        if dkim_records and dkim_records.strip():
            print(f"[+] DKIM encontrado ({dkim_prefix}):")
            for line in dkim_records.split('\n'):
                if line.strip():
                    print(f"    - {line.strip()}")
            dkim_found = True
    if not dkim_found:
        print("[-] No se encontraron registros DKIM (SIN DKIM)")
    
    # 4. DMARC Policy
    print("\n[*] Consultando DMARC Policy...")
    dmarc_domain = f"_dmarc.{domain}"
    dmarc_records = run_dig_command(dmarc_domain, 'TXT')
    if dmarc_records and dmarc_records.strip():
        print(f"[+] DMARC Policy encontrado:")
        for line in dmarc_records.split('\n'):
            if line.strip():
                print(f"    - {line.strip()}")
    else:
        print("[-] No se encontró política DMARC (SIN DMARC)")
    
    # 5. MX Records
    print("\n[*] Consultando MX Records...")
    mx_records = run_dig_command(domain, 'MX')
    if mx_records:
        print(f"[+] Servidores de Mail:")
        for line in mx_records.split('\n'):
            if line.strip():
                print(f"    - {line.strip()}")
    else:
        print("[-] No se encontraron registros MX")
    
    # 6. A Records
    print("\n[*] Consultando A Records...")
    a_records = run_dig_command(domain, 'A')
    if a_records:
        print(f"[+] Direcciones IP:")
        for line in a_records.split('\n'):
            if line.strip():
                print(f"    - {line.strip()}")
    else:
        print("[-] No se encontraron registros A")

def extract_flag(domain):
    """Extraer flag de los registros DNS"""
    flag_parts = []
    
    # Extraer parte 1 del SPF record
    txt_records = run_dig_command(domain, 'TXT')
    if txt_records and 'UNLP{' in txt_records:
        start_idx = txt_records.index('UNLP{')
        end_idx = txt_records.index('"', start_idx) if '"' in txt_records[start_idx:] else len(txt_records)
        part1 = txt_records[start_idx:end_idx]
        flag_parts.append(part1)
    
    # Extraer parte 2 del DMARC record
    dmarc_domain = f"_dmarc.{domain}"
    dmarc_records = run_dig_command(dmarc_domain, 'TXT')
    if dmarc_records and '_part' in dmarc_records:
        start_idx = dmarc_records.index('_part')
        end_idx = dmarc_records.index('}', start_idx) + 1 if '}' in dmarc_records[start_idx:] else len(dmarc_records)
        part2 = dmarc_records[start_idx:end_idx]
        flag_parts.append(part2)
    
    return ''.join(flag_parts) if flag_parts else None

def generate_report(domain):
    """Generar reporte de vulnerabilidades"""
    
    print(f"\n{'='*70}")
    print("REPORTE DE VULNERABILIDADES")
    print(f"{'='*70}\n")
    
    vulnerabilities = []
    
    # Revisar SPF
    txt_records = run_dig_command(domain, 'TXT')
    has_spf = False
    if txt_records and 'v=spf1' in txt_records.lower():
        has_spf = True
    
    if not has_spf:
        vulnerabilities.append("❌ SIN SPF: Cualquiera puede falsificar el dominio en el From:")
    else:
        vulnerabilities.append("✓ SPF presente")
    
    # Revisar DKIM
    dkim_found = False
    for prefix in ['default._domainkey', 'selector1._domainkey']:
        if run_dig_command(f"{prefix}.{domain}", 'TXT'):
            dkim_found = True
            break
    if not dkim_found:
        vulnerabilities.append("❌ SIN DKIM: Imposible verificar integridad del mensaje")
    else:
        vulnerabilities.append("✓ DKIM presente")
    
    # Revisar DMARC
    dmarc_records = run_dig_command(f"_dmarc.{domain}", 'TXT')
    dmarc_found = dmarc_records and dmarc_records.strip()
    if not dmarc_found:
        vulnerabilities.append("❌ SIN DMARC: No hay política de handling de emails fallidos")
    else:
        vulnerabilities.append("✓ DMARC presente")
    
    print("HALLAZGOS:")
    for vuln in vulnerabilities:
        print(f"  {vuln}")
    
    print("\n\nRECOMENDACIONES:")
    print("  1. Configurar SPF record con IP del servidor de mail")
    print("  2. Implementar DKIM para firmar los mensajes")
    print("  3. Configurar política DMARC (reject o quarantine)")
    print("  4. Usar DANE para validar certificados")
    print("  5. Implementar TLSRPT para reporte de fallidos")
    
    print("\n\nCÓMO EXPLOTAR (Explicación educativa):")
    print("  Sin SPF: El atacante puede enviar emails desde cualquier IP con From: admin@bankination.ctf.cert.unlp.edu.ar")
    print("  Sin DKIM: No hay firma digital, es imposible verificar autenticidad")
    print("  Sin DMARC: No hay política, el servidor receptor no sabe qué hacer con emails fallidos")
    print("  → Resultado: Spoofing de email completamente posible")
    
    # Extraer y mostrar flag
    print("\n\n" + "="*70)
    flag = extract_flag(domain)
    if flag:
        print(f"FLAG: {flag}")
    else:
        print("[-] No se pudo extraer la flag")
    print("="*70)

if __name__ == "__main__":
    domain = "bankination.ctf.cert.unlp.edu.ar"
    
    print("\n" + "="*70)
    print("BANKINATION - ANÁLISIS DE SEGURIDAD DNS")
    print("="*70)
    
    try:
        # Análisis principal
        analyze_domain(domain)
        
        # Generar reporte
        generate_report(domain)
        
    except Exception as e:
        print(f"\n[-] Error general: {e}")
        import traceback
        traceback.print_exc()

