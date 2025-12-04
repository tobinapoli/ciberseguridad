#!/usr/bin/env python3
import re

with open('tloz-totk.sav', 'rb') as f:
    data = f.read()

# Extract readable strings
strings = re.findall(b'[\x20-\x7e]{4,}', data)

with open('tloz-totk_analysis.txt', 'w', encoding='utf-8') as out:
    out.write('=== ANALYSIS OF tloz-totk.sav ===\n\n')
    out.write(f'File size: {len(data)} bytes\n')
    out.write(f'Hex dump (first 500 bytes):\n')
    out.write(data[:500].hex() + '\n\n')
    out.write(f'Found {len(strings)} readable strings:\n\n')
    for i, s in enumerate(strings[:150], 1):
        decoded = s.decode('utf-8', errors='ignore')
        out.write(f'{i}. {decoded}\n')

print('[+] Analysis saved to tloz-totk_analysis.txt')
