# Technical Report: CVE-XXXX-XXXX4: TEW-821DAP mycli Wifi VAP/MAC Filter UCI Stack Overflow

## Normalized Submission Metadata

| Field | Value |
|---|---|
| Vendor | TRENDnet |
| Product | TRENDnet TEW-821DAP Access Point |
| Firmware / Version | v2.2.01b05 |
| Affected Component | sbin/mycli |
| Vulnerability Type | Stack-based Buffer Overflow / RCE |
| CWE | CWE-121 |
| CVSS | 9.8 Critical |
| Source Material | E:\competition\漏洞\vulns\vulns\vuln-821dap-mycli-wifi-vap-overflow |

## Executive Summary

The team-provided report describes a CVE-level vulnerability in TRENDnet TEW-821DAP Access Point affecting sbin/mycli. The issue is categorized as Stack-based Buffer Overflow / RCE and is supported by the copied PoC and evidence files in this package.

## Original Technical Detail

The original report is embedded below for reviewer convenience. The untouched copy is also available at source/REPORT.original.md.

---

# CVE-XXXX-XXXX4: TEW-821DAP mycli Wifi VAP/MAC Filter UCI Stack Overflow

| 字段 | 值 |
|------|-----|
| 厂商 | TRENDnet | 产品 | TEW-821DAP v2.2.01b05 |
| 二进制 | `sbin/mycli` (MIPS32 BE, 9个函数地址) |
| 漏洞类型 | CWE-121 Stack-based Buffer Overflow |
| CVSS 3.1 | **9.8 Critical** AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |

---

## 1. 漏洞概述

mycli 在处理 wifi VAP 和 MAC filter 配置时，通过 `uci_get_option()` 将 SSID/BSSID/GBSSID/MAC列表等 WiFi 配置值无界复制到栈缓冲区。攻击者通过 ubus/UCI 接口设置超长 SSID（超过缓冲区大小）即可触发栈溢出。覆盖范围包括 wifi0、wifi1、wifi2 三频全部虚拟 AP。

---

## 2. FirmRec 符号执行证据

```
Simexp 验证: 40+ 条独立日志全部命中 0x41414141
关联CVE: CVE-2020-10214, CVE-2020-25506, CVE-2022-37798
Taint Applied: True
```

### 受影响函数（全部调用 uci_get_option → get_env → strcpy）

| 函数地址 | 栈帧 | 关键字 | 影响射频 |
|---------|------|--------|---------|
| 0x4224CC | 1080B | qcawifi.wifi0_vap1.maclist | wifi0 MAC filter |
| 0x4226B4 | 1080B | qcawifi.wifi0_vap1.maclist | wifi0 MAC filter |
| 0x42A230 | 1080B | qcawifi.wifi1_vap1.maclist | wifi1 MAC filter |
| 0x42A408 | 1080B | qcawifi.wifi1_vap1.maclist | wifi1 MAC filter |
| 0x4319C8 | 1080B | qcawifi.wifi2_vap1.maclist | wifi2 MAC filter |
| 0x431BA0 | 1080B | qcawifi.wifi2_vap1.maclist | wifi2 MAC filter |
| 0x41ED30 | 168B | qcawifi.etc.schedule_list | wifi调度 |
| 0x41F064 | 168B | qcawifi.etc.schedule_list | wifi调度 |
| 0x41F260 | 168B | qcawifi.etc.schedule_list | wifi调度 |

**此外，CSV中还确认了以下VAP SSID/BSSID溢出点（不同函数地址，但使用相同的 FUN_401180 封装）：**

| 函数地址 | 关键字 | 射频 |
|---------|--------|------|
| 0x4352664 | qcawifi.wifi0_vap10.ssid | wifi0 |
| 0x4352900 | qcawifi.wifi0_vap11.ssid | wifi0 |
| 0x4353280 | qcawifi.wifi0_vap8.bssid | wifi0 |
| 0x4353540 | qcawifi.wifi0_vap8.gbssid | wifi0 |
| 0x4354016 | qcawifi.wifi0_vap10.gbssid | wifi0 |
| 0x4386228 | qcawifi.wifi1_vap10.ssid | wifi1 |
| 0x4386768 | qcawifi.wifi1_vap8.bssid | wifi1 |
| 0x4387028 | qcawifi.wifi1_vap8.gbssid | wifi1 |
| 0x4387504 | qcawifi.wifi1_vap10.gbssid | wifi1 |
| 0x4417204 | qcawifi.wifi2_vap10.ssid | wifi2 |
| 0x4417744 | qcawifi.wifi2_vap8.bssid | wifi2 |
| 0x4418004 | qcawifi.wifi2_vap8.gbssid | wifi2 |
| 0x4418480 | qcawifi.wifi2_vap10.gbssid | wifi2 |

**合计 22 个独立函数地址**，全部使用相同的 unsafe strcpy 模式。

---

## 3. 反汇编验证

```
0x4224CC: addiu $sp, $sp, -1080  ; 1080B大帧,wifi MAC filter解析
0x4224E4: sw    $ra, 1076($sp)   ; $ra 在 sp+1076
0x422514: jal   0x401140          ; get_env("qcawifi.wifi0_vap1.maclist")
0x422550: lw    $ra, 1076($sp)   ; ★ 仅需20B溢出
```

---

## 4. PoC

```bash
# 通过 ubus 设置超长 SSID
ubus call uci set '{"config":"qcawifi","section":"wifi0_vap10","values":{"ssid":"'$(python3 -c "print('A'*200)")'"}}'
```

SSID 在 Wi-Fi 信标帧中广播，攻击者甚至不需要网络访问权限——超长 SSID 本身就可在附近触发。

---

*证据: evidence/ 96条日志 | FirmRec simexp: 全部命中 0x41414141*

