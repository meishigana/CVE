# 公开 CVE/PoC 重复性检查

检查日期：2026-06-08

## 检查结论

未发现公开 CVE 或 PoC 完全覆盖以下组合：

```text
TP-Link Archer C7(US) V5 firmware 220715
/usr/bin/tddp
TDDPv2 spCmd command byte 0x52
setProductName/product_name
shell command substitution command injection
```

提交价值：有。建议作为独立 CVE 或独立变体提交。

重复风险：中等。原因是 TP-Link TDDP/TDDPv2 历史上已有多个命令注入 CVE，其中 `CVE-2021-42232` 同样位于 `/usr/bin/tddp`，但触发点、设备型号和固件版本不同。

## 重点相近 CVE

### CVE-2021-42232

公开描述：

- 产品：TP-Link Archer A7(US) V5
- 固件：`Archer A7(US)_V5_210519`
- 组件：`/usr/bin/tddp`
- 类型：command injection
- NVD CVSS v3.1：`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`，9.8 Critical

公开 PoC/说明指向：

- 函数地址：`401EA0`
- 场景：tftp 命令参数拼接
- 缺陷：只过滤 `;`，可用 `||` 注入
- 修复版本：公开材料称 `Archer A7(US)_V5_211022` 修复

与本漏洞差异：

- 本漏洞目标为 Archer C7(US) V5 firmware 220715。
- 本漏洞触发 TDDPv2 `spCmd` 子命令 `0x52`。
- 本漏洞处理函数为 `0x402f50` 附近的 `setProductName`。
- 本漏洞输入语义是 product name，不是 tftp 参数。
- 本漏洞绕过方式依赖 `$()` command substitution 和单引号拼接，不是 `||`。

结论：不是完全重复，但属于同组件同类型漏洞，提交时应主动声明差异。

### CVE-2025-9377

公开描述：

- 产品：TP-Link Archer C7(EU) V2、TL-WR841N/ND(MS) V9
- 入口：Parental Control page
- 类型：authenticated RCE / OS command injection
- NVD CVSS v3.1：`AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`，7.2 High
- CISA KEV 已收录，说明公开利用关注度高

与本漏洞差异：

- `CVE-2025-9377` 影响 Archer C7(EU) V2，不是 Archer C7(US) V5。
- `CVE-2025-9377` 入口是 Web 管理页，不是 TDDPv2。
- `CVE-2025-9377` 需要高权限认证，本漏洞当前 PoC 未依赖 Web 登录态。
- 本漏洞触发点是 `/usr/bin/tddp` `0x52 setProductName`。

结论：不重复。

## 关键词检索

已检索关键词包括：

```text
"TP-Link Archer C7 v5" "TDDPv2" "setProductName"
"tddp_cmd_setProductName"
"grep \"product_name\" /tmp/cc-tmp"
"TDDPv2" "0x52" "TP-Link"
"Archer C7(US)_V5.0_220715" "tddp"
"c7v5_us-up-ver1-2-1-P1[20220715-rel19099]" vulnerability
"TP-Link Archer C7" "TDDP" "CVE"
```

NVD API 检查：

- `CVE-2021-42232`：存在，A7 V5 `/usr/bin/tddp`，相近但不重复。
- `CVE-2025-9377`：存在，C7(EU) V2 Parental Control authenticated RCE，不重复。
- `keywordSearch=TP-Link Archer C7 TDDP`：未返回匹配 CVE。
- `keywordSearch=TP-Link Archer C7 RCE`：未返回覆盖本链路的匹配 CVE。

## 提交建议

建议不要泛称：

```text
TP-Link Archer C7 RCE
```

应精确命名为：

```text
TP-Link Archer C7(US) V5 firmware 220715 TDDPv2 0x52 setProductName command injection
```

提交时附上：

- 与 `CVE-2021-42232` 的差异表。
- 与 `CVE-2025-9377` 的差异表。
- 固件版本、二进制哈希、反汇编地址、动态证据。
- 当前仿真限制和后续真机复现计划。

## 参考来源

- NVD CVE-2021-42232: https://nvd.nist.gov/vuln/detail/CVE-2021-42232
- NVD CVE-2025-9377: https://nvd.nist.gov/vuln/detail/CVE-2025-9377
- TP-Link advisory referenced by CVE-2025-9377: https://www.tp-link.com/us/support/faq/4365/
- CVE-2021-42232 public write-up: https://github.com/mQaLeX/IoT/blob/main/tp-link/Archer%20A7%28US%29_V5_20519_tddp.md

