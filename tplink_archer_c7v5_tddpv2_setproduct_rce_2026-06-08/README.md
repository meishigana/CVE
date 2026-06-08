# TP-Link Archer C7 V5 TDDPv2 setProductName RCE CVE 材料包

日期：2026-06-08

## 结论

本目录整理的是 TP-Link Archer C7(US) V5 固件 `Archer C7(US)_V5.0_220715` 中 `/usr/bin/tddp` 的 TDDPv2 `0x52 setProductName` 命令注入 RCE 材料。

当前证据强度：高。

提交价值：有，但建议以“疑似新 CVE/新变体”提交，并在材料中主动说明与 `CVE-2021-42232`、`CVE-2025-9377` 的差异。当前未发现公开 CVE/PoC 完全覆盖 `Archer C7(US) V5 220715 + TDDPv2 0x52 setProductName/product_name` 这条链路。

主要保守点：当前动态复现在本地授权仿真环境完成。由于 Docker/WSL 环境缺少 MIPS `binfmt_misc`，复现脚本在隔离 rootfs 副本中使用了 host-exec bridge 转发 `/bin/sh -c` 到原始 MIPS busybox shell。`/usr/bin/tddp` 二进制未修改。正式对外披露前，建议补充真机或完整系统 QEMU 复现。

## 文件说明

- `cve_submission_draft.md`：可直接改写为 CNA/厂商提交文本。
- `technical_report.md`：技术细节、根因、影响与证据摘要。
- `poc_reproduction.md`：本地授权仿真复现说明。
- `duplicate_check.md`：公开 CVE/PoC 重复性检查。
- `evidence_index.md`：证据文件索引和哈希。
- `evidence_hostexec_bridge.txt`：最新可复现动态证据。
- `verify_tddpv2_hostexec_bridge.sh`：动态复现脚本。
- `sh_bridge.c`：host-exec bridge 源码。
- `static_setproduct_402f40_403120.txt`：`setProductName` 关键反汇编片段。
- `static_spcmd_404180_404360.txt`：TDDPv2 `spCmd` 分发关键反汇编片段。

## 建议提交定位

建议标题：

`TP-Link Archer C7(US) V5 firmware 220715 TDDPv2 setProductName command injection`

建议弱点类型：

`CWE-78: Improper Neutralization of Special Elements used in an OS Command`

建议 CVSS 初评：

`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`，基础分 8.8。

若厂商确认 TDDPv2 服务可从普通 LAN 网络直接访问且协议密钥/认证不构成有效权限要求，可讨论调整为 `AV:N`，可能达到 9.8。
