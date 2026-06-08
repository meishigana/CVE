# 邮件提交报告：TP-Link Archer C7(US) V5 TDDPv2 setProductName OS Command Injection

日期：2026-06-08

## 使用说明

本文件说明如何通过邮件提交 CVE 请求。邮件正文请直接使用同目录下的：

```text
email_body.txt
```

建议收件人：

```text
cve-assign@mitre.org
```

可选抄送：

```text
cve@mitre.org
cve-request@mitre.org
```

邮件主题已更新为：

```text
[REQUEST] CVE for TP-Link Archer C7(US) V5 - TDDPv2 setProductName OS command injection
```

## 附件策略

不建议在邮件里直接附带大量文件、源码、截图或 PoC 脚本。CVE/MITRE 邮件系统可能拒收大附件、可执行内容、脚本或安全敏感材料。

推荐做法：

1. 将材料上传到 GitHub 仓库。
2. 邮件正文只提供仓库链接、关键文件 SHA256、漏洞摘要和复现状态。
3. 如仓库为私有，应在邮件中说明可按需授权访问或单独提供压缩包。
4. 如仓库公开，应避免放置会直接导致未授权利用的完整攻击脚本，或在公开前先与厂商协调。

当前邮件正文中的仓库链接占位为：

```text
https://github.com/meishigana/CVE/tree/main/tplink_archer_c7v5_tddpv2_setproduct_rce_2026-06-08
```

本地已准备 Git 仓库：

```text
CVE/
```

远程仓库尚未创建。请先在 GitHub 网页创建空仓库：

```text
https://github.com/meishigana/CVE
```

创建后可使用以下远端地址推送：

```text
ssh://git@ssh.github.com:443/meishigana/CVE.git
```

## 正文关键改动

邮件正文已按以下要求调整：

- 主题增加 `[REQUEST]` 标签。
- `Reproduction status` 开头加入：

```text
Note: Full real-device reproduction is not yet completed, but the emulated environment strongly indicates the vulnerability exists. We can provide real-device evidence upon request.
```

- CVSS 处补充：

```text
Environmental score may vary. If TDDPv2 is reachable from WAN, adjust to AV:N -> 9.8 Critical.
```

- 重复性检查处补充：

```text
No existing CVE covers the combination of TDDPv2 command 0x52 (setProductName) in Archer C7(US) V5 firmware 220715.
```

- 邮件中不再列“直接附件清单”，改为提供 GitHub 仓库链接和关键 SHA256。

## 建议仓库内容

本地 `CVE/` 仓库已包含：

```text
README.md
SHA256SUMS.txt
tplink_archer_c7v5_tddpv2_setproduct_rce_2026-06-08/
```

关键材料包括：

```text
technical_report.md
poc_reproduction.md
duplicate_check.md
evidence_hostexec_bridge.txt
static_setproduct_402f40_403120.txt
static_spcmd_404180_404360.txt
screenshots/real1.png
screenshots/real2.png
screenshots/real_01_terminal_reproduction_output.txt
```

完整哈希清单位于：

```text
CVE/SHA256SUMS.txt
```

## 发送前检查

发送前建议确认：

- 将 `email_body.txt` 中的 GitHub 链接替换为真实可访问链接。
- 确认仓库公开或已向接收方授权访问。
- 不在邮件中直接附带 `sh_bridge.c`、复现脚本或大量 PNG 文件。
- 如担心公开 PoC 风险，可先使用私有仓库，并在邮件中说明可按需授权访问。

