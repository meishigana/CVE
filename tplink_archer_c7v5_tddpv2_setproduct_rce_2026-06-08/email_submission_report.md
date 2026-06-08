# 邮件提交报告：TP-Link Archer C7(US) V5 TDDPv2 setProductName RCE

日期：2026-06-08

## 使用说明

本文件用于通过邮件向 MITRE CNA-LR、厂商或相关 CNA 提交漏洞材料。官方目前更推荐使用 CVE Web Form；如确实采用邮件，可将下方英文正文作为邮件主体，并按需附加证据文件。

建议收件人：

```text
cve-assign@mitre.org
```

可选抄送：

```text
cve@mitre.org
cve-request@mitre.org
```

建议主题：

```text
CVE request for TP-Link Archer C7(US) V5 - TDDPv2 setProductName OS command injection
```

敏感材料建议使用 PGP 或加密压缩包发送。不要在公开邮件列表、公开 issue 或社交平台发布完整可利用 PoC。

## 证据附件说明

### 真实屏幕截图

以下文件是真实屏幕截图和对应终端日志：

```text
screenshots/real_01_terminal_reproduction.png
screenshots/real_01_terminal_reproduction_output.txt
```

说明：

- `real_01_terminal_reproduction.png` 来自当前 Windows 桌面可见 PowerShell 窗口截图。
- 窗口中实际执行了 Docker 本地固件仿真复现命令。
- 对应日志 `real_01_terminal_reproduction_output.txt` 包含 `status=0x00`、`PWNED_CREATED`、`TDDP_RCE` 和 `/bin/sh -c` argv 记录。

### 渲染证据图

以下 PNG 是由本机文本证据渲染生成的报告插图，不是交互式桌面截图：

```text
screenshots/01_poc_reproduction_output.png
screenshots/02_materials_directory.png
screenshots/03_duplicate_check_summary.png
```

对应文本源文件：

```text
screenshots/01_poc_reproduction_output.txt
screenshots/02_materials_directory.txt
screenshots/03_duplicate_check_summary.txt
```

建议提交时优先附加真实屏幕截图和原始文本日志；渲染证据图只作为辅助材料。

### 建议附件清单

```text
cve_submission_draft.md
technical_report.md
poc_reproduction.md
duplicate_check.md
evidence_index.md
evidence_hostexec_bridge.txt
verify_tddpv2_hostexec_bridge.sh
sh_bridge.c
static_setproduct_402f40_403120.txt
static_spcmd_404180_404360.txt
screenshots/real_01_terminal_reproduction.png
screenshots/real_01_terminal_reproduction_output.txt
screenshots/01_poc_reproduction_output.png
screenshots/02_materials_directory.png
screenshots/03_duplicate_check_summary.png
```

## Email Body Draft

```text
To: cve-assign@mitre.org
Cc: cve@mitre.org
Subject: CVE request for TP-Link Archer C7(US) V5 - TDDPv2 setProductName OS command injection

Hello MITRE CNA-LR team,

I would like to request a CVE ID for a suspected new vulnerability in TP-Link Archer C7(US) V5 firmware.

Reporter:
Name: [Your Name]
Organization: [Your Organization, if any]
Contact: [Your Email]
Discovery date: 2026-06-08

Vendor:
TP-Link

Affected product:
TP-Link Archer C7(US) V5

Affected firmware:
Archer C7(US)_V5.0_220715
c7v5_us-up-ver1-2-1-P1[20220715-rel19099]_2022-07-15_17.44.43

Affected component:
/usr/bin/tddp

Target binary SHA256:
6ff6ff1fd2e05fa33854e8995906ac7f5df7c9e2612439bfd199948f61b308db

Vulnerability type:
OS command injection / potential remote code execution

CWE:
CWE-78: Improper Neutralization of Special Elements used in an OS Command

Suggested title:
TP-Link Archer C7(US) V5 firmware 220715 TDDPv2 setProductName command injection

Summary:
The /usr/bin/tddp binary in TP-Link Archer C7(US) V5 firmware 220715 appears to contain an OS command injection vulnerability in the TDDPv2 spCmd handler. The issue is reachable through command byte 0x52, which maps to the setProductName handler. The product name value supplied through a TDDPv2 packet is incorporated into shell command strings that are later executed through /bin/sh -c.

The input validation appears to use a narrow denylist. It blocks a small set of shell metacharacters, including backtick, pipe, semicolon, and ampersand, but it does not fully neutralize shell command substitution syntax. A crafted product name can therefore alter shell command execution.

Verified code path:
TDDPv2 spCmd -> command byte 0x52 -> setProductName -> product_name command template -> tddp_execCmd -> /bin/sh -c

Root cause:
The setProductName handler copies product name data from the TDDPv2 packet into an internal buffer, checks only a limited denylist of characters, and then embeds that value into shell command templates used to update product information. Because shell metacharacter handling is incomplete, command substitution remains possible.

Example laboratory payload:
A'$(echo TDDP_RCE>/tmp/pwned)'

Observed shell command string in the lab reproduction:
grep "product_name" /tmp/cc-tmp >/dev/null 2>&1 && sed -i 's/product_name:.*/product_name:A'$(echo TDDP_RCE>/tmp/pwned)'/g' /tmp/cc-tmp || echo "product_name:A'$(echo TDDP_RCE>/tmp/pwned)'" >> /tmp/cc-tmp

Impact:
If reachable in a deployed configuration, successful exploitation may allow an attacker with access to the TDDPv2 service to execute operating system commands with the privileges of the tddp service. This may allow configuration tampering, network traffic manipulation, persistence, malware deployment, or denial of service.

Suggested CVSS v3.1:
CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 8.8 High

CVSS rationale:
This score is intentionally conservative because the TDDPv2 exposure and authentication assumptions should be confirmed by the vendor or on physical hardware. The current laboratory PoC does not rely on a web management login session. If the vendor confirms that the TDDPv2 service is reachable from a normal LAN network without an effective authentication requirement, AV:N may be appropriate, which would raise the score to 9.8 Critical.

Reproduction status:
The issue has been reproduced in a local, authorized firmware-emulation laboratory environment using the original /usr/bin/tddp binary extracted from the firmware image. The target /usr/bin/tddp binary was not modified.

The reproduction sends a TDDPv2 command byte 0x52 packet carrying a crafted product name. The emulated service returns status 0x00, and the injected command creates /tmp/pwned with the content TDDP_RCE.

Key laboratory evidence:
sent=60 status=0x00
PWNED_CREATED
/tmp/pwned
TDDP_RCE

The captured shell argv log shows that the injected value reaches /bin/sh -c:
argv[0]=sh
argv[1]=-c
argv[2]=grep "product_name" /tmp/cc-tmp ... A'$(echo TDDP_RCE>/tmp/pwned)' ...

Attached evidence:
- screenshots/real_01_terminal_reproduction.png
- screenshots/real_01_terminal_reproduction_output.txt
- evidence_hostexec_bridge.txt
- technical_report.md
- poc_reproduction.md
- duplicate_check.md

Important validation note:
The dynamic reproduction was performed in a Docker/WSL-based local firmware-emulation environment. Because this environment does not provide MIPS binfmt_misc support for child process execution, /bin/sh inside the isolated rootfs was temporarily replaced with a host-exec bridge. The bridge records argv and forwards execution to the original MIPS busybox shell through qemu-mips-static. It does not directly create /tmp/pwned. The original /usr/bin/tddp binary was not modified.

I can provide additional real-device or full-system QEMU evidence if required.

Duplicate check:
I checked public CVE and PoC records and did not find an exact duplicate for the following combination:
TP-Link Archer C7(US) V5 firmware 220715 + /usr/bin/tddp + TDDPv2 command byte 0x52 + setProductName/product_name + shell command substitution command injection.

Related but not exact duplicate:

1. CVE-2021-42232
This is a TP-Link Archer A7(US) V5 /usr/bin/tddp command injection in firmware 210519. Public writeups describe a different tftp parameter command injection path near function address 401EA0, where only semicolon is filtered and || can be used for injection. The issue reported here affects Archer C7(US) V5 firmware 220715 and uses the TDDPv2 0x52 setProductName/product_name path near 0x402f50.

2. CVE-2025-9377
This is an authenticated RCE affecting TP-Link Archer C7(EU) V2 and TL-WR841N/ND(MS) V9 through the Parental Control page. It is a web management interface issue and does not cover the TDDPv2 0x52 setProductName path in Archer C7(US) V5 firmware 220715.

References:
NVD CVE-2021-42232:
https://nvd.nist.gov/vuln/detail/CVE-2021-42232

Public CVE-2021-42232 write-up:
https://github.com/mQaLeX/IoT/blob/main/tp-link/Archer%20A7%28US%29_V5_20519_tddp.md

NVD CVE-2025-9377:
https://nvd.nist.gov/vuln/detail/CVE-2025-9377

TP-Link advisory referenced by CVE-2025-9377:
https://www.tp-link.com/us/support/faq/4365/

Suggested remediation:
- Avoid constructing shell commands with product name values or other attacker-controlled input.
- Replace shell command execution with direct file/configuration APIs.
- If shell execution is unavoidable, use strict allowlist validation and robust argument escaping.
- Reject or encode shell-sensitive characters including $, (, ), quotes, backslash, newline, redirection operators, and control characters.
- Add regression tests for TDDPv2 command handlers and product_name update paths.
- Consider disabling or restricting TDDPv2 exposure in production firmware.

Disclosure plan:
I am requesting coordinated handling and a CVE assignment. I do not plan to publish full exploit details before vendor coordination. A reasonable coordinated disclosure timeline would be 90 days from vendor acknowledgement, unless the vendor requests a different schedule or confirms that a fix is available earlier.

Attachments:
1. cve_submission_draft.md
2. technical_report.md
3. poc_reproduction.md
4. duplicate_check.md
5. evidence_index.md
6. evidence_hostexec_bridge.txt
7. verify_tddpv2_hostexec_bridge.sh
8. sh_bridge.c
9. static_setproduct_402f40_403120.txt
10. static_spcmd_404180_404360.txt
11. screenshots/real_01_terminal_reproduction.png
12. screenshots/real_01_terminal_reproduction_output.txt
13. screenshots/01_poc_reproduction_output.png
14. screenshots/02_materials_directory.png
15. screenshots/03_duplicate_check_summary.png

Please let me know if additional information, a minimized PoC, packet capture, real-device reproduction, or full-system QEMU reproduction is required.

Best regards,
[Your Name]
```

## 中文摘要

这版措辞的重点是：

- 不把渲染证据图称为真实截图。
- 明确真实截图文件是 `screenshots/real_01_terminal_reproduction.png`。
- 将结论表述为“已在本地授权固件仿真实验环境复现”，避免把仿真复现夸大为真机复现。
- 保留 CVE 提交价值判断，但主动披露 host-exec bridge 和重复性风险。
- 对外邮件正文使用更保守的 `potential remote code execution`，并说明如果部署环境中 TDDPv2 可达，则影响可升级为实际 RCE 风险。

