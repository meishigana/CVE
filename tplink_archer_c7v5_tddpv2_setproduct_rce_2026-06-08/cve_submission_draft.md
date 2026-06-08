# CVE 提交草案：TP-Link Archer C7 V5 TDDPv2 setProductName 命令注入 RCE

## 标题

TP-Link Archer C7(US) V5 firmware 220715 TDDPv2 setProductName command injection

## 漏洞类型

- CWE：CWE-78
- 类型：OS Command Injection / Remote Code Execution
- 影响组件：`/usr/bin/tddp`
- 协议入口：TDDPv2 UDP service
- 子命令：`spCmd` command byte `0x52`
- 处理链路：`TDDPv2 spCmd -> 0x52 -> setProductName -> tddp_execCmd -> /bin/sh -c`

## 受影响产品与版本

已验证受影响：

- Product: TP-Link Archer C7(US) V5
- Firmware: `Archer C7(US)_V5.0_220715`
- Firmware file: `c7v5_us-up-ver1-2-1-P1[20220715-rel19099]_2022-07-15_17.44.43`
- Target binary: `/usr/bin/tddp`
- `/usr/bin/tddp` SHA256: `6ff6ff1fd2e05fa33854e8995906ac7f5df7c9e2612439bfd199948f61b308db`

未确认范围：

- Archer C7 其他区域版本，如 EU/JP/RU。
- Archer A7/C7 其他构建日期。
- 其他包含相同或相近 TDDPv2 `setProductName` 实现的 TP-Link 固件。

## 漏洞描述

TP-Link Archer C7(US) V5 firmware 220715 中的 `/usr/bin/tddp` 在处理 TDDPv2 `spCmd` 子命令 `0x52` 时，会将数据包中的 product name 字段拼接进 shell 命令，并通过 `/bin/sh -c` 执行。该处理逻辑只过滤了少量 shell 元字符，例如反引号、管道符、分号和 `&`，但没有阻止 `$`、括号和单引号组合形成的 command substitution。

攻击者在可访问 TDDPv2 服务的网络位置构造合法 TDDPv2 数据包后，可以使 product name 字段进入 `grep/sed/echo` 命令模板，并触发任意命令执行。

## 根因摘要

关键过滤逻辑只检查以下字符：

```text
` | ; &
```

但 payload 可以使用如下形态绕过过滤：

```text
A'$(echo TDDP_RCE>/tmp/pwned)'
```

该 payload 进入命令模板后会触发 shell command substitution：

```sh
grep "product_name" /tmp/cc-tmp >/dev/null 2>&1 && sed -i 's/product_name:.*/product_name:A'$(echo TDDP_RCE>/tmp/pwned)'/g' /tmp/cc-tmp || echo "product_name:A'$(echo TDDP_RCE>/tmp/pwned)'" >> /tmp/cc-tmp
```

## 复现摘要

在本地授权仿真环境中，发送 TDDPv2 `0x52` payload 后：

```text
sent=60 status=0x00
PWNED_CREATED
/tmp/pwned content: TDDP_RCE
```

bridge argv 日志显示，目标程序实际调用了 `/bin/sh -c`，并且注入 payload 位于 shell 命令字符串中：

```text
argv[0]=sh
argv[1]=-c
argv[2]=grep "product_name" /tmp/cc-tmp ... A'$(echo TDDP_RCE>/tmp/pwned)' ...
```

## 安全影响

成功利用后，攻击者可在路由器上以 `tddp` 服务运行权限执行任意系统命令。典型影响包括：

- 读取或篡改设备配置。
- 修改网络、DNS、防火墙或启动项。
- 下载和运行恶意程序。
- 建立持久化控制或横向移动入口。
- 导致设备拒绝服务或完全失陷。

## CVSS 初评

保守建议：

```text
CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 8.8 High
```

理由：

- TDDPv2 通常面向局域网/相邻网络服务，暂按 `AV:A` 保守评估。
- 当前 PoC 未依赖 Web 登录态。
- 成功后可执行系统命令，C/I/A 均为 High。

如果厂商或真机复现确认该服务在普通 LAN 下可直接访问且 TDDPv2 协议密钥/认证不构成有效权限要求，可考虑：

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical
```

## 与已公开 CVE 的关系

初步检索未发现完全重复的公开 CVE 或 PoC。存在相近但不完全重复的公开漏洞：

- `CVE-2021-42232`：TP-Link Archer A7(US) V5 firmware 210519 的 `/usr/bin/tddp` 命令注入，公开材料指向 `401EA0` 附近的 tftp 参数拼接，过滤 `;` 不充分，可使用 `||` 注入。该漏洞影响 A7 V5 旧固件，不是本次 C7 V5 220715 的 `0x52 setProductName/product_name` 链路。
- `CVE-2025-9377`：TP-Link Archer C7(EU) V2 和 TL-WR841N/ND(MS) V9 的 authenticated RCE，入口为 Parental Control page，不是 TDDPv2 `setProductName`。

因此建议作为独立漏洞或新变体提交，同时在提交中主动披露上述相近 CVE 以降低重复争议。

## 已知限制

当前复现基于本地授权仿真：

- 原始 `/usr/bin/tddp` 未修改。
- rootfs 为固件解包副本。
- 因 Docker/WSL 缺少 MIPS `binfmt_misc`，隔离 rootfs 中 `/bin/sh` 使用 host-exec bridge 转发到原始 MIPS busybox shell。
- bridge 只记录 argv 并转发 shell 执行，不直接创建 `/tmp/pwned`。

建议提交前补充：

- 真机复现截图或日志。
- 完整系统 QEMU 复现，移除 host-exec bridge。
- 确认 TDDPv2 服务端口、暴露面、默认认证/密钥前提。
- 检查最新固件是否仍存在同一链路。

