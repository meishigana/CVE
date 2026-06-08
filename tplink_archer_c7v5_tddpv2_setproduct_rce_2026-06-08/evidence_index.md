# 证据索引

## 核心证据

### 动态复现证据

文件：

```text
evidence_hostexec_bridge.txt
```

关键内容：

```text
PWNED_CREATED
TDDP_RCE
argv[0]=sh
argv[1]=-c
argv[2]=grep "product_name" /tmp/cc-tmp ... A'$(echo TDDP_RCE>/tmp/pwned)' ...
```

说明：

- 证明 TDDPv2 payload 被目标程序接受。
- 证明 payload 进入 `/bin/sh -c` 命令字符串。
- 证明 command substitution 产生实际执行效果。

### 复现脚本

文件：

```text
verify_tddpv2_hostexec_bridge.sh
```

说明：

- 自动构建隔离 rootfs。
- 启动 `qemu-mips-static` 下的 `/usr/bin/tddp`。
- 构造 TDDPv2 `0x52` payload。
- 检查 `/tmp/pwned` 和 argv 日志。

### bridge 源码

文件：

```text
sh_bridge.c
```

说明：

- 用于解决当前 Docker/WSL 环境缺 MIPS `binfmt_misc` 时 shell 子进程无法继续执行的问题。
- 只记录 argv 并调用 `qemu-mips-static -L / /bin/busybox sh`。
- 不直接创建 `/tmp/pwned`。

### 静态反汇编证据

文件：

```text
static_spcmd_404180_404360.txt
static_setproduct_402f40_403120.txt
```

关键点：

- `0x404250` 附近比较子命令 `0x52`。
- `0x40425c` 跳转到 `0x402f50`。
- `0x403018` / `0x40301c` 选择 payload 偏移。
- `0x403044` 之后循环检查 4 个非法字符。
- `0x403098`、`0x4030b0`、`0x4030c0` 附近执行命令模板。

## 哈希

目标 `/usr/bin/tddp`：

```text
6ff6ff1fd2e05fa33854e8995906ac7f5df7c9e2612439bfd199948f61b308db
```

bridge：

```text
ac1d931093b92c24e009bcea489396b204c97bb4ad7cd869c87201141bf8bd0c
```

## 原始证据位置

工作目录中的原始证据仍保留在：

```text
inout/work/deepdive/tplink_tddpv2_setproduct_hostexec_bridge_2026_06_08/evidence.txt
inout/work/deepdive/tplink_tddpv2_setproduct_hostexec_bridge_2026_06_08/verify_tddpv2_hostexec_bridge.sh
inout/work/deepdive/tplink_tddpv2_setproduct_hostexec_bridge_2026_06_08/sh_bridge.c
inout/work/deepdive/tplink_tddpv2_setproduct_402f40_403120_2026_06_08.txt
inout/work/deepdive/tplink_tddpv2_spcmd_404180_404360_2026_06_08.txt
```
