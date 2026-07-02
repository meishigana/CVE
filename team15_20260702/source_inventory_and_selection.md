# Complete Source Inventory and Selection Notes

All REPORT.md files under E:\\competition\\漏洞\\vulns were enumerated and classified before selecting the 15-package batch.

| Batch | Directory | Selected | Type | PoC | Evidence | Title | Reason |
|---|---|---|---|---:|---:|---|---|| vulns | vuln-751wic-alphapd-password-overflow | yes | Stack-based Buffer Overflow / RCE | 1 | 137 | CVE-XXXX-XXXX11: TV-IP751WIC alphapd Multi-Password Stack Overflow | Selected |
| vulns | vuln-751wic-alphapd-time-command-injection | yes | Command Injection / RCE | 1 | 137 | CVE-XXXX-XXXX9: TV-IP751WIC alphapd Time Command Injection | Selected |
| vulns | vuln-751wic-alphapd-wifi-key-overflow | yes | Stack-based Buffer Overflow / RCE | 1 | 137 | CVE-XXXX-XXXX10: TV-IP751WIC alphapd Wifi Key/SSID Stack Overflow | Selected |
| vulns | vuln-755ap-mycli-stackoverflow | yes | Stack-based Buffer Overflow / RCE | 1 | 374 | CVE-XXXX-XXXX: TEW-755AP sbin/mycli UCI Wifi Config Stack Overflow | Selected |
| vulns | vuln-755ap-ssi-command-injection | yes | Command Injection / RCE | 1 | 374 | CVE-XXXX-XXXX: TEW-755AP cgi/ssi Multi-Vector Command Injection | Selected |
| vulns | vuln-755ap-ssi-stackoverflow | yes | Stack-based Buffer Overflow / RCE | 1 | 374 | CVE-XXXX-XXXX: TEW-755AP cgi/ssi WAN Config Stack Overflow | Selected |
| vulns | vuln-821dap-mycli-time-syslog-overflow | yes | Stack-based Buffer Overflow / RCE | 1 | 96 | CVE-XXXX-XXXX3: TEW-821DAP mycli Time/Syslog UCI Stack Overflow | Selected |
| vulns | vuln-821dap-mycli-wifi-vap-overflow | yes | Stack-based Buffer Overflow / RCE | 1 | 96 | CVE-XXXX-XXXX4: TEW-821DAP mycli Wifi VAP/MAC Filter UCI Stack Overflow | Selected |
| vulns | vuln-821dap-ssi-filename-command-injection | no | Command Injection / RCE | 1 | 80 | CVE-XXXX-XXXX7: TEW-821DAP cgi/ssi Arbitrary File Command Injection | Excluded for this 15-item batch |
| vulns | vuln-821dap-ssi-ntp-timezone-overflow | no | Stack-based Buffer Overflow / RCE | 1 | 80 | CVE-XXXX-XXXX8: TEW-821DAP cgi/ssi NTP/Timezone Config Stack Overflow | Excluded for this 15-item batch |
| vulns | vuln-821dap-ssi-remote-command-injection | yes | Command Injection / RCE | 1 | 80 | CVE-XXXX-XXXX6: TEW-821DAP cgi/ssi REMOTE_ADDR Command Injection | Selected |
| vulns | vuln-821dap-ssi-wan-config-overflow | yes | Stack-based Buffer Overflow / RCE | 1 | 80 | CVE-XXXX-XXXX5: TEW-821DAP cgi/ssi WAN Config Stack Overflow + Command Injection | Selected |
| vulns | vuln-823dru-cli-command-injection | no | Command Injection / RCE | 1 | 553 | CVE-XXXX-XXXX: TEW-823DRU bin/cli NVRAM Command Injection | Excluded for this 15-item batch |
| vulns | vuln-823dru-rc-command-injection | yes | Command Injection / RCE | 1 | 553 | CVE-XXXX-XXXX: TEW-823DRU sbin/rc NVRAM Command Injection | Selected |
| vulns | vuln-823dru-rc-stackoverflow | yes | Stack-based Buffer Overflow / RCE | 1 | 553 | CVE-XXXX-XXXX: TEW-823DRU sbin/rc NVRAM strcpy Stack Overflow | Selected |
| vulns | vuln-823dru-ssi-command-injection | yes | Command Injection / RCE | 1 | 553 | CVE-XXXX-XXXX: TEW-823DRU cgi/ssi Multi-Vector Command Injection | Selected |
| vulns | vuln-wlc100-nginx | yes | Stack-based Buffer Overflow / RCE | 1 | 5 | CVE-XXXX-XXXX2: TEW-WLC100 nginx HTTP Header Stack Overflow | Selected |
| vulns | vuln-wlc100p-netifd | yes | Stack-based Buffer Overflow / RCE | 1 | 3 | CVE-XXXX-XXXX1: TEW-WLC100P netifd DHCP blobmsg Stack Overflow | Selected |
| vulns2 | vuln-totolink-n600r-cstecgi-main-command-injection | no | Command Injection / RCE | 1 | 2 | CVE-XXXX-XXXX: TOTOLINK N600R cstecgi.cgi Main Dispatcher + System Wrappers Command Injection | Excluded for this 15-item batch |
| vulns2 | vuln-totolink-n600r-cstecgi-popen-command-injection | no | Command Injection / RCE | 1 | 2 | CVE-XXXX-XXXX: TOTOLINK N600R cstecgi.cgi Time/WiFi Service popen() Command Injection | Excluded for this 15-item batch |
| vulns2 | vuln-totolink-n600r-cstecgi-strcpy-stackoverflow | no | Stack-based Buffer Overflow / RCE | 1 | 2 | CVE-XXXX-XXXX: TOTOLINK N600R cstecgi.cgi strcpy/sprintf Multi-Function Stack Overflow | Excluded for this 15-item batch |
| vulns2 | vuln-totolink-n600r-cstecgi-system-command-injection | no | Command Injection / RCE | 1 | 2 | CVE-XXXX-XXXX: TOTOLINK N600R cstecgi.cgi system() Command Injection | Excluded for this 15-item batch |
| vulns2 | vuln-totolink-x5000r-cstecgi-dosystem-command-injection | no | Command Injection / RCE | 1 | 2 | CVE-XXXX-XXXX: TOTOLINK X5000R cstecgi.cgi doSystem() Command Injection | Excluded for this 15-item batch |
| vulns2 | vuln-totolink-x5000r-cstecgi-popen-command-injection | no | Command Injection / RCE | 1 | 2 | CVE-XXXX-XXXX: TOTOLINK X5000R cstecgi.cgi getCurrentTime popen() Command Injection | Excluded for this 15-item batch |
| vulns2 | vuln-totolink-x5000r-cstecgi-strcpy-stackoverflow | no | Stack-based Buffer Overflow / RCE | 1 | 2 | CVE-XXXX-XXXX: TOTOLINK X5000R cstecgi.cgi strcpy/sprintf Stack Overflow | Excluded for this 15-item batch |
| vulns2 | vuln-totolink-x5000r-cstecgi-system-command-injection | no | Command Injection / RCE | 1 | 2 | CVE-XXXX-XXXX: TOTOLINK X5000R cstecgi.cgi Direct system() Command Injection | Excluded for this 15-item batch |
| vulns3 | vuln-idirect-hardcoded-backdoor-credentials | no | Authentication / Credential Issue | 1 | 0 | iDirect Evolution/iSavi/Ranger: Hardcoded Backdoor Credentials (CWE-798) | Excluded: likely duplicate/public-material-heavy |
| vulns3 | vuln-idirect-i1-i2-auth-impersonation | no | Authentication / Credential Issue | 0 | 0 | iDirect i1/i2: Satellite Modem Identity Authentication Bypass (CWE-287) | Excluded: likely duplicate/public-material-heavy |
| vulns3 | vuln-idirect-isavi-ranger-admin-bypass | no | Authentication / Credential Issue | 1 | 0 | iDirect iSavi/Ranger: Remote Web Administration Bypass (CWE-288) | Excluded: likely duplicate/public-material-heavy |
| vulns3 | vuln-idirect-isavi-ranger-xss | no | Cross-Site Scripting | 0 | 0 | iDirect iSavi/Ranger: Cross-Site Scripting via REMOTE_ADDR (CWE-79) | Excluded: likely duplicate/public-material-heavy |
| vulns3 | vuln-idirect-ntc-commit-multicast-command-injection | no | Command Injection / RCE | 1 | 1 | CVE-2024-13502: OS Command Injection in Newtec/iDirect NTC Series Modems | Excluded: likely duplicate/public-material-heavy |
| vulns3 | vuln-idirect-ntc-update-signaling-stackoverflow | no | Stack-based Buffer Overflow / RCE | 0 | 1 | CVE-2024-13503: Stack-Based Buffer Overflow RCE in Newtec/iDirect Update Signaling | Excluded: likely duplicate/public-material-heavy |
| vulns3 | vuln-newtec-mdm2200-buffer-overflow-rce | no | Stack-based Buffer Overflow / RCE | 1 | 1 | Newtec MDM2200: Buffer Overflow RCE via Satellite Signal Injection (CWE-121) | Excluded: likely duplicate/public-material-heavy |
| vulns3 | vuln-newtec-mdm2200-connection-reset | no | Authentication / Credential Issue | 0 | 0 | Newtec MDM2200: Connection Reset Attack via Forward Channel Jamming (CWE-400) | Excluded: likely duplicate/public-material-heavy |
| vulns3 | vuln-newtec-mdm2200-firmware-update-unauth | no | Authentication / Credential Issue | 0 | 1 | Newtec MDM2200: Unauthenticated Firmware Update (CWE-306) | Excluded: likely duplicate/public-material-heavy |
| vulns3 | vuln-newtec-mdm6000-xss | no | Cross-Site Scripting | 0 | 0 | Newtec MDM6000: Cross-Site Scripting in Web Management Interface (CWE-79) | Excluded: likely duplicate/public-material-heavy |

