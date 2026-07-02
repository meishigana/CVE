# Team Vulnerability CVE Submission Batch - Selected 15

Generated: 2026-07-02

This folder contains 15 draft-ready CVE/vendor disclosure packages selected from E:\\competition\\漏洞\\vulns. Selection prioritized local team-generated TrendNet reports with PoC files and large FirmRec/simexp evidence sets. Public existing-CVE or paper-derived iDirect/Newtec items were not selected for this batch to reduce duplicate-submission risk.

## Selected Packages

| # | Package | Title | Type | CWE | CVSS | PoC | Evidence |
|---|---|---|---|---|---|---:|---:|
| 1 | 01_wlc100p-netifd | CVE-XXXX-XXXX1: TEW-WLC100P netifd DHCP blobmsg Stack Overflow | Stack-based Buffer Overflow / RCE | CWE-121 | 9.8 Critical | 1 | 3 |
| 2 | 02_wlc100-nginx | CVE-XXXX-XXXX2: TEW-WLC100 nginx HTTP Header Stack Overflow | Stack-based Buffer Overflow / RCE | CWE-121 | 9.8 Critical | 1 | 5 |
| 3 | 03_821dap-mycli-time-overflow | CVE-XXXX-XXXX3: TEW-821DAP mycli Time/Syslog UCI Stack Overflow | Stack-based Buffer Overflow / RCE | CWE-121 | 9.8 Critical | 1 | 96 |
| 4 | 04_821dap-mycli-wifi-overflow | CVE-XXXX-XXXX4: TEW-821DAP mycli Wifi VAP/MAC Filter UCI Stack Overflow | Stack-based Buffer Overflow / RCE | CWE-121 | 9.8 Critical | 1 | 96 |
| 5 | 05_821dap-ssi-wan-overflow | CVE-XXXX-XXXX5: TEW-821DAP cgi/ssi WAN Config Stack Overflow + Command Injection | Stack-based Buffer Overflow / RCE | CWE-121 | 9.8 Critical | 1 | 80 |
| 6 | 06_821dap-ssi-remote-cmdi | CVE-XXXX-XXXX6: TEW-821DAP cgi/ssi REMOTE_ADDR Command Injection | Command Injection / RCE | CWE-77 | 9.8 Critical | 1 | 80 |
| 7 | 07_751wic-apd-time-cmdi | CVE-XXXX-XXXX9: TV-IP751WIC alphapd Time Command Injection | Command Injection / RCE | CWE-77 | 9.8 Critical | 1 | 137 |
| 8 | 08_751wic-apd-wifi-key-overflow | CVE-XXXX-XXXX10: TV-IP751WIC alphapd Wifi Key/SSID Stack Overflow | Stack-based Buffer Overflow / RCE | CWE-121 | 9.8 Critical | 1 | 137 |
| 9 | 09_751wic-apd-password-overflow | CVE-XXXX-XXXX11: TV-IP751WIC alphapd Multi-Password Stack Overflow | Stack-based Buffer Overflow / RCE | CWE-121 | 9.8 Critical | 1 | 137 |
| 10 | 10_823dru-rc-bof | CVE-XXXX-XXXX: TEW-823DRU sbin/rc NVRAM strcpy Stack Overflow | Stack-based Buffer Overflow / RCE | CWE-121 | 9.8 Critical | 1 | 553 |
| 11 | 11_823dru-rc-cmdi | CVE-XXXX-XXXX: TEW-823DRU sbin/rc NVRAM Command Injection | Command Injection / RCE | CWE-77 | 9.8 Critical | 1 | 553 |
| 12 | 12_823dru-ssi-cmdi | CVE-XXXX-XXXX: TEW-823DRU cgi/ssi Multi-Vector Command Injection | Command Injection / RCE | CWE-77 | 9.8 Critical | 1 | 553 |
| 13 | 13_755ap-mycli-bof | CVE-XXXX-XXXX: TEW-755AP sbin/mycli UCI Wifi Config Stack Overflow | Stack-based Buffer Overflow / RCE | CWE-121 | 9.8 Critical | 1 | 374 |
| 14 | 14_755ap-ssi-cmdi | CVE-XXXX-XXXX: TEW-755AP cgi/ssi Multi-Vector Command Injection | Command Injection / RCE | CWE-77 | 9.8 Critical | 1 | 374 |
| 15 | 15_755ap-ssi-bof | CVE-XXXX-XXXX: TEW-755AP cgi/ssi WAN Config Stack Overflow | Stack-based Buffer Overflow / RCE | CWE-121 | 9.8 Critical | 1 | 374 |

## Next External-Submission Checklist

- Run duplicate CVE searches for each title, product, component, and sink function before filing.
- Confirm exact firmware filenames and official product names against vendor advisory format.
- Keep exploit details limited to controlled reproduction material when sending to the vendor.
- Add vendor case IDs and CVE IDs after assignment.
