# Vulnerability Disclosure Materials

This repository contains vulnerability research and coordinated disclosure materials prepared for CVE assignment requests.

The materials are intended to help vendors, CNAs, and security coordinators review reported issues. Each entry is organized as a separate directory containing a technical report, reproduction notes, duplicate-check notes, evidence references, and integrity hashes.

## Current Reports

| Product | Vulnerability | Status | Directory |
| --- | --- | --- | --- |
| TP-Link Archer C7(US) V5 firmware 220715 | TDDPv2 `setProductName` OS command injection | Prepared for CVE request | `tplink_archer_c7v5_tddpv2_setproduct_rce_2026-06-08/` |
| NETGEAR R7000 firmware V1.0.9.18_1.2.27 | ReadyCLOUD `leafp2p_username` to `comm.sh` OS command injection | Prepared for CVE request | `netgear_r7000_readycloud_leafp2p_comm_rce_2026-06-08/` |
| TOTOLINK X5000R firmware 2350/2415 | `exportOvpn` pre-authenticated OpenVPN file disclosure and suffix-constrained path traversal | Prepared for CVE request | `totolink_x5000r_exportovpn_file_disclosure_2026-06-09/` |
| ASUS RT-AX86U Pro firmware 3.0.0.6.102_37436 | `upload_server_ipsec_cert.cgi` authenticated IPsec certificate archive symlink traversal arbitrary file write | Prepared for CVE request | `asus_rt_ax86u_pro_ipsec_cert_symlink_write_2026-06-09/` |

## Repository Integrity

SHA256 hashes for repository files are listed in:

```text
SHA256SUMS.txt
```

Reviewers can use this file to verify that downloaded materials match the versions referenced in disclosure emails.

## Disclosure Policy

These materials are provided for coordinated vulnerability disclosure and defensive security review. They must not be used to test, access, or exploit systems without explicit authorization.

Where exploitability has been validated only in a laboratory or emulated environment, the relevant report states that limitation explicitly. Additional physical-device or full-system emulation evidence can be provided during coordinated handling when required.

## Contact

Reporter: Chuanteng Su

Email: fuhanhan2014@163.com
