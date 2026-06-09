# TOTOLINK X5000R `exportOvpn` Pre-Authenticated OpenVPN File Disclosure

Date prepared: 2026-06-09

## Summary

This directory contains materials prepared for a CVE assignment request concerning a pre-authenticated OpenVPN export file disclosure and suffix-constrained path traversal issue in TOTOLINK X5000R firmware.

The affected component is:

```text
/web/cgi-bin/cstecgi.cgi
```

The affected handler is:

```text
exportOvpn
```

The verified behavior is not remote code execution. The current evidence supports the following scope:

```text
pre-authenticated OpenVPN profile/archive disclosure
suffix-constrained path traversal using ../ in the username field
```

## Verified Affected Versions

```text
V9.1.0cu.2415_B20250515
V9.1.0cu.2350_B20230313
```

## Vulnerable Request Forms

```text
/cgi-bin/cstecgi.cgi?exportOvpn&type=user&name=<username>&mode=config
/cgi-bin/cstecgi.cgi?exportOvpn&type=user&name=<username>&filetype=gz
```

The parser is position-sensitive:

```text
arg0: contains exportOvpn
arg1: type=user
arg2: username field, such as name=<username> or username=<username>
arg3: mode=config or filetype=gz
```

## Impact

An unauthenticated attacker who can access the router HTTP service can request existing OpenVPN user profile files or archives. If these files contain client certificates, private keys, static keys, server addresses, or reusable VPN credentials, the attacker may obtain VPN access material without authenticating to the web interface.

The traversal behavior is constrained by forced suffixes:

```text
mode=config  -> .ovpn
filetype=gz  -> .tar.gz
```

This should not be described as unrestricted arbitrary file read.

## Validation Status

The issue was reproduced in a local QEMU/chroot CGI harness using the original firmware CGI and libraries. The harness pre-created representative OpenVPN export files in a temporary rootfs to model a configured device runtime state, because the firmware image does not ship with generated user OpenVPN exports by default.

Current evidence does not support an RCE claim. Shell metacharacter and URL-encoded metacharacter tests were performed and did not produce command execution in the available environment.

## Suggested CVSS

Suggested CVSS v3.1:

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5 High
```

The score assumes that OpenVPN export files contain sensitive VPN access material. If a CNA considers the dependency on generated OpenVPN files a stronger environmental limitation, confidentiality impact may be adjusted downward.

## Duplicate Check

No exact public CVE was found for this combination:

```text
TOTOLINK X5000R
V9.1.0cu.2415_B20250515 and V9.1.0cu.2350_B20230313
cstecgi.cgi exportOvpn
pre-authenticated OpenVPN profile/archive disclosure
suffix-constrained path traversal
```

Related but not exact duplicate:

- `CVE-2025-14586`: `exportOvpn&type=user` OS command injection affecting `9.1.0cu.2089_B20211224`.
- `CVE-2025-13184`: unauthenticated Telnet enablement via `action=telnet` on another X5000R firmware.
- `CVE-2025-9934`: `cstecgi.cgi` command injection in function `sub_410C34` via the `pid` argument affecting `V9.1.0cu.2415_B20250515`.

This candidate is scoped to file disclosure and suffix-constrained path traversal, not Telnet enablement or command injection.

## Files

Core reports:

```text
technical_report.md
poc_reproduction.md
duplicate_check.md
evidence_index.md
cve_submission_draft.md
submission_checklist.md
```

Email materials:

```text
email_body.txt
email_submission_report.md
```

Evidence and PoC:

```text
poc_pre_auth_file_disclosure.py
verified_report_zh.md
vulndb_verified_report_zh.md
scripts/
```

## Integrity

Repository-level file hashes are available in:

```text
../SHA256SUMS.txt
```

