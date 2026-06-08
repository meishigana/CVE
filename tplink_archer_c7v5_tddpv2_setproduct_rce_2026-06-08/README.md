# TP-Link Archer C7(US) V5 TDDPv2 `setProductName` OS Command Injection

Date prepared: 2026-06-08

## Summary

This directory contains materials prepared for a CVE assignment request concerning a suspected OS command injection vulnerability in TP-Link Archer C7(US) V5 firmware `Archer C7(US)_V5.0_220715`.

The affected component is:

```text
/usr/bin/tddp
```

The observed vulnerable path is:

```text
TDDPv2 spCmd -> command byte 0x52 -> setProductName -> product_name command template -> tddp_execCmd -> /bin/sh -c
```

The issue appears to result from incomplete shell metacharacter neutralization before attacker-controlled product name data is embedded into shell command strings.

## Affected Version

Verified firmware image:

```text
Archer C7(US)_V5.0_220715
c7v5_us-up-ver1-2-1-P1[20220715-rel19099]_2022-07-15_17.44.43
```

Target binary SHA256:

```text
6ff6ff1fd2e05fa33854e8995906ac7f5df7c9e2612439bfd199948f61b308db  /usr/bin/tddp
```

## Validation Status

The issue has been reproduced in a local, authorized firmware-emulation laboratory environment using the original `/usr/bin/tddp` binary extracted from the firmware image. The target binary was not modified.

Full real-device reproduction is not yet completed. The emulated environment strongly indicates the vulnerability exists, and additional real-device evidence can be provided upon request.

Important limitation:

The dynamic reproduction was performed in a Docker/WSL-based local firmware-emulation environment. Because this environment does not provide MIPS `binfmt_misc` support for child process execution, `/bin/sh` inside the isolated rootfs was temporarily replaced with a host-exec bridge. The bridge records argv and forwards execution to the original MIPS busybox shell through `qemu-mips-static`; it does not directly create the proof marker file.

## Severity Assessment

Suggested CVSS v3.1:

```text
CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 8.8 High
```

This score is conservative because TDDPv2 network exposure and authentication assumptions should be confirmed by the vendor or on physical hardware.

Environmental score may vary. If TDDPv2 is reachable from WAN, adjust to `AV:N`, which may result in `9.8 Critical`.

## Duplicate Check

No exact public duplicate was found for the following combination:

```text
TP-Link Archer C7(US) V5 firmware 220715
/usr/bin/tddp
TDDPv2 command byte 0x52
setProductName/product_name
shell command substitution command injection
```

Related but not exact duplicate:

- `CVE-2021-42232`: TP-Link Archer A7(US) V5 `/usr/bin/tddp` command injection in a different tftp parameter handling path.
- `CVE-2025-9377`: TP-Link Archer C7(EU) V2 authenticated RCE through the Parental Control page, not this TDDPv2 `setProductName` path.

## Files

Core reports:

```text
technical_report.md
poc_reproduction.md
duplicate_check.md
evidence_index.md
cve_submission_draft.md
```

Email materials:

```text
email_body.txt
email_submission_report.md
```

Evidence:

```text
evidence_hostexec_bridge.txt
static_setproduct_402f40_403120.txt
static_spcmd_404180_404360.txt
screenshots/real1.png
screenshots/real2.png
screenshots/real_01_terminal_reproduction_output.txt
```

Auxiliary reproduction files:

```text
verify_tddpv2_hostexec_bridge.sh
sh_bridge.c
capture_real_repro_screenshots.ps1
```

## Integrity

Repository-level file hashes are available in:

```text
../SHA256SUMS.txt
```

Key evidence hashes are also included in `email_body.txt`.

