# CVE Request Material: TP-Link Archer BE800/BE550 Unsafe Configuration Restore to Root PPP Command Execution

## Summary

TP-Link Archer BE800 v1 firmware `1.4.1 Build 20260401` and Archer BE550 v2 / BE9300 v2 firmware `1.3.1 Build 20260403` appear to allow an authenticated administrator to restore a crafted configuration backup archive whose entries are extracted directly under `/` without a file/path whitelist.

The strongest current RCE chain is through restored `/etc/config/network`: a crafted backup can define a `proto ppp` interface with attacker-controlled `option connect`, and the TP-Link PPP netifd helper passes that value to root `pppd` as a `connect` command. TP-Link's local `pppd` source executes the `connect` string through `/bin/sh -c` on the tty-channel PPP path.

The same restore primitive can also write startup-controlled files such as `/etc/rc.local`, which can provide persistent root command execution after reboot. That path is treated as supporting impact because LuCI also exposes a normal authenticated startup editor; the cleaner CVE position is the unsafe restore-to-rootfs write plus PPP service execution chain.

This is an authenticated admin-to-root issue. It is not currently claimed as unauthenticated RCE.

## Affected Products

- Vendor: TP-Link
- Product: Archer BE800 v1
- Firmware: `1.4.1 Build 20260401`
- Local firmware archive: `Archer BE800v1_260401.zip`
- Local firmware bin: `be800v1-up-all-ver1-4-1-P1[20260401-rel14784]_sign_2026-04-01_05.21.50.bin`
- Firmware bin SHA256: `8cc0888a92b0a36ed97f04e175489affd1d3573c953f2c1c0ebd9c3996fe9c01`

- Vendor: TP-Link
- Product: Archer BE550 v2 / BE9300 v2
- Firmware: `1.3.1 Build 20260403`
- Local firmware archive: `Archer BE550v2_260403.zip`
- Local firmware bin: `be550v2-be9300v2-up-all-ver1-3-1-P1[20260403-rel18661]_sign_2026-04-03_05.34.46.bin`
- Firmware bin SHA256: `14459cc129b1e186c195c9d6ebb5a76cc27e3196bcba6d14d5225cadb89f8a17`

## Vulnerability Type

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- CWE-73: External Control of File Name or Path
- CWE-78: OS Command Injection / command execution as a consequence of restored service configuration

## Technical Details

The GPL source for both firmware families contains a LuCI restore handler that streams the uploaded backup archive into:

```sh
tar -xzC/ >/dev/null 2>&1
```

Relevant source locations:

- BE800:
  - `gpl_focus/GPL_Archer_BE800v1/Iplatform/openwrt/ibase/luci/src/modules/admin-full/luasrc/controller/admin/system.lua:185`
  - upload handler around lines `227-240`
- BE550 / BE9300:
  - `gpl_focus/GPL_Archer_BE550v2.6_BE9300v2.6/Iplatform/openwrt/ibase/luci/src/modules/admin-full/luasrc/controller/admin/system.lua:185`
  - upload handler around lines `227-240`

No archive member whitelist is applied before extraction. Because extraction is rooted at `/`, a backup archive containing `etc/config/network` writes `/etc/config/network`.

## Primary Impact: PPP `connect` Root Command Execution

The restored `/etc/config/network` can define a PPP interface with:

```text
config interface 'pocppp'
	option proto 'ppp'
	option device '/dev/null'
	option username 'poc'
	option password 'poc'
	option connect 'id > /tmp/tplink_be_ppp_connect_poc'
```

The PPP protocol handler accepts `connect:file`, `disconnect:file`, and `pppd_options`, then passes `connect "$connect"` to `/usr/sbin/pppd`.

Relevant source:

- BE800 `gpl_focus/GPL_Archer_BE800v1/qca_95xx_12_1/package/network/services/ppp/files/ppp.sh:68-76`, `136-160`
- BE550 `gpl_focus/GPL_Archer_BE550v2.6_BE9300v2.6/qca_95xx_12_2/package/network/services/ppp/files/ppp.sh:68-76`, `136-160`

TP-Link's local `pppd` source treats the `connect` option as a shell command:

- `inout/firmware/gpl/tp-link/extracted/GPL_Archer_BE800v1/Iplatform/packages/opensource/pppd/src/pppd/tty.c:183-187`
- `.../tty.c:558`, `696-697`
- `.../main.c:1862-1868`

The current PoC is for an added `proto ppp` interface. Default PPPoE should not be assumed affected by this exact `connect` path without additional runtime proof, because PPPoE replaces the tty-channel connect function.

Verifier output:

- `evidence/verify_ppp_be800_output.txt`
- `evidence/verify_ppp_be550_output.txt`

Detailed source report:

- `evidence/source_report_restore_ppp_connect_rce.md`

## Supporting Impact: `/etc/rc.local` Persistence

The OpenWrt startup path executes `/etc/rc.local`:

- BE800:
  - `gpl_focus/GPL_Archer_BE800v1/qca_95xx_12_1/package/base-files/files/etc/init.d/done:10-12`
- BE550 / BE9300:
  - `gpl_focus/GPL_Archer_BE550v2.6_BE9300v2.6/qca_95xx_12_2/package/base-files/files/etc/init.d/done:10-12`

The relevant logic is:

```sh
[ -f /etc/rc.local ] && {
	sh /etc/rc.local
}
```

Therefore, a crafted restore archive can create or replace `/etc/rc.local` with attacker-controlled commands. After reboot, the commands execute as root. This is supporting impact rather than the main CVE chain.

## Local Proof of Concept

Primary PPP PoC generator/verifier:

- `poc/verify_tplink_be_restore_ppp_connect_rce_chain_2026_06_16.sh`

The benign PoC creates a backup archive with `etc/config/network` and confirms that the restored `connect` option reaches the root `pppd` argv stream.

Supporting rc.local PoC generator/verifier:

- `poc/verify_tplink_be_restore_rc_local_rce_chain_2026_06_16.sh`

The benign PoC creates a backup archive with:

```text
etc/rc.local
```

Example payload used by the verifier:

```sh
#!/bin/sh
id > /tmp/tplink_be_restore_rc_local_poc
```

The local semantic verifier confirms that the archive member is extracted as `etc/rc.local` under the chosen root directory, matching the GPL restore command behavior.

Verifier output:

- `evidence/verify_rc_local_output.txt`

## Reproduction Status

Full real-device reproduction is not yet completed. QEMU full-system validation was assessed but not executed in this workspace because:

- The available WSL environment has `qemu-aarch64` user-mode only; `qemu-system-aarch64` is not installed.
- The official BE800/BE550 `.bin` firmware images are TP-Link `fw-type:Cloud` high-entropy packages.
- Previous local binwalk/segment probes did not recover a usable production root filesystem or kernel.
- Without a production rootfs/kernel or a real device, QEMU would only prove generic OpenWrt/GPL source semantics, not the affected firmware runtime behavior.

Current evidence consists of:

- GPL source evidence for the restore command and boot execution sink.
- Local archive semantics proving the crafted restore archive layout.
- Harness-level PPP argument-flow proof for BE800 and BE550 GPL scripts.

Real-device evidence can be added later by uploading the crafted backup through the authenticated web UI, applying/restarting networking or bringing up the restored PPP interface, and capturing `/tmp/tplink_be_ppp_connect_poc`. Reboot-based `/etc/rc.local` evidence can be captured separately.

## Possible Unauthenticated NIU Route, Not Claimed

The GPL LuCI tree also contains a `niu/system/backup` restore handler that uses `tar -xzC/` and no local `sysauth` binding was found under `modules/niu`. Product configuration marks some LuCI modules as not enabled or broken, and production rootfs extraction is not available, so this report does not claim the NIU route is reachable or unauthenticated in the affected production images. It is a follow-up validation target.

## Duplicate Check

Known related public TP-Link issues include OpenVPN/config import or restore vulnerabilities, especially on Archer AX53 and related models. The closest known family includes:

- CVE-2026-30815: Archer AX53 OpenVPN configuration restore command injection.
- TP-Link FAQ 5055 lists Archer AX53 OpenVPN restore-related CVEs including CVE-2026-30815, CVE-2026-30816, and CVE-2026-30817.
- CVE-2026-9151: VPN configuration import command injection on several Archer AX-series products.

No public record was found during this pass that explicitly covers:

- Archer BE800 v1 `1.4.1 Build 20260401`
- Archer BE550 v2 / BE9300 v2 `1.3.1 Build 20260403`
- the restore-to-PPP `connect` root command execution chain
- the broader restore-to-rootfs write primitive on these BE-series firmware versions

Duplicate or merge risk remains because the root cause is similar to broader unsafe restore/import vulnerability families.

## Suggested Severity

Conservative CVSS v3.1:

```text
CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H
```

Score: 6.8 Medium

Rationale:

- Attack vector is adjacent/local management network under the conservative assumption.
- Valid administrator credentials are required.
- Successful exploitation can execute commands as root after restore and a network/service trigger.

If the management interface is reachable from a broader network, or if the CNA treats web-admin to device-root as a stronger privilege boundary, the score may increase.

## Recommended Fix

- Do not extract uploaded backup archives directly under `/`.
- Validate backup archive structure before extraction.
- Only allow a strict whitelist of expected configuration files.
- Reject absolute paths, `..` path components, symlinks, hardlinks, device nodes, and startup-controlled paths such as `/etc/rc.local` or `/etc/init.d/*`.
- Extract to a temporary directory first, validate file list and metadata, then copy only approved files.

## Files

- `README.md`: this report.
- `email_body.txt`: draft email body for CVE request.
- `evidence/source_report_restore_rootfs_write_rce.md`: detailed restore primitive/source analysis.
- `evidence/source_report_restore_ppp_connect_rce.md`: detailed primary PPP analysis.
- `evidence/firmware_hashes.txt`: local firmware hash scan.
- `evidence/verify_rc_local_output.txt`: local restore archive verifier output.
- `evidence/verify_ppp_be800_output.txt`: BE800 PPP verifier output.
- `evidence/verify_ppp_be550_output.txt`: BE550 PPP verifier output.
- `evidence/verify_openvpn_output.txt`: OpenVPN supporting verifier output.
- `poc/*.sh`: benign local verifier scripts.
