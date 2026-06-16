# TP-Link Archer BE800/BE550 Unsafe Configuration Restore Rootfs Write

## Summary

TP-Link Archer BE800 v1 firmware `1.4.1 Build 20260401` and Archer BE550 v2 / BE9300 v2 firmware `1.3.1 Build 20260403` contain configuration restore handlers that stream the uploaded backup archive directly into `tar` with extraction rooted at `/`.

The restore implementation does not validate archive member names against a whitelist before extraction. A crafted backup can therefore create or replace rootfs-relative paths such as `etc/config/network`, `etc/config/openvpn`, `etc/openvpn/*`, or `etc/rc.local`. The strongest current RCE chain is restored `/etc/config/network` to PPP `connect`: a crafted config can cause TP-Link's PPP netifd helper to pass an attacker-controlled `connect` command to root `pppd`, whose source executes it through `/bin/sh -c` on the tty-channel path.

This report is intentionally conservative: the confirmed `admin-full` and `admin-mini` boundaries are authenticated administrator access to the web configuration restore feature. A possible `niu` route without local `sysauth` exists in GPL source, but production reachability is not confirmed and is not claimed as unauthenticated RCE. Full production-firmware or real-device end-to-end execution has not yet been completed in this workspace.

## Affected Products

### Archer BE800 v1

- Firmware archive: `inout/firmware/archives/tp-link/Archer BE800v1_260401.zip`
- Firmware version: `1.4.1 Build 20260401`
- Firmware bin: `be800v1-up-all-ver1-4-1-P1[20260401-rel14784]_sign_2026-04-01_05.21.50.bin`
- Zip SHA256: `ef2885965a529ea719d44a55392ae8dd4811408e48165850343f74644824e7b5`
- Bin SHA256: `8cc0888a92b0a36ed97f04e175489affd1d3573c953f2c1c0ebd9c3996fe9c01`

### Archer BE550 v2 / BE9300 v2

- Firmware archive: `inout/firmware/archives/tp-link/Archer BE550v2_260403.zip`
- Firmware version: `1.3.1 Build 20260403`
- Firmware bin: `be550v2-be9300v2-up-all-ver1-3-1-P1[20260403-rel18661]_sign_2026-04-03_05.34.46.bin`
- Zip SHA256: `a6106666c612851736f9574d0e8c810f78c1e1834ca9b4601d02814426c6bf6a`
- Bin SHA256: `14459cc129b1e186c195c9d6ebb5a76cc27e3196bcba6d14d5225cadb89f8a17`

## Root Cause

The authenticated LuCI restore path defines:

```sh
tar -xzC/ >/dev/null 2>&1
```

and writes uploaded archive chunks directly to this command through `io.popen()`. Because extraction uses `-C /` and no archive member whitelist is applied first, normal relative archive names are interpreted as rootfs-relative paths.

Core restore evidence:

- BE800 `gpl_focus/GPL_Archer_BE800v1/Iplatform/openwrt/ibase/luci/src/modules/admin-full/luasrc/controller/admin/system.lua:185`
- BE800 upload stream to `io.popen(restore_cmd, "w")`: same file around lines `227-240`
- BE550 corresponding file: `gpl_focus/GPL_Archer_BE550v2.6_BE9300v2.6/Iplatform/openwrt/ibase/luci/src/modules/admin-full/luasrc/controller/admin/system.lua:185`

Additional same-pattern restore handlers exist in the GPL LuCI source:

- `admin-mini`: `gunzip | tar -xC/ >/dev/null 2>&1`
- `niu`: `tar -xzC/ >/dev/null 2>&1`

These additional handlers reinforce that the vulnerable primitive is systemic in the shipped source tree, but the current report does not claim they are unauthenticated.

## Authentication Boundary

The normal `admin` LuCI tree is protected by root web authentication:

- BE800 `gpl_focus/GPL_Archer_BE800v1/Iplatform/openwrt/ibase/luci/src/modules/admin-full/luasrc/controller/admin/index.lua:28-29`
- BE550 corresponding file: `gpl_focus/GPL_Archer_BE550v2.6_BE9300v2.6/Iplatform/openwrt/ibase/luci/src/modules/admin-full/luasrc/controller/admin/index.lua:28-29`

The `mini` tree is also protected with `page.sysauth = "root"` in `mini/index.lua`.

The GPL `niu/system/backup` route contains the same `tar -xzC/` restore pattern and no local `sysauth` binding was found under `modules/niu`. However, the production image could omit this module, and local product config marks some LuCI modules as disabled or broken. Without production rootfs or real-device route proof, this remains an unauthenticated-route candidate only.

## Impact Chains

### PPP `connect` Execution Through `/etc/config/network`

A restored `etc/config/network` can define a `proto ppp` interface with:

```text
option connect 'id > /tmp/tplink_be_ppp_connect_poc'
```

The TP-Link/OpenWrt PPP protocol script passes `connect` to `/usr/sbin/pppd`:

- BE800 `gpl_focus/GPL_Archer_BE800v1/qca_95xx_12_1/package/network/services/ppp/files/ppp.sh:68-76`
- BE800 same file around `136-160`
- BE550 corresponding file under `qca_95xx_12_2/package/network/services/ppp/files/ppp.sh`

The TP-Link local `pppd` source treats `connect` as a shell command:

- `inout/firmware/gpl/tp-link/extracted/GPL_Archer_BE800v1/Iplatform/packages/opensource/pppd/src/pppd/tty.c:183-187`
- `inout/firmware/gpl/tp-link/extracted/GPL_Archer_BE800v1/Iplatform/packages/opensource/pppd/src/pppd/main.c:1862-1868`

This is the best current CVE chain because it is a restored configuration field flowing into a root service execution boundary. The current PoC targets an added `proto ppp` interface. Default PPPoE should not be assumed affected by this exact path without additional runtime proof.

### Persistent Startup Execution Through `/etc/rc.local`

OpenWrt startup runs `/etc/rc.local` from the `done` init script:

- BE800 `gpl_focus/GPL_Archer_BE800v1/qca_95xx_12_1/package/base-files/files/etc/init.d/done:10-12`
- BE550 `gpl_focus/GPL_Archer_BE550v2.6_BE9300v2.6/qca_95xx_12_2/package/base-files/files/etc/init.d/done:10-12`

Relevant logic:

```sh
[ -f /etc/rc.local ] && {
	sh /etc/rc.local
}
```

A crafted restore archive containing `etc/rc.local` can therefore persist attacker-controlled commands that execute after reboot.

Important caveat: LuCI also contains a normal authenticated startup editor for `/etc/rc.local`. For that reason, the strongest CVE framing is not "admin can edit rc.local"; it is that the restore operation accepts arbitrary rootfs archive members and is not constrained to a safe backup file whitelist.

### OpenVPN Script Execution Through Restored UCI Config

The OpenVPN init scripts accept script-related directives from UCI and start OpenVPN as root. A restore archive can place both `etc/config/openvpn` and referenced scripts under `etc/openvpn/`.

This chain is useful supporting evidence but has duplicate risk with prior public TP-Link OpenVPN/import CVEs and depends on OpenVPN instance start conditions.

## Suggested CWE

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- CWE-73: External Control of File Name or Path
- CWE-78: OS Command Injection / command execution as a consequence of restored startup or service configuration

## Suggested CVSS

Conservative CVSS v3.1:

```text
CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H = 6.8 Medium
```

Rationale:

- The attacker is assumed to need authenticated administrator access.
- The management service is conservatively treated as adjacent/LAN reachable.
- Successful exploitation can modify persistent root-owned files and can lead to root command execution through startup or service scripts.

## Current Validation Status

Confirmed:

- GPL source restore command extracts backup archives under `/`.
- No member whitelist was identified before extraction in the reviewed restore handlers.
- Local archive semantic PoC proves `etc/config/network` and `etc/rc.local` restore paths.
- PPP harness proves restored `connect` reaches the `pppd` argument boundary on BE800 and BE550 GPL scripts.
- TP-Link local `pppd` source treats `connect` as shell command execution.

Not yet confirmed:

- Production firmware rootfs extraction from the official `.bin` images.
- Real-device upload, reboot, and marker-file proof.
- HTTP request/response capture from the production web UI.
- Whether production UI exposes the `niu` restore variant.

## Recommended Remediation

- Do not extract uploaded backup archives directly under `/`.
- Extract to a temporary directory and validate the complete archive manifest first.
- Allow only a strict whitelist of expected backup configuration paths.
- Reject absolute paths, `..`, symlinks, hardlinks, device nodes, FIFOs, and any startup/service-control paths.
- Reject or normalize metadata that could alter ownership, permissions, or special file types.
- Copy validated files into place using controlled application logic instead of raw `tar -C /`.
