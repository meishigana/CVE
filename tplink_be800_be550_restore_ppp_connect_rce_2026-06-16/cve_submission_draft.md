# CVE Submission Draft

## Title

TP-Link Archer BE800 and BE550 unsafe authenticated configuration restore permits rootfs file write and root PPP command execution

## Vulnerability Type

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- CWE-73: External Control of File Name or Path
- CWE-78: OS Command Injection / command execution as a consequence of restored service configuration

## Affected Products

- TP-Link Archer BE800 v1 firmware `1.4.1 Build 20260401`
- TP-Link Archer BE550 v2 / BE9300 v2 firmware `1.3.1 Build 20260403`

## Short Description

TP-Link Archer BE800 v1 firmware `1.4.1 Build 20260401` and Archer BE550 v2 / BE9300 v2 firmware `1.3.1 Build 20260403` contain an authenticated configuration restore vulnerability. The LuCI restore handler extracts an uploaded backup archive directly under `/` using `tar -xzC/` without validating archive members against a whitelist. An authenticated administrator can restore a crafted archive that writes `/etc/config/network` with a PPP `connect` command. TP-Link's PPP netifd helper passes this command to root `pppd`, which executes it through `/bin/sh -c` on the tty-channel PPP path.

## Technical Details

The vulnerable restore implementation streams uploaded backup data to:

```sh
tar -xzC/ >/dev/null 2>&1
```

Relevant source locations:

- `gpl_focus/GPL_Archer_BE800v1/Iplatform/openwrt/ibase/luci/src/modules/admin-full/luasrc/controller/admin/system.lua:185`
- `gpl_focus/GPL_Archer_BE800v1/Iplatform/openwrt/ibase/luci/src/modules/admin-full/luasrc/controller/admin/system.lua:227-240`
- `gpl_focus/GPL_Archer_BE550v2.6_BE9300v2.6/Iplatform/openwrt/ibase/luci/src/modules/admin-full/luasrc/controller/admin/system.lua:185`
- `gpl_focus/GPL_Archer_BE550v2.6_BE9300v2.6/Iplatform/openwrt/ibase/luci/src/modules/admin-full/luasrc/controller/admin/system.lua:227-240`

Because extraction is rooted at `/`, an archive member named `etc/config/network` writes `/etc/config/network`. No archive member whitelist, path allowlist, symlink rejection, or temporary-directory validation was identified in the reviewed restore path.

The normal admin restore route is authenticated under the root LuCI admin tree:

- `gpl_focus/GPL_Archer_BE800v1/Iplatform/openwrt/ibase/luci/src/modules/admin-full/luasrc/controller/admin/index.lua:28-29`
- `gpl_focus/GPL_Archer_BE550v2.6_BE9300v2.6/Iplatform/openwrt/ibase/luci/src/modules/admin-full/luasrc/controller/admin/index.lua:28-29`

## PPP Execution Chain

A crafted restore archive writes `/etc/config/network` with:

```text
config interface 'pocppp'
	option proto 'ppp'
	option device '/dev/null'
	option username 'poc'
	option password 'poc'
	option connect 'id > /tmp/tplink_be_ppp_connect_poc'
```

The PPP helper declares and reads `connect:file`, then starts `/usr/sbin/pppd` and passes `connect "$connect"`:

- BE800 `gpl_focus/GPL_Archer_BE800v1/qca_95xx_12_1/package/network/services/ppp/files/ppp.sh:68-76`
- BE800 `gpl_focus/GPL_Archer_BE800v1/qca_95xx_12_1/package/network/services/ppp/files/ppp.sh:136-160`
- BE550 `gpl_focus/GPL_Archer_BE550v2.6_BE9300v2.6/qca_95xx_12_2/package/network/services/ppp/files/ppp.sh:68-76`
- BE550 `gpl_focus/GPL_Archer_BE550v2.6_BE9300v2.6/qca_95xx_12_2/package/network/services/ppp/files/ppp.sh:136-160`

TP-Link's local `pppd` source treats `connect` as a shell command:

- `inout/firmware/gpl/tp-link/extracted/GPL_Archer_BE800v1/Iplatform/packages/opensource/pppd/src/pppd/tty.c:183-187`
- `inout/firmware/gpl/tp-link/extracted/GPL_Archer_BE800v1/Iplatform/packages/opensource/pppd/src/pppd/main.c:1862-1868`

The command is triggered when the restored PPP interface is brought up through LuCI apply, network restart, `/sbin/ifup`, or reboot. The PoC targets an added `proto ppp` interface; default PPPoE should not be assumed affected by this exact path without separate proof.

## Supporting Impact

The same restore primitive can also write other rootfs-relative files, including:

- `/etc/rc.local`, which OpenWrt executes through `/etc/init.d/done` after reboot.
- `/etc/config/openvpn` plus referenced scripts under `/etc/openvpn/`, which can trigger OpenVPN script hooks if a valid instance is started.

These are supporting impact paths. The recommended CVE framing is the unsafe restore-to-rootfs write and restored PPP `connect` execution chain.

## Proof of Concept

Benign local verifier scripts are included:

- `poc/verify_tplink_be_restore_ppp_connect_rce_chain_2026_06_16.sh`
- `poc/verify_tplink_be_restore_rc_local_rce_chain_2026_06_16.sh`
- `poc/verify_tplink_be_restore_openvpn_rce_chain_2026_06_16.sh`

The primary PPP PoC archive shape is:

```text
etc/config/network
```

The local harness confirms that TP-Link's PPP script passes:

```text
connect
id > /tmp/tplink_be_ppp_connect_poc
```

to `/usr/sbin/pppd` on both BE800 and BE550 GPL PPP scripts.

## Severity

Suggested conservative CVSS v3.1:

```text
CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H = 6.8 Medium
```

This assumes the attacker needs valid administrator credentials and access to the management interface from the local/adjacent network. If the management interface is reachable from a broader network, or if the CNA treats web-admin-to-device-root as a stronger privilege boundary, the score may be adjusted.

## Known Limitations

- This is not claimed as unauthenticated RCE.
- Full production rootfs extraction from the official `.bin` images has not been achieved locally.
- Real-device upload/network-trigger marker proof is still pending.
- The PPP chain is source/harness verified but still needs real-device or QEMU runtime proof.
- A possible `niu` restore route without local `sysauth` exists in GPL source, but production reachability is unconfirmed and is not claimed here.

## Recommended Fix

- Extract backup archives only to a temporary directory.
- Validate the full archive manifest before copying files into place.
- Use a strict backup-file whitelist.
- Reject absolute paths, `..`, symlinks, hardlinks, device nodes, FIFOs, startup files, and service execution hooks.
- Do not preserve attacker-controlled ownership, mode, or special-file metadata.

## Reporter Notes

This may overlap with prior TP-Link configuration import/restore vulnerability families. I did not find local evidence that the listed BE800/BE550/BE9300 firmware versions are publicly covered for this restore-to-PPP-connect chain or the broader restore-to-rootfs write primitive. Please classify as a new CVE, new affected-product record, or variant according to vendor/CNA root-cause tracking.
