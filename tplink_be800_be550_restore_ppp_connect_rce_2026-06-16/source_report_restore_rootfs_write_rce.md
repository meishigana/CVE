# TP-Link Archer BE800/BE550 Authenticated Config Restore Rootfs Write to Persistent Root Code Execution

## Summary

This is the strongest current CVE candidate in the BE800/BE550 analysis.

The LuCI configuration restore handlers stream an authenticated admin upload directly into `tar` with extraction rooted at `/`. A crafted backup archive can therefore write rootfs-relative paths such as `etc/rc.local`, `etc/config/openvpn`, or `etc/openvpn/poc_up.sh`. Because OpenWrt boot logic executes `/etc/rc.local` through `/etc/init.d/done`, the issue can be turned into persistent root command execution after reboot.

This is not unauthenticated. The confirmed boundary is authenticated web admin/root.

## Affected Local Targets

- TP-Link Archer BE800 v1 firmware archive: `be800v1-up-all-ver1-4-1-P1[20260401-rel14784]_sign_2026-04-01_05.21.50.bin`
- TP-Link Archer BE550 v2 / BE9300 v2 firmware archive: `be550v2-be9300v2-up-all-ver1-3-1-P1[20260403-rel18661]_sign_2026-04-03_05.34.46.bin`
- Local firmware hashes:
  - BE800 zip SHA256: `ef2885965a529ea719d44a55392ae8dd4811408e48165850343f74644824e7b5`
  - BE800 bin SHA256: `8cc0888a92b0a36ed97f04e175489affd1d3573c953f2c1c0ebd9c3996fe9c01`
  - BE550 zip SHA256: `a6106666c612851736f9574d0e8c810f78c1e1834ca9b4601d02814426c6bf6a`
  - BE550 bin SHA256: `14459cc129b1e186c195c9d6ebb5a76cc27e3196bcba6d14d5225cadb89f8a17`
- GPL source packages:
  - `inout/firmware/gpl/tp-link/GPL_Archer_BE800v1.tar.gz`
  - `inout/firmware/gpl/tp-link/GPL_Archer_BE550v2.6_BE9300v2.6.tar.gz`

Official `.bin` runtime rootfs extraction is not currently achieved in this workspace. The published images appear to use TP-Link Cloud/high-entropy packaging; available local tools found gzip/FIT-like signatures but did not recover a usable root filesystem. The strongest evidence is therefore GPL source plus local semantic PoC, not a production rootfs diff.

## Evidence

### Authenticated Route

- BE800 and BE550 `admin` route requires root web auth:
  - `gpl_focus/GPL_Archer_BE800v1/Iplatform/openwrt/ibase/luci/src/modules/admin-full/luasrc/controller/admin/index.lua:28`
  - `gpl_focus/GPL_Archer_BE550v2.6_BE9300v2.6/Iplatform/openwrt/ibase/luci/src/modules/admin-full/luasrc/controller/admin/index.lua:28`
- `page.sysauth = "root"` and `page.sysauth_authenticator = "htmlauth"` protect the admin tree.

### Vulnerable Restore

- BE800:
  - `gpl_focus/GPL_Archer_BE800v1/Iplatform/openwrt/ibase/luci/src/modules/admin-full/luasrc/controller/admin/system.lua:185`
  - `restore_cmd = "tar -xzC/ >/dev/null 2>&1"`
  - non-image upload chunks are piped into `io.popen(restore_cmd, "w")` at lines 227-240.
- BE550:
  - same path under `GPL_Archer_BE550v2.6_BE9300v2.6`, same logic.
- CLI restore path also extracts backup archives under `/`:
  - BE800 `gpl_focus/GPL_Archer_BE800v1/qca_95xx_12_1/package/base-files/files/sbin/sysupgrade:278-286`
  - BE550 `gpl_focus/GPL_Archer_BE550v2.6_BE9300v2.6/qca_95xx_12_2/package/base-files/files/sbin/sysupgrade:284-292`

No archive member whitelist is applied. Because extraction uses `-C /`, a normal member named `etc/rc.local` writes `/etc/rc.local`; path traversal is not required.

### Persistence / Execution Sink

- BE800 `gpl_focus/GPL_Archer_BE800v1/qca_95xx_12_1/package/base-files/files/etc/init.d/done:10-12`
- BE550 `gpl_focus/GPL_Archer_BE550v2.6_BE9300v2.6/qca_95xx_12_2/package/base-files/files/etc/init.d/done:10-12`

The `done` init script runs:

```sh
[ -f /etc/rc.local ] && {
	sh /etc/rc.local
}
```

The boot path starts `/etc/init.d/rcS S boot` from `etc/inittab`, so `/etc/rc.local` is executed during boot through normal OpenWrt startup semantics.

## Local PoC

Benign proof script:

- `scripts/verify_tplink_be_restore_rc_local_rce_chain_2026_06_16.sh`

Observed local output:

```text
archive=/tmp/tplink_be_restore_rc_local_chain_.../restore_rc_local_poc.tgz
root=/tmp/tplink_be_restore_rc_local_chain_.../root
wrote=/tmp/tplink_be_restore_rc_local_chain_.../root/etc/rc.local
payload=#!/bin/sh;id > /tmp/tplink_be_restore_rc_local_poc;
```

Manual PoC shape:

```sh
mkdir -p poc/etc
printf '#!/bin/sh\nid > /tmp/tplink_be_restore_rc_local_poc\n' > poc/etc/rc.local
chmod 755 poc/etc/rc.local
tar -czf restore_rc_local_poc.tgz -C poc etc/rc.local
```

Upload `restore_rc_local_poc.tgz` through the authenticated LuCI backup/restore function. After restore and reboot, `/etc/rc.local` should execute as root and create `/tmp/tplink_be_restore_rc_local_poc`.

## OpenVPN Pivot

OpenVPN provides a second root execution path, but it is more conditional than `rc.local` because the OpenVPN service or instance must be started.

Evidence:

- BE800 OpenVPN init loads `/etc/config/openvpn` and starts enabled instances:
  - `gpl_focus/GPL_Archer_BE800v1/Iplatform/packages/opensource/openvpn/filesystem/etc/init.d/openvpn:222-227`
  - config generation and root launch at lines 152-189.
- BE550:
  - `gpl_focus/GPL_Archer_BE550v2.6_BE9300v2.6/Iplatform/packages/opensource/openvpn/filesystem/etc/init.d/openvpn:292-297`
  - config generation and root launch at lines 197-234.
- Script-bearing directives accepted from UCI include `script_security`, `up`, `down`, `route_up`, `client_connect`, and `client_disconnect`.

Benign semantic verifier:

- `scripts/verify_tplink_be_restore_openvpn_rce_chain_2026_06_16.sh`

This script proves a restore archive can place `/etc/config/openvpn` and a script under `/etc/openvpn/`, and that the TP-Link init semantics generate OpenVPN directives such as:

```text
script-security 2
up /etc/openvpn/poc_up.sh
```

## PPP / Network Pivot

A second execution sink was found through restored `/etc/config/network` and the PPP netifd protocol handler. This sink is stronger than the earlier helper-script variant because upstream `pppd` treats `connect` as a shell command string; the restore archive only needs to write `/etc/config/network`.

Evidence:

- BE800 `gpl_focus/GPL_Archer_BE800v1/qca_95xx_12_1/package/network/services/ppp/files/ppp.sh:68-76`
- BE550 `gpl_focus/GPL_Archer_BE550v2.6_BE9300v2.6/qca_95xx_12_2/package/network/services/ppp/files/ppp.sh:68-76`
- `connect:file`, `disconnect:file`, and raw `pppd_options` are declared and later passed to `/usr/sbin/pppd` at lines `136-160`.
- PPP packages are enabled in product SDK configs:
  - BE800 `sdk.config:7276-7281`, `sdk_32bit.config:7116-7121`
  - BE550 `sdk_32bit.config:7117-7122`
- TP-Link pins upstream `pppd` commit `8e77984ac5d7acbe68b2b2f590abd17564c9730d`; at that commit, `connect` is an `o_string` option and the help text says it invokes a shell command.

Benign semantic verifier:

- `scripts/verify_tplink_be_restore_ppp_connect_rce_chain_2026_06_16.sh`

The verifier proves a restored network config can cause TP-Link's PPP script to pass `connect 'id > /tmp/tplink_be_ppp_connect_poc'` into the root `pppd` argv. This is currently harness/source-level validation; real-device or QEMU execution of the command remains pending.

## Severity

Suggested CVSS v3.1, if the restore function is reachable only from LAN-side authenticated admin:

`CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = 6.8 Medium

If TP-Link/CNA treats web admin-to-root execution on the device as a stronger privilege boundary or the management interface is exposed beyond an adjacent network, severity may rise. A conservative report should state that the attacker needs valid administrator credentials.

## Duplicate Risk

High similarity exists with public TP-Link OpenVPN/config-restore CVEs:

- CVE-2026-30815 covers TP-Link Archer AX53 v1.0 OpenVPN configuration restore command injection before 1.7.1 Build 20260213.
- TP-Link FAQ 5055 lists Archer AX53 OpenVPN restore-related issues including CVE-2026-30815, CVE-2026-30816, and CVE-2026-30817.
- CVE-2026-9151 covers Archer AX12 v1, AX17 v1, AX18 v1, and AX1300 v1.6 VPN module command injection via crafted VPN client configuration import.

Current public records checked during this pass do not list Archer BE800 v1 or Archer BE550 v2 / BE9300 v2 for these CVEs. Submission value therefore depends on whether TP-Link/CNA accepts this as a newly affected product/version or merges it into an existing vulnerability family.

## CVE Submission Position

Recommended wording:

> TP-Link Archer BE800 v1 firmware 1.4.1 Build 20260401 and Archer BE550 v2 / BE9300 v2 firmware 1.3.1 Build 20260403 allow an authenticated administrator to restore a crafted configuration backup archive whose entries are extracted directly under `/` without path whitelisting. This permits writing startup-controlled files such as `/etc/rc.local`, leading to persistent root command execution after reboot.

Recommended classification:

- CWE-22 or CWE-73 for unrestricted archive member/path handling, plus CWE-78 for the resulting command execution if using the `rc.local` or OpenVPN script execution chain.
- Report as authenticated persistent root code execution via unsafe configuration restore.

## Remaining Validation Needed

- Real-device or QEMU boot proof showing `/etc/rc.local` survives restore and executes after reboot.
- Runtime proof for the PPP pivot showing restored `/etc/config/network` brings up the PPP interface and executes the `connect` script as root.
- HTTP request/response capture for the authenticated restore upload.
- Confirm whether BE550 production web UI exposes the same LuCI restore endpoint in the final firmware image.
