# TP-Link Archer BE800/BE550 Restore-to-PPP Root Script Execution Candidate

## Summary

This is a secondary, conditional RCE chain discovered after the unsafe configuration restore issue. It is more distinct from the public TP-Link OpenVPN restore/import CVEs than the OpenVPN pivot, but it still depends on the same authenticated configuration restore primitive.

An authenticated administrator can restore an archive that writes `/etc/config/network`. The TP-Link/OpenWrt PPP netifd protocol handler accepts restored UCI options `connect:file`, `disconnect:file`, and `pppd_options`, then passes them to `/usr/sbin/pppd`. In the PPP daemon sources present in the TP-Link GPL package, `connect` is a shell command string. A restored interface with `option proto 'ppp'` and `option connect 'id > /tmp/tplink_be_ppp_connect_poc'` causes the netifd PPP boundary to receive:

```text
connect
id > /tmp/tplink_be_ppp_connect_poc
```

For `proto ppp`, the default tty channel in `pppd` is expected to execute that string while bringing up the PPP interface. Current validation is source-level and harness-level; real-device or QEMU confirmation of actual `pppd` script execution is still needed. This finding should not be generalized to the default `proto pppoe` WAN path without additional proof, because the PPPoE plugin replaces the normal tty channel.

## Affected Local Targets

- TP-Link Archer BE800 v1 official firmware archive:
  - `Archer BE800v1_260401.zip`
  - firmware version: `1.4.1 Build 20260401`
  - local bin SHA256: `8cc0888a92b0a36ed97f04e175489affd1d3573c953f2c1c0ebd9c3996fe9c01`
- TP-Link Archer BE550 v2 / BE9300 v2 official firmware archive:
  - `Archer BE550v2_260403.zip`
  - firmware version: `1.3.1 Build 20260403`
  - local bin SHA256: `14459cc129b1e186c195c9d6ebb5a76cc27e3196bcba6d14d5225cadb89f8a17`
- GPL packages:
  - `inout/firmware/gpl/tp-link/GPL_Archer_BE800v1.tar.gz`
  - `inout/firmware/gpl/tp-link/GPL_Archer_BE550v2.6_BE9300v2.6.tar.gz`

## Evidence

### Restore Path

- BE800 LuCI restore streams uploaded backup data to `tar -xzC/ >/dev/null 2>&1`:
  - `gpl_focus/GPL_Archer_BE800v1/Iplatform/openwrt/ibase/luci/src/modules/admin-full/luasrc/controller/admin/system.lua:185`
  - upload handler: lines `227-240`
- BE550 uses the same logic at the corresponding path.
- CLI/preinit restore extracts preserved configuration under `/`:
  - BE800 `gpl_focus/GPL_Archer_BE800v1/qca_95xx_12_1/package/base-files/files/lib/preinit/80_mount_root:8-12`
  - BE550 `gpl_focus/GPL_Archer_BE550v2.6_BE9300v2.6/qca_95xx_12_2/package/base-files/files/lib/preinit/80_mount_root:8-12`
- `/etc/config/*` is treated as preserved configuration:
  - BE800 `gpl_focus/GPL_Archer_BE800v1/qca_95xx_12_1/package/base-files/Makefile:46-49`, `183-186`
  - BE550 `gpl_focus/GPL_Archer_BE550v2.6_BE9300v2.6/qca_95xx_12_2/package/base-files/Makefile:46-49`, `182-185`

### PPP Execution Sink

- BE800 and BE550 PPP protocol script declares hidden/file options:
  - `qca_95xx_12_1/package/network/services/ppp/files/ppp.sh:68-76`
  - `qca_95xx_12_2/package/network/services/ppp/files/ppp.sh:68-76`
- The same script reads `connect`, `disconnect`, and `pppd_options` and passes them to root `pppd`:
  - BE800 `ppp.sh:136-160`
  - BE550 `ppp.sh:136-160`
- PPP-family protocols are registered:
  - BE800 `ppp.sh:335-338`
  - BE550 `ppp.sh:335-338`
- PPP packages are enabled:
  - BE800 `Iplatform/build/product_configs/be800v1/sdk.config:7276-7281`
  - BE800 `Iplatform/build/product_configs/be800v1/sdk_32bit.config:7116-7121`
  - BE550 `Iplatform/build/product_configs/be550v2/sdk_32bit.config:7117-7122`
- The OpenWrt PPP package in the QCA tree pins upstream source:
  - `PKG_SOURCE_URL:=https://github.com/paulusmack/ppp`
  - `PKG_SOURCE_VERSION:=8e77984ac5d7acbe68b2b2f590abd17564c9730d`
  - `PKG_RELEASE_VERSION:=2.4.7`
  - BE800 `qca_95xx_12_1/package/network/services/ppp/Makefile:13-23`
  - BE550 `qca_95xx_12_2/package/network/services/ppp/Makefile:13-23`
- Upstream `pppd` source at that commit confirms the same execution semantics:
  - `pppd/tty.c:144-145`: `connect_script` and `disconnect_script` variables.
  - `pppd/tty.c:185-188`: `connect` and `disconnect` are `o_string` options.
  - `pppd/tty.c:562` and `705`: `connect_script` becomes `connector`, then is passed to `device_script(connector, ...)`.
  - `pppd/options.c:376`: help text describes `connect <p>` as invoking shell command `<p>`.
- The product Iplatform configuration appears to enable TP-Link's local `pppd` package rather than the OpenWrt `ppp` package:
  - BE800 `Iplatform/build/product_configs/be800v1/iplatform.config:403`: `# CONFIG_PACKAGE_ppp is not set`
  - BE800 `Iplatform/build/product_configs/be800v1/iplatform.config:984-986`: `CONFIG_PACKAGE_netifd=y` and `CONFIG_PACKAGE_pppd=y`
  - BE550 `Iplatform/build/product_configs/be550v2/iplatform.config:407`: `# CONFIG_PACKAGE_ppp is not set`
  - BE550 `Iplatform/build/product_configs/be550v2/iplatform.config:978-980`: `CONFIG_PACKAGE_netifd=y` and `CONFIG_PACKAGE_pppd=y`
- TP-Link's local Iplatform `pppd` package is version `2.4.3`:
  - `inout/firmware/gpl/tp-link/extracted/GPL_Archer_BE800v1/Iplatform/packages/opensource/pppd/Makefile:11`
- The local TP-Link `pppd` source also treats `connect` as a shell command:
  - `pppd/src/pppd/tty.c:142-143`: `connect_script` and `disconnect_script` variables.
  - `pppd/src/pppd/tty.c:183-187`: `connect` and `disconnect` are string options.
  - `pppd/src/pppd/tty.c:558`, `696-697`: `connect_script` becomes `connector`, then is passed to `device_script(connector, ...)`.
  - `pppd/src/pppd/main.c:353-354`: `uid = getuid()` and `privileged = uid == 0`.
  - `pppd/src/pppd/main.c:441-445`: `pppd` requires effective root.
  - `pppd/src/pppd/main.c:1862-1868`: the child runs `execl("/bin/sh", "sh", "-c", program, ...)` after `setuid(uid)`.
- PPPoE caveat:
  - `pppd/src/pppd/tty.c:403` initializes the normal tty channel.
  - `pppd/src/pppd/pppoe/plugin.c:383-387` replaces `the_channel` with the PPPoE channel.
  - `pppd/src/pppd/pppoe/plugin.c:505` sets that channel's connect function to `PPPOEConnectDevice`.
  - Therefore, this report frames the current PoC around `proto ppp`, not default PPPoE WAN.

## Local Semantic PoC

Verifier:

- `scripts/verify_tplink_be_restore_ppp_connect_rce_chain_2026_06_16.sh`

The script creates a restore archive containing:

```text
etc/config/network
```

The restored network config contains:

```text
config interface 'pocppp'
	option proto 'ppp'
	option device '/dev/null'
	option username 'poc'
	option password 'poc'
	option connect 'id > /tmp/tplink_be_ppp_connect_poc'
```

The verifier then sources the unmodified TP-Link PPP script with netifd helpers stubbed and captures the resulting `proto_run_command` argument stream. The first item is the netifd interface name; `/usr/sbin/pppd` follows and receives the malicious `connect` option. Observed on both BE800 and BE550 GPL trees:

```text
/usr/sbin/pppd
nodetach
ipparam
pocppp
...
user
poc
password
poc
connect
id > /tmp/tplink_be_ppp_connect_poc
ip-up-script
/lib/netifd/ppp-up
...
/dev/null
```

This proves the restored UCI option reaches the root `pppd` execution boundary as a shell command string. Unlike the earlier script-file variant, this PoC only needs to restore `/etc/config/network`.

## Preconditions

- Attacker has authenticated administrator access, or another bug that can trigger the configuration restore primitive.
- A crafted restore archive writes `/etc/config/network` with a PPP interface and a malicious `connect` command.
- The added `proto ppp` interface is brought up through network restart, LuCI apply, `/sbin/ifup`, or reboot.
- Real `pppd` is present and accepts the `connect` option as expected.
- The trigger path uses the tty-channel PPP path. Default `proto pppoe` should not be assumed exploitable by this exact `connect` path without separate runtime proof.

## CVE Position

Recommended framing if real-device/QEMU proof succeeds:

> TP-Link Archer BE800 v1 firmware 1.4.1 Build 20260401 and Archer BE550 v2 / BE9300 v2 firmware 1.3.1 Build 20260403 allow an authenticated administrator to restore a crafted configuration archive that writes PPP network configuration. The restored `/etc/config/network` can define a `proto ppp` interface with an attacker-controlled `connect` command, which is passed by TP-Link's netifd PPP handler to root `pppd`. Because the PPP daemon treats `connect` as a shell command on the tty-channel path, this can lead to root command execution when the interface is brought up.

Suggested CWE:

- CWE-73 / CWE-22 for unsafe restore of externally controlled file paths.
- CWE-78 for resulting root command execution through restored PPP options.

Suggested severity, assuming LAN-side authenticated admin:

- CVSS v3.1 candidate: `AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = 6.8 Medium.
- If management is reachable remotely or CNA treats admin-to-root as a higher privilege boundary, score may increase.

## Duplicate Risk

This chain is distinct from known public TP-Link OpenVPN/VPN import issues because it uses:

- `/etc/config/network`
- netifd PPP protocol handling
- `pppd connect` shell command execution

It does not depend on `/etc/config/openvpn`, `script-security`, or OpenVPN import parsing. However, it shares the broader root cause of unsafe configuration restore with other TP-Link restore/import vulnerability families.

Current public search on 2026-06-16 did not find a record explicitly covering BE800 v1 `1.4.1 Build 20260401` or BE550 v2 / BE9300 v2 `1.3.1 Build 20260403` with a PPP/netifd restore-to-`pppd connect` chain.

## Current Confidence

- Restore write primitive: high, source and local archive semantics verified.
- UCI `connect` to netifd PPP argument stream: high, verified on BE800 and BE550 GPL scripts.
- `pppd connect` shell execution semantics: high for the TP-Link local `pppd` source and upstream pppd semantics.
- End-to-end exploitability on production images: medium pending real-device/QEMU proof.
- Applicability to default PPPoE WAN: low pending separate proof; current PoC is for an added `proto ppp` interface.

## Remaining Validation Needed

- Real device or QEMU boot proof that the restored `/etc/config/network` survives restore and starts the added `proto ppp` interface.
- Runtime log or marker file proving the `connect` shell command executes as root.
- HTTP request/response capture for the authenticated restore upload.
- Confirm whether the production firmware image contains the same PPP scripts and `pppd`; official `.bin` extraction is not yet achieved due TP-Link Cloud/high-entropy packaging.
