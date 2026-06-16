# Evidence Index

## Firmware Hashes

- `evidence/firmware_hashes.txt`
  - BE800 zip SHA256: `ef2885965a529ea719d44a55392ae8dd4811408e48165850343f74644824e7b5`
  - BE800 bin SHA256: `8cc0888a92b0a36ed97f04e175489affd1d3573c953f2c1c0ebd9c3996fe9c01`
  - BE550 zip SHA256: `a6106666c612851736f9574d0e8c810f78c1e1834ca9b4601d02814426c6bf6a`
  - BE550 bin SHA256: `14459cc129b1e186c195c9d6ebb5a76cc27e3196bcba6d14d5225cadb89f8a17`

## Source Reports

- `evidence/source_report_restore_rootfs_write_rce.md`
  - Main analysis for unsafe rootfs extraction and `rc.local` persistence.
  - Includes `admin-full` restore command and boot execution sink.

- `evidence/source_report_restore_ppp_connect_rce.md`
  - Primary PPP/netifd/pppd chain.
  - Explains why the current PPP PoC is framed around `proto ppp` and not default PPPoE.

## Local Verifier Outputs

- `evidence/verify_rc_local_output.txt`
  - Confirms a crafted archive member `etc/rc.local` is written under the chosen root when extracted with equivalent restore semantics.

- `evidence/verify_ppp_be800_output.txt`
  - Confirms BE800 GPL `ppp.sh` passes restored `connect` to the captured `pppd` argv stream.

- `evidence/verify_ppp_be550_output.txt`
  - Confirms the same PPP argument flow on the BE550 / BE9300 GPL tree.

- `evidence/verify_openvpn_output.txt`
  - Confirms restore placement for `etc/config/openvpn` and `etc/openvpn/poc_up.sh`, and generated OpenVPN config semantics. This is supporting evidence only.

## PoC Scripts

- `poc/verify_tplink_be_restore_rc_local_rce_chain_2026_06_16.sh`
  - Builds a benign `etc/rc.local` archive and validates restore extraction semantics.

- `poc/verify_tplink_be_restore_ppp_connect_rce_chain_2026_06_16.sh`
  - Builds a benign `etc/config/network` archive and uses a shell harness to capture `pppd` argv.

- `poc/verify_tplink_be_restore_openvpn_rce_chain_2026_06_16.sh`
  - Demonstrates restore placement for OpenVPN script-bearing configuration. This is supporting evidence only.

## Key Source Locations

### Restore primitive

- BE800 `gpl_focus/GPL_Archer_BE800v1/Iplatform/openwrt/ibase/luci/src/modules/admin-full/luasrc/controller/admin/system.lua:185`
- BE800 `gpl_focus/GPL_Archer_BE800v1/Iplatform/openwrt/ibase/luci/src/modules/admin-full/luasrc/controller/admin/system.lua:227`
- BE550 `gpl_focus/GPL_Archer_BE550v2.6_BE9300v2.6/Iplatform/openwrt/ibase/luci/src/modules/admin-full/luasrc/controller/admin/system.lua:185`
- BE550 `gpl_focus/GPL_Archer_BE550v2.6_BE9300v2.6/Iplatform/openwrt/ibase/luci/src/modules/admin-full/luasrc/controller/admin/system.lua:227`

### Additional same-pattern restore handlers

- BE800 `gpl_focus/GPL_Archer_BE800v1/Iplatform/openwrt/ibase/luci/src/modules/admin-mini/luasrc/controller/mini/system.lua:29`
- BE800 `gpl_focus/GPL_Archer_BE800v1/Iplatform/openwrt/ibase/luci/src/modules/niu/luasrc/controller/niu/system.lua:46`
- BE550 corresponding paths under `GPL_Archer_BE550v2.6_BE9300v2.6`

### Possible unauthenticated NIU route, not production-claimed

- BE800 `gpl_focus/GPL_Archer_BE800v1/Iplatform/openwrt/ibase/luci/src/modules/niu/luasrc/controller/niu/system.lua:29`
- BE800 `gpl_focus/GPL_Archer_BE800v1/Iplatform/openwrt/ibase/luci/src/modules/niu/luasrc/controller/niu/system.lua:42`
- BE800 `gpl_focus/GPL_Archer_BE800v1/Iplatform/openwrt/ibase/luci/src/modules/niu/luasrc/controller/niu/system.lua:46`
- BE800 dispatcher auth gate only when `track.sysauth` is present: `gpl_focus/GPL_Archer_BE800v1/Iplatform/openwrt/ibase/luci/src/libs/web/luasrc/dispatcher.lua:389`

This route remains a candidate only because production module installation is unconfirmed.

### Authentication boundary

- BE800 `gpl_focus/GPL_Archer_BE800v1/Iplatform/openwrt/ibase/luci/src/modules/admin-full/luasrc/controller/admin/index.lua:28`
- BE550 `gpl_focus/GPL_Archer_BE550v2.6_BE9300v2.6/Iplatform/openwrt/ibase/luci/src/modules/admin-full/luasrc/controller/admin/index.lua:28`
- BE800 `gpl_focus/GPL_Archer_BE800v1/Iplatform/openwrt/ibase/luci/src/modules/admin-mini/luasrc/controller/mini/index.lua:28`

### Startup execution sink

- BE800 `gpl_focus/GPL_Archer_BE800v1/qca_95xx_12_1/package/base-files/files/etc/init.d/done:10`
- BE550 `gpl_focus/GPL_Archer_BE550v2.6_BE9300v2.6/qca_95xx_12_2/package/base-files/files/etc/init.d/done:10`

### PPP execution sink

- BE800 `gpl_focus/GPL_Archer_BE800v1/qca_95xx_12_1/package/network/services/ppp/files/ppp.sh:68`
- BE800 `gpl_focus/GPL_Archer_BE800v1/qca_95xx_12_1/package/network/services/ppp/files/ppp.sh:136`
- BE550 `gpl_focus/GPL_Archer_BE550v2.6_BE9300v2.6/qca_95xx_12_2/package/network/services/ppp/files/ppp.sh:68`
- BE550 `gpl_focus/GPL_Archer_BE550v2.6_BE9300v2.6/qca_95xx_12_2/package/network/services/ppp/files/ppp.sh:136`

## Evidence Limitations

- Production `.bin` rootfs extraction is not available in this workspace.
- QEMU full-system boot proof is not available.
- Real-device proof and HTTP upload capture are still missing.
- GPL source may include modules not exposed in the final production web UI, so final product claims should be limited to confirmed routes or verified device behavior.
