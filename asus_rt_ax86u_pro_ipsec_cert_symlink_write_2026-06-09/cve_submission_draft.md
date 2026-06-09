# CVE Submission Draft: ASUS RT-AX86U Pro IPsec Certificate Upload Symlink Traversal Arbitrary File Write

## Title

ASUS RT-AX86U Pro firmware 3.0.0.6.102_37436 upload_server_ipsec_cert.cgi authenticated archive symlink traversal arbitrary file write

## Vulnerability Type

- CWE: CWE-59, Improper Link Resolution Before File Access
- Related CWE: CWE-22, Improper Limitation of a Pathname to a Restricted Directory
- Type: Authenticated arbitrary file write primitive through unsafe archive extraction
- Affected endpoint: `upload_server_ipsec_cert.cgi`
- Affected function: `libwebapi.so!upload_server_ipsec_cert_cgi`
- Sink: `system("tar -xzf %s -C %s")`

## Affected Product and Version

Verified affected:

```text
Vendor: ASUS
Product: RT-AX86U Pro
Firmware: 3.0.0.6.102_37436
Firmware image: RT-AX86U_PRO_3.0.0.6_102_37436-g5a1fb9f_476-gaed2e_nand_squashfs.pkgtb
```

Key binary hashes:

```text
B25BA9C81B4D42EA6727E076CF1FE930C09618A2ED406A8894667716721F46A8  firmware image
6FC4777807A68229712AEB3B128660EA03063DE8AB0E0A73F0835AA029AD0E0A  usr/sbin/httpd
902FFA78239981CDF3319D3D81FDE881CD5668EF6713AF0232E93D9DE8D61B37  usr/lib/libwebapi.so
```

Unconfirmed scope:

- Other ASUSWRT 3.0.0.6 builds that include the same `upload_server_ipsec_cert_cgi` implementation.
- Other ASUS router models with the same IPsec certificate upload handler.

## Vulnerability Description

ASUS RT-AX86U Pro firmware `3.0.0.6.102_37436` contains an authenticated arbitrary file write primitive in the IPsec server certificate upload handler. The web endpoint `upload_server_ipsec_cert.cgi` stores an uploaded archive at `/tmp/server_ipsec_file/server_ipsec.tgz` and calls `libwebapi.so!upload_server_ipsec_cert_cgi`.

The handler extracts the archive into `/tmp/server_ipsec_file` using:

```text
tar -xzf %s -C %s
```

with fixed arguments:

```text
/tmp/server_ipsec_file/server_ipsec.tgz
/tmp/server_ipsec_file
```

The extraction does not prevent archive-contained symbolic links. A crafted tar archive can first create a symbolic link such as `linkout -> /tmp`, then include a file `linkout/asus_http_upload_symlink_write`. During extraction, tar follows the symlink and writes attacker-controlled content to `/tmp/asus_http_upload_symlink_write`, outside the intended extraction directory.

## Reproduction Summary

The issue was reproduced in a local firmware-emulation environment using the original extracted firmware binaries.

HTTP proof:

```text
POST /login_v2.cgi 200
COOKIE asus_token=...
RAW_UPLOAD_RECV b'HTTP/1.0 200 OK...
EXISTS /tmp/asus_http_upload_symlink_write
CONTENT /tmp/asus_http_upload_symlink_write: HTTP_SYMLINK_WRITE
```

Direct tar proof:

```text
EXISTS /tmp/asus_tar_symlink_write: symlink traversal
```

## Security Impact

An authenticated administrator can upload a crafted IPsec certificate archive that writes attacker-controlled content outside the intended extraction directory. This can tamper with files reachable by the privileged web service context and may enable denial of service or follow-on exploitation if sensitive writable targets are available.

The current verified impact is an authenticated arbitrary file write primitive. Stable RCE has not been proven.

## CVSS Initial Assessment

Suggested CVSS v3.1:

```text
CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:L = 5.5 Medium
```

If ASUS determines that the upload is reachable with lower privileges, or that the primitive enables reliable persistent code execution, the score should be adjusted.

## Duplicate Check Summary

No exact public duplicate was found in NVD API checks or public keyword searches for:

```text
upload_server_ipsec_cert.cgi
server_ipsec_file
upload_server_ipsec_cert_temp
ASUS RT-AX86U Pro IPsec certificate upload tar symlink traversal
```

Related but not duplicate:

- `CVE-2022-40617`: strongSwan revocation plugin denial of service, not ASUS web upload archive extraction.

## Evidence Package

```text
technical_report.md
poc_reproduction.md
duplicate_check.md
evidence_index.md
evidence_http_upload_symlink_write.txt
evidence_direct_tar_symlink_write.txt
static_archive_handler_string_scan.txt
static_libwebapi_ipsec_disasm.txt
```
