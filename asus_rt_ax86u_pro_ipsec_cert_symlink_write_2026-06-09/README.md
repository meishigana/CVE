# ASUS RT-AX86U Pro IPsec Certificate Upload Symlink Traversal Arbitrary File Write

Date prepared: 2026-06-09

## Summary

This directory contains materials prepared for a CVE assignment request concerning an authenticated archive extraction vulnerability in ASUS RT-AX86U Pro firmware `3.0.0.6.102_37436`.

The affected web endpoint is:

```text
upload_server_ipsec_cert.cgi
```

The observed vulnerable path is:

```text
httpd upload_server_ipsec_cert.cgi -> libwebapi.so!upload_server_ipsec_cert_cgi -> system("tar -xzf %s -C %s")
```

The issue occurs because the uploaded IPsec certificate archive is extracted with `tar -xzf` into `/tmp/server_ipsec_file` without preventing archive-contained symbolic links. A crafted archive can create a symlink inside the extraction directory and then write a subsequent file through that symlink outside the intended directory.

## Affected Version

Verified firmware image:

```text
ASUS RT-AX86U Pro
Firmware: 3.0.0.6.102_37436
Image: RT-AX86U_PRO_3.0.0.6_102_37436-g5a1fb9f_476-gaed2e_nand_squashfs.pkgtb
```

Key target hashes:

```text
B25BA9C81B4D42EA6727E076CF1FE930C09618A2ED406A8894667716721F46A8  firmware image
6FC4777807A68229712AEB3B128660EA03063DE8AB0E0A73F0835AA029AD0E0A  usr/sbin/httpd
902FFA78239981CDF3319D3D81FDE881CD5668EF6713AF0232E93D9DE8D61B37  usr/lib/libwebapi.so
```

## Validation Status

The issue was reproduced in a local, authorized firmware-emulation environment using the original extracted firmware binaries. The target `httpd` and `libwebapi.so` binaries were not modified.

Dynamic validation shows:

- A login session is created and an `asus_token` is returned.
- A crafted multipart upload to `/upload_server_ipsec_cert.cgi` returns `HTTP/1.0 200 OK`.
- The uploaded archive creates `/tmp/asus_http_upload_symlink_write` outside `/tmp/server_ipsec_file`.
- The marker content is attacker controlled: `HTTP_SYMLINK_WRITE`.

Important limitation:

The current evidence verifies an authenticated arbitrary file write primitive through symlink traversal during archive extraction. It does not yet prove stable remote code execution on a physical device.

## Severity Assessment

Suggested CVSS v3.1:

```text
CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:L = 5.5 Medium
```

Rationale:

- The endpoint is a web management endpoint and is treated as network reachable.
- Administrative authentication is currently required.
- The primitive allows attacker-controlled file creation/write outside the intended temporary extraction directory.
- Confidentiality impact is not demonstrated.
- Integrity impact is high because the web service runs in a privileged firmware context.
- Availability impact is low because overwrite targets may cause service disruption.

The score should be adjusted if ASUS confirms different privilege requirements or persistent overwrite targets that lead to code execution.

## Duplicate Check

No exact public duplicate was found for:

```text
ASUS RT-AX86U Pro 3.0.0.6.102_37436
upload_server_ipsec_cert.cgi
upload_server_ipsec_cert_cgi
/tmp/server_ipsec_file/server_ipsec.tgz
tar -xzf symlink traversal arbitrary file write
```

Related but not exact duplicate:

- `CVE-2022-40617`: strongSwan revocation plugin denial of service. It is IPsec-related but not an ASUS web upload archive extraction issue.

## Files

Core reports:

```text
technical_report.md
poc_reproduction.md
duplicate_check.md
evidence_index.md
cve_submission_draft.md
```

Email materials:

```text
email_body.txt
email_submission_report.md
```

Evidence:

```text
evidence_http_upload_symlink_write.txt
evidence_direct_tar_symlink_write.txt
static_archive_handler_string_scan.txt
static_libwebapi_ipsec_disasm.txt
target_hashes.txt
```

Auxiliary reproduction files:

```text
verify_asus_rt_ax86u_pro_ipsec_upload_symlink_write_2026_06_09.sh
verify_asus_rt_ax86u_pro_ipsec_tar_traversal_2026_06_09.sh
scan_asus_rt_ax86u_pro_archive_handlers_2026_06_09.sh
disasm_asus_libwebapi_ipsec_2026_06_09.py
```

## Integrity

File hashes are available in:

```text
SHA256SUMS.txt
```
