# Technical Report: ASUS RT-AX86U Pro IPsec Certificate Upload Symlink Traversal

## Overview

An authenticated archive extraction vulnerability was identified in ASUS RT-AX86U Pro firmware `3.0.0.6.102_37436`. The web endpoint `upload_server_ipsec_cert.cgi` accepts an IPsec server certificate archive and passes the uploaded archive to `libwebapi.so!upload_server_ipsec_cert_cgi`.

The handler extracts `/tmp/server_ipsec_file/server_ipsec.tgz` into `/tmp/server_ipsec_file` with `tar -xzf`. The extraction process does not prevent symbolic links embedded in the archive. A crafted archive can write attacker-controlled content outside the intended extraction directory.

## Affected Component

```text
Product: ASUS RT-AX86U Pro
Firmware: 3.0.0.6.102_37436
Endpoint: upload_server_ipsec_cert.cgi
Web daemon: usr/sbin/httpd
Library: usr/lib/libwebapi.so
Function: upload_server_ipsec_cert_cgi
Function address: 0xc89c
```

## Root Cause

The vulnerable function uses a shell command equivalent to:

```sh
tar -xzf /tmp/server_ipsec_file/server_ipsec.tgz -C /tmp/server_ipsec_file
```

The command line uses fixed paths, so this is not shell metacharacter command injection. The problem is archive extraction behavior: `tar` follows symlinks created earlier in the same archive. If the archive contains:

```text
linkout -> /tmp
linkout/asus_http_upload_symlink_write
```

then extraction writes:

```text
/tmp/asus_http_upload_symlink_write
```

instead of keeping the file under:

```text
/tmp/server_ipsec_file
```

## Static Evidence

`libwebapi.so` exports the relevant function:

```text
upload_server_ipsec_cert_cgi @ 0xc89c
gen_server_ipsec_file @ 0xc720
```

Relevant strings in `libwebapi.so`:

```text
upload_server_ipsec_cert_cgi
upload_server_ipsec_cert_temp
/tmp/server_ipsec_file/server_ipsec.tgz
/tmp/server_ipsec_file
tar -xzf %s -C %s
```

Relevant disassembly excerpt:

```text
0x0000c97c: bl       #0xbc44 ; snprintf
0x0000c980: mov      r0, r6
0x0000c984: bl       #0xbb30 ; system
...
0x0000ca0c: bl       #0xbd04 ; _eval
...
0x0000ca50: bl       #0xbcc8 ; doSystem
```

Interpretation:

- `snprintf` builds the fixed tar extraction command.
- `system` executes the extraction.
- `_eval` moves fixed certificate filenames into `/jffs/ca_files/`.
- `doSystem` removes `/tmp/server_ipsec_file`.

## Dynamic Evidence

### Direct Firmware Tar Test

The firmware-provided `/bin/tar` was executed inside the extracted rootfs under `qemu-arm-static`.

Parent directory and absolute path tar members did not escape because tar normalized them:

```text
tar: removing leading '../../' from member names
MISSING /tmp/asus_tar_traversal_parent
MISSING /tmp/asus_tar_traversal_deep
MISSING /tmp/asus_tar_traversal_abs
```

Archive-contained symlink traversal succeeded:

```text
EXISTS /tmp/asus_tar_symlink_write: symlink traversal
```

### HTTP Upload Test

The `httpd` binary was run in a local firmware-emulation rootfs. The test obtained an `asus_token`, uploaded the crafted archive to `/upload_server_ipsec_cert.cgi`, and observed a successful HTTP response:

```text
POST /login_v2.cgi 200
COOKIE asus_token=...
RAW_UPLOAD_RECV b'HTTP/1.0 200 OK...
```

The marker outside the extraction directory was created:

```text
EXISTS /tmp/asus_http_upload_symlink_write
CONTENT /tmp/asus_http_upload_symlink_write: HTTP_SYMLINK_WRITE
```

## Security Impact

An authenticated administrator can upload a crafted IPsec certificate archive that writes attacker-controlled content outside the intended temporary extraction directory. Depending on filesystem layout, writable targets, and service behavior on a physical device, this may allow:

- tampering with temporary runtime files;
- disrupting services through malicious overwrite;
- overwriting writable persistent files if a reachable symlink target is available;
- possible follow-on execution if a sensitive startup or configuration target can be overwritten.

The current verified impact is arbitrary file write primitive, not proven stable RCE.

## Recommended Fix

Recommended mitigations:

- Do not extract untrusted archives with raw `tar -xzf`.
- Reject archive entries that are symlinks or hard links.
- Reject absolute paths, `..` path components, and paths that resolve outside the extraction directory.
- Extract into a newly created private directory and validate every entry before writing.
- Prefer a safe archive extraction library or a two-pass validation process.
- Run the web upload handler with least privilege where possible.

## Evidence Files

```text
evidence_http_upload_symlink_write.txt
evidence_direct_tar_symlink_write.txt
static_archive_handler_string_scan.txt
static_libwebapi_ipsec_disasm.txt
```
