# Evidence Index

## Core Dynamic Evidence

### HTTP upload symlink write

File:

```text
evidence_http_upload_symlink_write.txt
```

Key contents:

```text
POST /login_v2.cgi 200
COOKIE asus_token=...
RAW_UPLOAD_RECV b'HTTP/1.0 200 OK...
EXISTS /tmp/asus_http_upload_symlink_write
CONTENT /tmp/asus_http_upload_symlink_write: HTTP_SYMLINK_WRITE
```

Purpose:

- Shows the web login flow produced an authenticated session token.
- Shows the crafted archive upload to `/upload_server_ipsec_cert.cgi` received an HTTP 200 response.
- Shows attacker-controlled content was written outside `/tmp/server_ipsec_file`.

### Direct firmware tar behavior

File:

```text
evidence_direct_tar_symlink_write.txt
```

Key contents:

```text
tar: removing leading '../../' from member names
MISSING /tmp/asus_tar_traversal_parent
MISSING /tmp/asus_tar_traversal_deep
MISSING /tmp/asus_tar_traversal_abs
EXISTS /tmp/asus_tar_symlink_write: symlink traversal
```

Purpose:

- Separates direct `../` path traversal from symlink traversal.
- Shows the firmware tar normalizes direct parent traversal but still follows archive-contained symlinks.

## Static Evidence

### Archive handler string scan

File:

```text
static_archive_handler_string_scan.txt
```

Key strings:

```text
upload_server_ipsec_cert_cgi
upload_server_ipsec_cert_temp
/tmp/server_ipsec_file/server_ipsec.tgz
/tmp/server_ipsec_file
tar -xzf %s -C %s
```

Purpose:

- Identifies the affected exported function.
- Identifies the fixed uploaded archive path and extraction directory.
- Identifies the unsafe extraction command template.

### libwebapi disassembly

File:

```text
static_libwebapi_ipsec_disasm.txt
```

Key lines:

```text
## upload_server_ipsec_cert_cgi @ 0xc89c, size 564
0x0000c97c: bl       #0xbc44 ; snprintf
0x0000c984: bl       #0xbb30 ; system
0x0000ca0c: bl       #0xbd04 ; _eval
0x0000ca50: bl       #0xbcc8 ; doSystem
```

Purpose:

- Shows the vulnerable function address.
- Shows command construction and execution.
- Shows post-extraction fixed file moves and cleanup.

## Reproduction Scripts

Files:

```text
verify_asus_rt_ax86u_pro_ipsec_upload_symlink_write_2026_06_09.sh
verify_asus_rt_ax86u_pro_ipsec_tar_traversal_2026_06_09.sh
```

Purpose:

- Rebuild isolated rootfs copies.
- Generate crafted tar payloads.
- Run firmware binaries under `qemu-arm-static`.
- Collect marker and command evidence.

## Static Helper Scripts

Files:

```text
scan_asus_rt_ax86u_pro_archive_handlers_2026_06_09.sh
disasm_asus_libwebapi_ipsec_2026_06_09.py
```

Purpose:

- Reproduce the static string scan.
- Reproduce the focused disassembly evidence.

## Target Hashes

File:

```text
target_hashes.txt
```

Purpose:

- Documents hashes of firmware image and key binaries.

## Integrity Hashes

File:

```text
SHA256SUMS.txt
```

Purpose:

- Documents hashes of all files in this submission package.
