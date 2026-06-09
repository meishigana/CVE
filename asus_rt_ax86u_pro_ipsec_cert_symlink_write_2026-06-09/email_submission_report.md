# Email Submission Report

Prepared: 2026-06-09

## Candidate

```text
ASUS RT-AX86U Pro firmware 3.0.0.6.102_37436 upload_server_ipsec_cert.cgi authenticated archive symlink traversal arbitrary file write
```

## Suggested Recipient

Submit to an appropriate CNA for ASUS product vulnerabilities or directly to ASUS PSIRT/product security contact. Include the full evidence package and the conservative scope statement.

## Attachments / Links

Recommended attachments:

```text
README.md
technical_report.md
poc_reproduction.md
duplicate_check.md
evidence_index.md
evidence_http_upload_symlink_write.txt
evidence_direct_tar_symlink_write.txt
static_archive_handler_string_scan.txt
static_libwebapi_ipsec_disasm.txt
target_hashes.txt
SHA256SUMS.txt
```

Optional helper scripts:

```text
verify_asus_rt_ax86u_pro_ipsec_upload_symlink_write_2026_06_09.sh
verify_asus_rt_ax86u_pro_ipsec_tar_traversal_2026_06_09.sh
scan_asus_rt_ax86u_pro_archive_handlers_2026_06_09.sh
disasm_asus_libwebapi_ipsec_2026_06_09.py
```

## Scope Notes

Use conservative wording:

```text
authenticated arbitrary file write primitive via archive-contained symlink traversal
```

Avoid claiming:

```text
unauthenticated exploit
stable RCE
confirmed physical-device persistence
```

## Duplicate Check Status

NVD keyword checks returned no exact public duplicate. `CVE-2022-40617` is related to strongSwan certificate revocation denial of service and should be mentioned only as not-a-duplicate context.
