# Submission Checklist

## Ready

- [x] Product identified: TOTOLINK X5000R.
- [x] Affected component identified: `/web/cgi-bin/cstecgi.cgi`.
- [x] Verified affected versions listed:
  - `V9.1.0cu.2415_B20250515`
  - `V9.1.0cu.2350_B20230313`
- [x] Vulnerable endpoint documented.
- [x] Parameter-order requirement documented.
- [x] Root cause documented.
- [x] PoC available.
- [x] PoC syntax check passed.
- [x] Dynamic evidence available for normal OpenVPN export.
- [x] Dynamic evidence available for `.tar.gz` export.
- [x] Dynamic evidence available for `../` traversal.
- [x] RCE boundary testing documented.
- [x] Suggested CWE and CVSS provided.
- [x] Related CVE duplicate-risk notes included.

## Recommended Submission Position

Submit as:

```text
TOTOLINK X5000R cstecgi.cgi exportOvpn pre-authenticated OpenVPN profile disclosure and suffix-constrained path traversal
```

Do not submit as:

```text
Remote code execution
Unauthenticated command injection
Fully arbitrary file read
```

## Important Wording

Use:

```text
pre-authenticated OpenVPN profile disclosure
suffix-constrained path traversal
existing OpenVPN export files
runtime impact depends on OpenVPN being configured or export files being generated
```

Avoid:

```text
arbitrary file read
gets /etc/passwd directly
RCE
command injection
guaranteed VPN compromise on every device
```

## Attach or Reference

Minimum attachment set:

```text
cve_submission_materials/totolink_x5000r_exportovpn_2026-06-08/CVE_FORM.md
cve_submission_materials/totolink_x5000r_exportovpn_2026-06-08/EVIDENCE_INDEX.md
pocs/totolink_x5000r_exportovpn_pre_auth_file_disclosure.py
inout/work/deepdive/exportovpn_versions/combined_evidence.txt
TOTOLINK_X5000R_exportOvpn_verified_report_2026-06-08.md
```

Optional supporting attachments:

```text
inout/vulndb/TOTOLINK_X5000R_exportOvpn_pre_auth_file_disclosure_verified_2026-06-08.md
inout/work/deepdive/exportovpn_static/combined_static.txt
inout/work/deepdive/exportovpn_related/evidence.txt
inout/work/deepdive/exportovpn_rce_attempts/combined_evidence.txt
inout/work/deepdive/exportovpn_real_shell_rce/combined_evidence.txt
```

## Disclosure Notes To Include

```text
The local QEMU/chroot harness used original firmware binaries and libraries. It pre-created representative OpenVPN export files in a temporary rootfs to model a configured device runtime state, because firmware images do not ship with user-generated OpenVPN profiles by default.
```

```text
Current evidence does not support RCE. Shell metacharacter and URL-encoded metacharacter tests did not produce command execution, so the requested CVE scope is limited to authentication bypass for export, sensitive file disclosure, and suffix-constrained path traversal.
```

