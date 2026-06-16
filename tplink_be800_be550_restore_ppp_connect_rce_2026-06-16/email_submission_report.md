# Email Submission Report: TP-Link BE800/BE550 Restore-to-PPP Root Command Execution

Date: 2026-06-16

## Usage

Use the same-directory file as the email body:

```text
email_body.txt
```

Suggested recipient:

```text
cve-assign@mitre.org
```

Optional CC:

```text
cve@mitre.org
```

Subject:

```text
[REQUEST] CVE for TP-Link Archer BE800/BE550 - authenticated configuration restore to root PPP command execution
```

## Evidence Repository

```text
https://github.com/meishigana/CVE/tree/main/tplink_be800_be550_restore_ppp_connect_rce_2026-06-16
```

Repository integrity:

```text
https://github.com/meishigana/CVE/blob/main/SHA256SUMS.txt
```

## Notes

- This request is framed as authenticated admin-to-root command execution.
- It does not claim unauthenticated RCE.
- The `niu` route is mentioned only as a production-unconfirmed follow-up candidate.
- Real-device or full-system QEMU evidence is still pending because the official firmware images are TP-Link `fw-type:Cloud` high-entropy packages and a production rootfs was not recovered locally.
