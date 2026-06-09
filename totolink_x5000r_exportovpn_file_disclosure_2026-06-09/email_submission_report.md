# Email Submission Report: TOTOLINK X5000R `exportOvpn`

Date: 2026-06-09

## Recommended Recipient

```text
cve-assign@mitre.org
```

Optional CC:

```text
cve@mitre.org
cve-request@mitre.org
```

Recommended subject:

```text
[REQUEST] CVE for TOTOLINK X5000R - exportOvpn pre-authenticated OpenVPN file disclosure
```

## Attachment Strategy

Do not attach many files directly to the email. The CVE/MITRE mail system may reject large attachments, source files, or security-sensitive PoC material.

Recommended approach:

1. Upload the materials to the GitHub `CVE` repository.
2. Include the repository link and key SHA256 hashes in the email body.
3. Use `email_body.txt` as the direct email body.
4. If the repository is private, state that access can be granted on request.

Repository path:

```text
https://github.com/meishigana/CVE/tree/main/totolink_x5000r_exportovpn_file_disclosure_2026-06-09
```

Integrity file:

```text
https://github.com/meishigana/CVE/blob/main/SHA256SUMS.txt
```

## Important Wording

Use:

```text
pre-authenticated OpenVPN profile/archive disclosure
suffix-constrained path traversal
runtime impact depends on generated OpenVPN files
```

Avoid:

```text
RCE
unauthenticated command injection
fully arbitrary file read
unconditional VPN compromise
```

