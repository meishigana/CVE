# Public CVE / PoC Duplicate Check

Check date: 2026-06-09

## Conclusion

No exact public CVE was found for the following combination:

```text
TOTOLINK X5000R
V9.1.0cu.2415_B20250515 and V9.1.0cu.2350_B20230313
cstecgi.cgi exportOvpn
pre-authenticated OpenVPN profile/archive disclosure
suffix-constrained path traversal
```

Submission value: meaningful, provided the scope is stated conservatively as file disclosure and limited traversal. It should not be submitted as RCE based on current evidence.

Duplicate risk: medium. Public X5000R CVEs exist for nearby `cstecgi.cgi` functionality, including an `exportOvpn` command injection in another version.

## Related Public CVEs

### CVE-2025-14586

NVD describes this as:

```text
TOTOLINK X5000R 9.1.0cu.2089_B20211224
/cgi-bin/cstecgi.cgi?action=exportOvpn&type=user
argument User
OS command injection
```

Why this is related:

- Same product family.
- Same CGI component.
- Same general `exportOvpn&type=user` area.

Why this is not an exact duplicate:

- Public affected version is `9.1.0cu.2089_B20211224`.
- Public weakness is command injection.
- This candidate is verified on `V9.1.0cu.2415_B20250515` and `V9.1.0cu.2350_B20230313`.
- This candidate is scoped to pre-authenticated OpenVPN export file disclosure and suffix-constrained path traversal, not command execution.
- RCE tests were performed and did not produce command execution in the available evidence.

### CVE-2025-13184

NVD describes this as unauthenticated Telnet enablement via `cstecgi.cgi`, leading to unauthenticated root login on factory/reset X5000R `V9.1.0u.6369_B20230113`.

Why this is not a duplicate:

- Different handler: `action=telnet`.
- Different impact: Telnet enablement and root login.
- Different verified firmware version.
- This candidate is OpenVPN file disclosure/path traversal.

### CVE-2025-9934

NVD describes this as a command injection in `cstecgi.cgi` function `sub_410C34` via the `pid` argument affecting `V9.1.0cu.2415_B20250515`.

Why this is not a duplicate:

- Different function/argument: `sub_410C34` / `pid`.
- Different impact: command injection.
- This candidate is `exportOvpn` file disclosure and suffix-constrained traversal.

## NVD API Checks

Local NVD API checks performed on 2026-06-09:

```text
keywordSearch=TOTOLINK X5000R exportOvpn
totalResults=0
```

Specific CVE checks:

```text
CVE-2025-14586: present; related exportOvpn command injection, not exact duplicate.
CVE-2025-13184: present; action=telnet, not duplicate.
CVE-2025-9934: present; pid/sub_410C34 command injection, not duplicate.
```

## Recommended Submission Wording

Use:

```text
TOTOLINK X5000R cstecgi.cgi exportOvpn pre-authenticated OpenVPN profile disclosure and suffix-constrained path traversal
```

Avoid:

```text
RCE
unauthenticated command injection
fully arbitrary file read
unconditional VPN compromise
```

## References

- NVD CVE-2025-14586: https://nvd.nist.gov/vuln/detail/CVE-2025-14586
- NVD CVE-2025-13184: https://nvd.nist.gov/vuln/detail/CVE-2025-13184
- NVD CVE-2025-9934: https://nvd.nist.gov/vuln/detail/CVE-2025-9934

