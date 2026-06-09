# Public CVE / PoC Duplicate Check

Check date: 2026-06-09

## Conclusion

No exact public CVE was found for the following combination:

```text
ASUS RT-AX86U Pro
Firmware 3.0.0.6.102_37436
upload_server_ipsec_cert.cgi
upload_server_ipsec_cert_cgi
/tmp/server_ipsec_file/server_ipsec.tgz
tar -xzf archive-contained symlink traversal
authenticated arbitrary file write primitive
```

Submission value: meaningful, provided the scope is stated conservatively as authenticated arbitrary file write through unsafe archive extraction. The current evidence should not be submitted as stable RCE.

Duplicate risk: low to medium. ASUS has published multiple router security advisories, and IPsec-related CVEs exist, but no public record found during this check describes this exact web upload archive extraction issue.

## NVD API Checks

NVD API checks performed on 2026-06-09:

```text
keywordSearch=upload_server_ipsec_cert.cgi
totalResults=0

keywordSearch=server_ipsec_file
totalResults=0

keywordSearch=upload_server_ipsec_cert_temp
totalResults=0

keywordSearch=ASUS RT-AX86U Pro IPsec CVE
totalResults=0

keywordSearch=ASUS tar symlink traversal ipsec certificate upload
totalResults=0
```

## Related Public CVEs

### CVE-2022-40617

NVD describes this as a strongSwan revocation plugin denial-of-service issue involving crafted certificate CRL/OCSP URLs.

Why this is related:

- It is IPsec/certificate related.
- ASUS router advisories have included IPsec-related third-party component fixes.

Why this is not an exact duplicate:

- Different component: strongSwan revocation plugin vs ASUS web certificate upload handler.
- Different weakness: denial of service vs unsafe archive extraction symlink traversal.
- Different impact: DoS vs arbitrary file write primitive.
- The public description does not reference `upload_server_ipsec_cert.cgi`, `upload_server_ipsec_cert_cgi`, `/tmp/server_ipsec_file`, or `tar -xzf`.

## Public Search Terms Used

The following public search terms were checked:

```text
ASUS RT-AX86U Pro upload_server_ipsec_cert.cgi CVE
"upload_server_ipsec_cert.cgi" ASUS CVE
"server_ipsec_file" "tar -xzf" ASUS
"upload_server_ipsec_cert_temp"
"RT-AX86U Pro" "IPsec" "CVE" ASUS
NVD ASUS "RT-AX86U PRO" "IPsec"
```

No exact match was found.

## Recommended Submission Wording

Use:

```text
ASUS RT-AX86U Pro upload_server_ipsec_cert.cgi authenticated IPsec certificate archive symlink traversal arbitrary file write
```

Avoid:

```text
unauthenticated RCE
stable command execution
fully arbitrary persistent overwrite
strongSwan CVE duplicate
```

## References

- NVD CVE API: https://services.nvd.nist.gov/rest/json/cves/2.0
- NVD CVE-2022-40617: https://nvd.nist.gov/vuln/detail/CVE-2022-40617
- ASUS Product Security Advisory page: https://www.asus.com/content/asus-product-security-advisory/
