# Duplicate Check

## Current Position

No local evidence in this workspace shows a public CVE that explicitly covers both:

- TP-Link Archer BE800 v1 `1.4.1 Build 20260401`
- TP-Link Archer BE550 v2 / BE9300 v2 `1.3.1 Build 20260403`

with the specific primitive:

- authenticated backup restore archive extracted under `/`
- no archive member whitelist
- attacker-controlled rootfs-relative file write
- follow-on root execution through startup or service configuration

## Related Public Vulnerability Families

The finding is close to prior TP-Link configuration import/restore vulnerability families, especially VPN/OpenVPN import issues. Related public records and advisories mentioned in the working notes include:

- Archer AX53 OpenVPN/configuration restore command injection family.
- TP-Link FAQ/advisory material for Archer AX53 OpenVPN restore-related CVEs.
- Other TP-Link VPN module command injection issues involving crafted VPN client configuration import.

Because of that overlap, duplicate/merge risk is real if the vendor or CNA treats this as another affected-product instance of an existing unsafe import/restore root cause.

## Distinguishing Factors

This report can be distinguished from OpenVPN-only import issues by emphasizing:

- The vulnerable primitive is generic backup restore extraction under `/`, not only OpenVPN parsing.
- The archive can write arbitrary rootfs-relative paths, including non-VPN paths.
- The PPP `connect` chain uses `/etc/config/network`, netifd PPP handling, and `pppd`, not OpenVPN.
- The affected products and firmware versions are BE800 v1 and BE550 v2 / BE9300 v2 202604 builds.

## Recommended Submission Language

Avoid overclaiming a brand-new vulnerability class if the CNA considers this part of an existing family. Use wording such as:

> This may be related to prior TP-Link configuration restore/import vulnerabilities. I did not find public coverage for Archer BE800 v1 firmware 1.4.1 Build 20260401 or Archer BE550 v2 / BE9300 v2 firmware 1.3.1 Build 20260403 with this restore-to-rootfs write primitive. Please treat this as either a new affected-product report or a new variant, depending on your internal root-cause tracking.

## Remaining External Checks

The duplicate check should be refreshed before submission against:

- TP-Link security advisories and FAQs.
- NVD and MITRE CVE records.
- VulDB / CNVD / GitHub PoC searches.
- Vendor release notes for BE800, BE550, and BE9300.
