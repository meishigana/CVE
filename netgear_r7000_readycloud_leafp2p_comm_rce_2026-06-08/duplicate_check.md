# Public CVE / PoC Duplicate Check

Check date: 2026-06-09

## Conclusion

No public CVE or public PoC was found that fully covers this combination:

```text
NETGEAR R7000 V1.0.9.18_1.2.27
ReadyCLOUD registration flow
readycloud_control.cgi
leafp2p_username -> readycloud_hostname
/opt/broken/comm.sh unquoted curl --user command
eval-triggered OS command injection
```

Submission value: conditional but meaningful. The finding appears suitable for CVE submission if the precondition is stated precisely: attacker-controlled pollution of `leafp2p_username` before ReadyCLOUD registration.

Duplicate risk: medium. NETGEAR R7000 has public command-injection CVEs, including one in an invite-related CGI, but the known items use different affected versions, components, parameters, and data paths.

## Closest Public CVEs

### CVE-2024-35520

Public summary:

- Product: NETGEAR R7000
- Firmware: `1.0.11.136`
- Component: `RMT_invite.cgi`
- Parameter: `device_name2`
- Type: command injection
- NVD reference: `https://nvd.nist.gov/vuln/detail/CVE-2024-35520`

Difference from this finding:

- This finding targets `V1.0.9.18_1.2.27`, not `1.0.11.136`.
- This finding uses ReadyCLOUD `/opt/broken/readycloud_control.cgi`, not legacy `RMT_invite.cgi`.
- This finding propagates `leafp2p_username` into `readycloud_hostname`, then into `/opt/broken/comm.sh`.
- This finding's sink is unquoted `curl --user` plus `eval`, not `device_name2` in `RMT_invite.cgi`.

Conclusion: related product and vulnerability class, but not an exact duplicate.

### CVE-2022-30078

Public summary:

- Products: NETGEAR R6200v2 and R6300v2
- Component: `ipv6_fix.cgi`
- Parameters include `ipv6_wan_ipaddr`, `ipv6_lan_ipaddr`, `ipv6_wan_length`, and `ipv6_lan_length`
- NVD-style descriptions identify shell metacharacter command execution in IPv6 CGI parameters.

Difference from this finding:

- Different products.
- Different CGI and parameters.
- Different source-to-sink path.
- No ReadyCLOUD `leafp2p_username` or `comm.sh` involvement.

Conclusion: not a duplicate.

### CVE-2022-27632

Local screening data references this as a related NETGEAR command-injection anchor, with candidate matches involving `ddns_status` and `acosNvramConfig_get` / `system` paths.

Difference from this finding:

- Different NVRAM key and command path.
- No ReadyCLOUD registration flow.
- No `leafp2p_username -> readycloud_hostname -> comm.sh` chain.

Conclusion: not a duplicate based on current evidence.

## Search Terms Used

```text
NETGEAR R7000 V1.0.9.18 ReadyCLOUD command injection leafp2p_username
"leafp2p_username" "NETGEAR"
"readycloud_hostname" "comm.sh" "NETGEAR"
"usb_remote_invite.cgi" "NETGEAR" CVE
"readycloud_control.cgi" "CVE"
"comm.sh" "readycloud_nvram"
CVE-2024-35520 NETGEAR R7000 RMT_invite.cgi
CVE-2022-30078 NETGEAR R7000 command injection
CVE-2022-27632 NETGEAR R7000 command injection
```

## References

- NVD CVE-2024-35520: https://nvd.nist.gov/vuln/detail/CVE-2024-35520
- NETGEAR advisory for PSV-2023-0154: https://kb.netgear.com/000066027/Security-Advisory-for-Post-Authentication-Command-Injection-on-the-R7000-PSV-2023-0154
- Debian tracker CVE-2022-30078: https://security-tracker.debian.org/tracker/CVE-2022-30078

