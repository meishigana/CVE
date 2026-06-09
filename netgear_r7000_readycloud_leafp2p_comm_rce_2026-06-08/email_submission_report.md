# Email Submission Report

Date prepared: 2026-06-09

## Recommended Recipient

Use the appropriate CNA/vendor disclosure channel for NETGEAR vulnerabilities. The package can also be submitted through the CVE Program request workflow if vendor CNA routing is not available.

## Subject

```text
CVE Request - NETGEAR R7000 ReadyCLOUD command injection via leafp2p_username state
```

## Attachments / Links

Recommended attachments:

```text
netgear_r7000_readycloud_leafp2p_comm_rce_2026-06-08.zip
```

or repository link to the directory:

```text
cve_submission_materials/netgear_r7000_readycloud_leafp2p_comm_rce_2026-06-08/
```

## Key Claims to Preserve

State precisely:

- The vulnerable sink is verified.
- The ReadyCLOUD trigger is verified.
- The PoC is stable and reproduced twice after fresh firmware extraction.
- The current proof requires attacker-controlled pollution of `leafp2p_username`.
- The upstream external writer for `leafp2p_username` is not yet proven.

Avoid claiming:

```text
Unauthenticated remote RCE
```

unless a separate request path that writes `leafp2p_username` is proven.

## Evidence Summary

The strongest lines for reviewers:

```text
Using routeruser; /bin/touch /tmp/pwned; # as device username
readycloud_hostname=routeruser; /bin/touch /tmp/pwned; #
curl --basic -k --user routeruser
[pwned]
-rw-r--r-- ... /tmp/pwned
```

## Duplicate Risk

Known nearby item:

```text
CVE-2024-35520
```

Difference:

`CVE-2024-35520` is `RMT_invite.cgi` / `device_name2` on R7000 firmware `1.0.11.136`. This submission is ReadyCLOUD `readycloud_control.cgi` / `comm.sh` on `V1.0.9.18_1.2.27`.

