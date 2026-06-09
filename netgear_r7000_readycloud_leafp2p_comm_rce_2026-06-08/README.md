# NETGEAR R7000 ReadyCLOUD leafp2p-to-comm OS Command Injection

Date prepared: 2026-06-09

## Summary

This directory contains materials prepared for a CVE assignment request concerning an OS command injection vulnerability in NETGEAR R7000 firmware `V1.0.9.18_1.2.27`.

The affected ReadyCLOUD components are:

```text
/opt/broken/readycloud_control.cgi
/opt/broken/register.sh
/opt/broken/comm.sh
```

The verified vulnerable path is:

```text
leafp2p_username NVRAM value
  -> readycloud_control.cgi copies it into readycloud_hostname
  -> register.sh
  -> comm.sh
  -> unquoted curl --user command
  -> eval
  -> OS command execution
```

The issue occurs because `comm.sh` reads `readycloud_hostname` and `readycloud_password` from NVRAM-derived state and embeds those values into a shell command without quoting or metacharacter neutralization.

## Affected Version

Verified firmware image:

```text
NETGEAR R7000
Firmware: V1.0.9.18_1.2.27
Firmware image: R7000-V1.0.9.18_1.2.27.chk
```

Target file hashes are listed in:

```text
target_hashes.txt
```

## Validation Status

The vulnerability was reproduced in a local, authorized firmware-emulation laboratory environment using the original firmware rootfs extracted from `R7000-V1.0.9.18_1.2.27.chk`.

The target `readycloud_control.cgi`, `register.sh`, `comm.sh`, and `libreadycloud.so` logic was not patched. The PoC replaces the NVRAM provider with a minimal ARM `libnvram.so` shim only to model attacker-polluted persistent state for `leafp2p_username` and to log reads/writes. External network calls are stubbed so the proof does not contact NETGEAR ReadyCLOUD services.

Important limitation:

The current evidence proves a stable RCE sink and ReadyCLOUD registration trigger under the precondition that `leafp2p_username` can be polluted with shell metacharacters before registration. A separate remote or authenticated web/API primitive that writes arbitrary metacharacters into `leafp2p_username` has not yet been proven.

## Severity Assessment

Suggested CVSS v3.1 for the proven state-pollution-to-RCE condition:

```text
CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H = 6.8 Medium
```

Rationale:

- ReadyCLOUD registration is exposed through router management functionality and is expected to require administrative context.
- The current PoC assumes attacker-controlled persistent state in `leafp2p_username`.
- Successful exploitation executes OS commands in the router firmware environment.

If a separate remotely reachable primitive is proven to write `leafp2p_username` without high privileges, the PR/AV metrics should be adjusted.

## Duplicate Check

No exact public duplicate was found for the following combination:

```text
NETGEAR R7000 V1.0.9.18_1.2.27
ReadyCLOUD / readycloud_control.cgi
leafp2p_username -> readycloud_hostname propagation
/opt/broken/comm.sh unquoted curl --user
eval-triggered OS command injection
```

Related but not exact duplicates:

- `CVE-2024-35520`: NETGEAR R7000 `1.0.11.136` command injection in `RMT_invite.cgi` via `device_name2`; different firmware version, component, parameter, and path.
- `CVE-2022-30078`: NETGEAR R6200v2/R6300v2 IPv6 CGI command injection; different products and parameters.
- `CVE-2022-27632`: local candidate data references this as a related NETGEAR command-injection anchor, but not this ReadyCLOUD `leafp2p_username` chain.

See `duplicate_check.md`.

## Files

Core reports:

```text
technical_report.md
poc_reproduction.md
duplicate_check.md
evidence_index.md
cve_submission_draft.md
```

Email materials:

```text
email_body.txt
email_submission_report.md
```

Evidence:

```text
evidence_leafp2p_to_comm_rce.txt
evidence_leafp2p_to_comm_rce_rerun_1.txt
evidence_leafp2p_to_comm_rce_rerun_2.txt
static_comm_sh_numbered.txt
static_readycloud_control_strings.txt
source_verification_report.md
```

Auxiliary reproduction file:

```text
verify_netgear_readycloud_leafp2p_to_comm_rce.sh
```

## Integrity

File hashes for this submission package are available in:

```text
SHA256SUMS.txt
```

