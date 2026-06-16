# QEMU Feasibility Assessment

## Question

Can QEMU be used in the current workspace to complete runtime RCE validation for the TP-Link Archer BE800/BE550 restore vulnerability?

## Result

Not with the current local artifacts and installed tools.

This does not mean QEMU is theoretically impossible. It means the current workspace lacks the necessary production runtime inputs for a defensible QEMU proof.

## Local Tool State

Observed locally:

- Windows host: no `qemu-system-aarch64`, no `qemu-system-arm`, no `binwalk` in PATH.
- WSL Ubuntu: `qemu-aarch64` user-mode exists.
- WSL Ubuntu: `qemu-system-aarch64` was not found.
- WSL Ubuntu: `unsquashfs` exists.

User-mode `qemu-aarch64` can run individual ARM64 ELF binaries if all required libraries are available, but it cannot boot the router firmware or validate the full restore/reboot path.

## Firmware State

The official firmware archives contain a single signed `.bin` image plus PDFs:

- `Archer BE800v1_260401.zip`
  - `be800v1-up-all-ver1-4-1-P1[20260401-rel14784]_sign_2026-04-01_05.21.50.bin`
- `Archer BE550v2_260403.zip`
  - `be550v2-be9300v2-up-all-ver1-3-1-P1[20260403-rel18661]_sign_2026-04-03_05.34.46.bin`

Previous local segment probes identified these images as TP-Link `fw-type:Cloud` high-entropy packages. Local extraction did not recover a usable production root filesystem or kernel.

Relevant local notes:

- `inout/work/deepdive/tplink_be800_be550_2026_06_16/be800_segment_probe.md`
- `inout/work/deepdive/tplink_be800_be550_2026_06_16/be550_segment_probe.md`
- `inout/work/deepdive/tplink_be800_be550_2026_06_16/be800_binwalk.txt`
- `inout/work/deepdive/tplink_be800_be550_2026_06_16/be550_binwalk.txt`

## Why QEMU Was Not Executed

For this vulnerability, useful QEMU validation would need to prove:

1. the target firmware restore handler accepts the crafted backup archive,
2. the archive writes `/etc/rc.local` or `/etc/config/network` in the target rootfs,
3. the target init/network path runs the command as root after reboot or interface bring-up.

That requires either:

- a bootable production rootfs/kernel pair, or
- a sufficiently complete emulated production rootfs with the target binaries and scripts.

The current workspace has GPL source and source-level scripts, but not an extracted production rootfs. Building a generic OpenWrt or GPL-derived rootfs would only prove generic source semantics, not that the released BE800/BE550 firmware images are exploitable at runtime.

## Next Conditions Required for QEMU Proof

QEMU validation becomes practical if one of the following is available:

- extracted BE800/BE550 production rootfs and kernel,
- a real device filesystem backup,
- vendor development image/rootfs,
- a working decrypt/unpack method for TP-Link `fw-type:Cloud` firmware,
- or installed `qemu-system-aarch64` plus enough runtime filesystem content to boot or chroot the target environment.

Until then, the correct evidence boundary is:

- GPL source evidence: strong,
- local archive/handler semantics: strong,
- production runtime proof: pending.
