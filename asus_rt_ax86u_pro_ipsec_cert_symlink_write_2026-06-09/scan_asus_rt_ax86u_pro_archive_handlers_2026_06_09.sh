#!/usr/bin/env bash
set -euo pipefail

ROOT=${ROOT:-/root/inout/firmware/unpacked/asus/RT-AX86U_PRO_300610237436/_RT-AX86U_PRO_3.0.0.6_102_37436-g5a1fb9f_476-gaed2e_nand_squashfs.pkgtb.extracted/squashfs-root}
OUT=${OUT:-/root/inout/work/deepdive/asus_rt_ax86u_pro_300610237436_initial_2026_06_09/archive_handler_string_scan.txt}

mkdir -p "$(dirname "$OUT")"

{
  echo "# Archive/upload handler string scan"
  echo "ROOT=$ROOT"
  echo

  for f in "$ROOT/usr/lib/libwebapi.so" "$ROOT/usr/sbin/httpd"; do
    echo "### ${f#$ROOT/}"
    strings -a "$f" 2>/dev/null | grep -E 'upload_server_ipsec_cert|server_ipsec|tar -xzf|tar xzf|tar czf|ipsec_s2s|upload_cert|caupload|\.tgz|\.tar' | head -n 200 || true
    echo
  done

  echo "### firmware-wide likely archive extraction strings"
  find "$ROOT/usr" "$ROOT/bin" "$ROOT/sbin" -maxdepth 4 -type f 2>/dev/null | while read -r f; do
    hits="$(strings -a "$f" 2>/dev/null | grep -E 'tar -xzf|tar xzf|unzip .*-d|server_ipsec|\.tgz' | head -n 40 || true)"
    if [ -n "$hits" ]; then
      echo "#### ${f#$ROOT/}"
      printf '%s\n' "$hits"
      echo
    fi
  done
} | tee "$OUT"

echo "$OUT"
