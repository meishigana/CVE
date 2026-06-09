#!/usr/bin/env bash
set -euo pipefail

LATEST="/root/inout/firmware/unpacked/totolink/CS_C8344R_X5000R_IP04433_MT7621MT7915_SPI_16M256M_V9.1.0cu.2415_B20250515_ALL/_CS_C8344R_X5000R_IP04433_MT7621MT7915_SPI_16M256M_V9.1.0cu.2415_B20250515_ALL.web.extracted/squashfs-root"
OLD="/root/inout/firmware/unpacked/totolink/TOTOLINK_C8344R_X5000R_IP04433_MT7621MT7915_SPI_16M256M_V9.1.0cu.2350_B20230313_ALL/_TOTOLINK_C8344R_X5000R_IP04433_MT7621MT7915_SPI_16M256M_V9.1.0cu.2350_B20230313_ALL.web.extracted/squashfs-root"
BASE="/root/inout/work/deepdive/exportovpn_static"

rm -rf "$BASE"
mkdir -p "$BASE"

analyze_one() {
  local label="$1"
  local root="$2"
  local out="$BASE/$label"
  local cgi="$root/web/cgi-bin/cstecgi.cgi"
  local lib="$root/usr/lib/libcscommon.so"

  mkdir -p "$out"

  {
    echo "### files"
    file "$cgi" "$lib"
    echo
    echo "### imported and exported symbols: cstecgi.cgi"
    readelf -Ws "$cgi" | grep -E 'UND|FUNC' | grep -E 'system|popen|exec|Validity|valid|cmd|command|getNthValueSafe|safe|getenv|fopen|snprintf|strstr|strcmp' || true
    echo
    echo "### imported and exported symbols: libcscommon.so"
    readelf -Ws "$lib" | grep -E 'FUNC|GLOBAL' | grep -E 'system|popen|exec|Validity|valid|cmd|command|getNthValueSafe|safe|url|decode|encode|check' || true
    echo
    echo "### cstecgi strings of interest"
    strings -a -tx "$cgi" | grep -E 'exportOvpn|openvpn|build_user|config|tar.gz|ovpn|Validity|valid|system|HTTP/1.1 501|can not open config|cmd' || true
    echo
    echo "### libcscommon strings of interest"
    strings -a -tx "$lib" | grep -E 'Validity|valid|cmd|command|shell|forbid|illegal|decode|encode|url|check|HTTP/1.1 501' || true
  } > "$out/summary.txt"

  objdump -d "$cgi" > "$out/cstecgi.disasm.txt" 2>"$out/cstecgi.objdump.err" || true
  objdump -d "$lib" > "$out/libcscommon.disasm.txt" 2>"$out/libcscommon.objdump.err" || true

  {
    echo "### cstecgi calls of interest"
    grep -n -E '<(system|popen|fopen|snprintf|strstr|strcmp|getNthValueSafe|Validity_check|is_cmd_string_valid)@plt>' "$out/cstecgi.disasm.txt" || true
    echo
    echo "### libcscommon named functions of interest"
    grep -n -E '<.*(Validity|valid|cmd|command|decode|url|check).*>' "$out/libcscommon.disasm.txt" || true
    echo
    echo "### cstecgi export/openvpn string references by offset"
    strings -a -tx "$cgi" | grep -E 'exportOvpn|openvpn-cert build_user|/etc/openvpn/server/user|can not open config file|HTTP/1.1 501' || true
  } > "$out/locations.txt"

  echo "$out/summary.txt"
  echo "$out/locations.txt"
}

analyze_one latest "$LATEST"
analyze_one old "$OLD"

cat "$BASE/latest/summary.txt" "$BASE/latest/locations.txt" "$BASE/old/summary.txt" "$BASE/old/locations.txt" > "$BASE/combined_static.txt"
echo "$BASE/combined_static.txt"
