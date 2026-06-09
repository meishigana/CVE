#!/usr/bin/env bash
set -euo pipefail

BASE="/root/inout/work/deepdive/exportovpn_related"
rm -rf "$BASE"
mkdir -p "$BASE"

{
  echo "### map_cert_script.sh"
  while IFS= read -r f; do
    echo "===== $f ====="
    sed -n '1,240p' "$f"
  done < <(find /root/inout/firmware/unpacked/totolink -type f -name map_cert_script.sh 2>/dev/null)

  echo
  echo "### openvpn/cert related files"
  find /root/inout/firmware/unpacked/totolink -type f \( -name '*openvpn*' -o -name '*cert*' \) -print 2>/dev/null | head -300

  echo
  echo "### textual references in likely text files"
  find /root/inout/firmware/unpacked/totolink -type f \( -name '*.sh' -o -name '*.conf' -o -name '*.lua' -o -name '*.json' -o -name '*.js' -o -name '*.html' \) -print0 2>/dev/null |
    xargs -0 grep -RIn --binary-files=without-match 'openvpn-cert\|build_user\|exportOvpn\|map_cert_script' 2>/dev/null |
    head -300 || true

  echo
  echo "### binary/string references"
  find /root/inout/firmware/unpacked/totolink -type f -print0 2>/dev/null |
    xargs -0 grep -RIna --binary-files=text 'openvpn-cert\|build_user\|exportOvpn\|map_cert_script' 2>/dev/null |
    head -300 || true
} | tee "$BASE/evidence.txt"

echo "$BASE/evidence.txt"
