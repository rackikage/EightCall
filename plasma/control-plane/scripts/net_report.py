#!/usr/bin/env python3
"""Stateless helper. No server, no daemon: run, print JSON, exit.

  net_report.py                 -> local hostname + resolved addresses
  net_report.py <host> <port>   -> single TCP connect check (owned targets only)
"""
from __future__ import annotations

import json
import socket
import sys
import time


def local() -> dict:
    host = socket.gethostname()
    addrs: list[str] = []
    try:
        for info in socket.getaddrinfo(host, None):
            a = info[4][0]
            if a not in addrs:
                addrs.append(a)
    except OSError:
        pass
    return {"hostname": host, "addresses": addrs}


def tcp_check(host: str, port: int, timeout: float = 3.0) -> dict:
    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"host": host, "port": port, "open": True, "connect_ms": round((time.time() - t0) * 1000, 2)}
    except OSError as e:
        return {"host": host, "port": port, "open": False, "error": type(e).__name__, "connect_ms": round((time.time() - t0) * 1000, 2)}


def main(argv: list[str]) -> int:
    if not argv:
        print(json.dumps(local(), indent=2))
        return 0
    if len(argv) == 2:
        print(json.dumps(tcp_check(argv[0], int(argv[1])), indent=2))
        return 0
    print("usage: net_report.py [host port]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
