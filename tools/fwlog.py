#!/usr/bin/env python3
"""pfirewall.log parser: header validation, streaming filter, export, stats."""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

REQUIRED = ("date", "time", "action", "protocol", "src-ip", "dst-ip", "src-port", "dst-port")


class HeaderError(Exception):
    pass


def read_header(stream) -> list[str]:
    for raw in stream:
        line = raw.rstrip("\n")
        if line.startswith("#Fields:"):
            fields = line.split(":", 1)[1].strip().split()
            break
        if line.startswith("#"):
            continue
        raise HeaderError("data before #Fields header")
    else:
        raise HeaderError("no #Fields header found")
    missing = [f for f in REQUIRED if f not in fields]
    if missing:
        raise HeaderError("missing columns: " + ", ".join(missing))
    return fields


def parse(path, action=None, ip=None, port=None, proto=None):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        fields = read_header(fh)
        for n, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != len(fields):
                yield {"malformed": True, "line": n}
                continue
            rec = {k.replace("-", "_"): v for k, v in zip(fields, parts)}
            if action and rec.get("action", "").upper() != action.upper():
                continue
            if ip and ip not in (rec.get("src_ip"), rec.get("dst_ip")):
                continue
            if port and port not in (rec.get("src_port"), rec.get("dst_port")):
                continue
            if proto and rec.get("protocol", "").upper() != proto.upper():
                continue
            yield rec


def cmd_check(path) -> int:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            fields = read_header(fh)
    except HeaderError as exc:
        print(f"HEADER FAIL: {exc}", file=sys.stderr)
        return 2
    records = malformed = 0
    for rec in parse(path):
        if rec.get("malformed"):
            malformed += 1
        else:
            records += 1
    print(f"fields:    {' '.join(fields)}")
    print(f"records:   {records}")
    print(f"malformed: {malformed}")
    return 1 if malformed else 0


def cmd_parse(path, fmt, **filters) -> int:
    recs = [r for r in parse(path, **filters) if not r.get("malformed")]
    if fmt == "csv":
        writer = csv.DictWriter(sys.stdout, fieldnames=list(recs[0].keys()) if recs else [])
        writer.writeheader()
        writer.writerows(recs)
    else:
        for rec in recs:
            print(json.dumps(rec, sort_keys=True))
    return 0


def cmd_stats(path) -> int:
    actions: Counter = Counter()
    src: Counter = Counter()
    dst: Counter = Counter()
    proto: Counter = Counter()
    for rec in parse(path):
        if rec.get("malformed"):
            continue
        actions[rec.get("action")] += 1
        src[rec.get("src_ip")] += 1
        dst[rec.get("dst_ip")] += 1
        proto[rec.get("protocol")] += 1
    print("actions:", dict(actions))
    print("protocols:", dict(proto))
    print("top src:")
    for ip, n in src.most_common(5):
        print(f"  {ip} {n}")
    print("top dst:")
    for ip, n in dst.most_common(5):
        print(f"  {ip} {n}")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="fwlog.py")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("check")
    p.add_argument("log")

    p = sub.add_parser("parse")
    p.add_argument("log")
    p.add_argument("--action")
    p.add_argument("--ip")
    p.add_argument("--port")
    p.add_argument("--proto")
    p.add_argument("--jsonl", action="store_true")
    p.add_argument("--csv", action="store_true")

    p = sub.add_parser("stats")
    p.add_argument("log")

    args = ap.parse_args(argv)
    try:
        if args.cmd == "check":
            return cmd_check(args.log)
        if args.cmd == "parse":
            return cmd_parse(args.log, "csv" if args.csv else "jsonl",
                             action=args.action, ip=args.ip, port=args.port, proto=args.proto)
        return cmd_stats(args.log)
    except HeaderError as exc:
        print(f"HEADER FAIL: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"IO FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
