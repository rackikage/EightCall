#!/usr/bin/env python3
"""wfpdiag.xml / netevents.xml / wfpstate.xml parser: decode netEvents, join filters."""
from __future__ import annotations

import argparse
import csv
import json
import sys
import xml.etree.ElementTree as ET
from collections import Counter

DEFAULT_BLOCK = "Block Outbound Default Rule"


def _text(node, path):
    el = node.find(path)
    if el is None or el.text is None:
        return None
    return el.text.strip() or None


def _decode_app_id(ev):
    el = ev.find("header/appId/data")
    if el is None or not el.text:
        return None
    try:
        raw = bytes.fromhex(el.text.strip())
    except ValueError:
        return None
    try:
        decoded = raw.decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    return decoded.rstrip("\x00") or None


def _capabilities(ev):
    return [i.text.strip() for i in ev.findall("internalFields/capabilities/item") if i.text]


def _terminating(ev):
    out = []
    for item in ev.findall("internalFields/terminatingFiltersInfo/item"):
        out.append({
            "filter_id": _text(item, "filterId"),
            "sublayer": _text(item, "subLayer"),
            "action": _text(item, "actionType"),
        })
    return out


def _classify(ev, kind):
    node = ev.find(f"classify{kind}")
    if node is None:
        return {}
    keys = ("filterId", "layerId", "originalProfile", "currentProfile", "msFwpDirection", "isLoopback")
    return {k: _text(node, k) for k in keys}


def iter_events(root):
    for ev in root.iter():
        if ev.tag in ("netEvent", "item") and ev.find("header") is not None:
            yield ev


def load_state(path):
    if not path:
        return {}
    root = ET.parse(path).getroot()
    filters = {}
    for item in root.iter():
        if item.tag != "item":
            continue
        fid = _text(item, "filterId")
        if not fid:
            continue
        filters[fid] = {
            "name": _text(item, "displayData/name"),
            "layer": _text(item, "layerKey"),
            "action": _text(item, "action/type"),
        }
    return filters


def record(ev, filters):
    event_type = _text(ev, "type") or ""
    if event_type.endswith("CLASSIFY_DROP"):
        action = "drop"
    elif event_type.endswith("CLASSIFY_ALLOW"):
        action = "allow"
    else:
        action = event_type
    terminating = _terminating(ev)
    block = next((t for t in terminating if t["action"] == "FWP_ACTION_BLOCK"), None)
    filter_name = filters.get(block["filter_id"], {}).get("name") if block else None
    rec = {
        "ts": _text(ev, "header/timeStamp"),
        "action": action,
        "ip_version": _text(ev, "header/ipVersion"),
        "proto": _text(ev, "header/ipProtocol"),
        "src_ip": _text(ev, "header/localAddrV4") or _text(ev, "header/localAddrV6.byteArray16"),
        "dst_ip": _text(ev, "header/remoteAddrV4") or _text(ev, "header/remoteAddrV6.byteArray16"),
        "src_port": _text(ev, "header/localPort"),
        "dst_port": _text(ev, "header/remotePort"),
        "app_path": _decode_app_id(ev),
        "package_sid": _text(ev, "header/packageSid"),
        "user_id": _text(ev, "header/userId"),
        "capabilities": _capabilities(ev),
        "terminating_filters": terminating,
        "classify": _classify(ev, "Drop" if action == "drop" else "Allow"),
    }
    rec["capability_count"] = len(rec["capabilities"])
    rec["block_filter_id"] = block["filter_id"] if block else None
    rec["block_filter_name"] = filter_name
    rec["default_block"] = filter_name == DEFAULT_BLOCK
    return rec


def load(xml_path, state_path=None):
    filters = load_state(state_path)
    root = ET.parse(xml_path).getroot()
    return [record(ev, filters) for ev in iter_events(root)]


def cmd_check(xml_path, state_path) -> int:
    recs = load(xml_path, state_path)
    print(f"events: {len(recs)}")
    print(f"filters: {len(load_state(state_path))}")
    return 0 if recs else 2


def cmd_parse(xml_path, state_path, fmt, action) -> int:
    recs = [r for r in load(xml_path, state_path) if not action or r["action"] == action]
    if fmt == "csv":
        flat = [{**r, "capabilities": ";".join(r["capabilities"])} for r in recs]
        writer = csv.DictWriter(sys.stdout, fieldnames=list(flat[0].keys()) if flat else [])
        writer.writeheader()
        writer.writerows(flat)
    else:
        for rec in recs:
            print(json.dumps(rec, sort_keys=True))
    return 0


def cmd_stats(xml_path, state_path) -> int:
    recs = load(xml_path, state_path)
    actions: Counter = Counter()
    blocks: Counter = Counter()
    caps: Counter = Counter()
    dst: Counter = Counter()
    for rec in recs:
        actions[rec["action"]] += 1
        blocks[rec["block_filter_name"]] += 1
        caps[rec["capability_count"]] += 1
        dst[rec["dst_ip"]] += 1
    print("actions:", dict(actions))
    print("block filters:", dict(blocks))
    print("capability_count:", dict(caps))
    print("top dst:")
    for ip, n in dst.most_common(5):
        print(f"  {ip} {n}")
    gaps = [r for r in recs if r["action"] == "drop" and r["default_block"] and r["capability_count"] > 0]
    print(f"drops despite capability (private-range miss candidates): {len(gaps)}")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="wfp.py")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("check")
    p.add_argument("xml")
    p.add_argument("--state")

    p = sub.add_parser("parse")
    p.add_argument("xml")
    p.add_argument("--state")
    p.add_argument("--action", choices=["drop", "allow"])
    p.add_argument("--jsonl", action="store_true")
    p.add_argument("--csv", action="store_true")

    p = sub.add_parser("stats")
    p.add_argument("xml")
    p.add_argument("--state")

    args = ap.parse_args(argv)
    try:
        if args.cmd == "check":
            return cmd_check(args.xml, args.state)
        if args.cmd == "parse":
            return cmd_parse(args.xml, args.state, "csv" if args.csv else "jsonl", args.action)
        return cmd_stats(args.xml, args.state)
    except ET.ParseError as exc:
        print(f"XML FAIL: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"IO FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
