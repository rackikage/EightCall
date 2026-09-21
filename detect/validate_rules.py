#!/usr/bin/env python3
"""Minimal Sigma evaluator used to validate the detect rules against
locally generated fixtures (OSLog lines and pcaps).

Supports the subset of Sigma used by these rules:
  field, field|contains, field|contains|all, field|re, field|gte, field|lte
and condition expressions with and / or / parentheses.
"""
from __future__ import annotations

import re
import sys

import yaml


def _re_search(pattern: str, value: str) -> bool:
    return re.search(pattern, value) is not None


def match_field(event: dict, spec: str, expected) -> bool:
    parts = spec.split("|")
    field = parts[0]
    mods = parts[1:]
    actual = event.get(field)
    if actual is None:
        return False
    actual = str(actual)
    values = expected if isinstance(expected, list) else [expected]
    results = []
    for v in values:
        v = str(v)
        if "re" in mods:
            results.append(_re_search(v, actual))
        elif "gte" in mods:
            try:
                results.append(float(actual) >= float(v))
            except ValueError:
                results.append(False)
        elif "lte" in mods:
            try:
                results.append(float(actual) <= float(v))
            except ValueError:
                results.append(False)
        elif "contains" in mods:
            results.append(v in actual)
        else:
            results.append(v == actual)
    if "all" in mods:
        return all(results)
    return any(results)


def match_item(event: dict, item: dict) -> bool:
    return all(match_field(event, k, v) for k, v in item.items())


def _tokenize(expr: str):
    return re.findall(r"\(|\)|\band\b|\bor\b|[A-Za-z_][A-Za-z0-9_]*", expr)


def eval_condition(expr: str, truth: dict) -> bool:
    tokens = _tokenize(expr)
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def parse_or():
        nonlocal pos
        left = parse_and()
        while peek() == "or":
            pos += 1
            right = parse_and()
            left = left or right
        return left

    def parse_and():
        nonlocal pos
        left = parse_atom()
        while peek() == "and":
            pos += 1
            right = parse_atom()
            left = left and right
        return left

    def parse_atom():
        nonlocal pos
        tok = peek()
        if tok == "(":
            pos += 1
            val = parse_or()
            if peek() != ")":
                raise ValueError("unbalanced condition")
            pos += 1
            return val
        pos += 1
        return truth.get(tok, False)

    result = parse_or()
    if pos != len(tokens):
        raise ValueError("trailing tokens in condition")
    return result


def load_rule(path: str) -> dict:
    with open(path) as fh:
        return yaml.safe_load(fh)


def evaluate(rule: dict, events: list[dict]) -> list[dict]:
    det = rule["detection"]
    condition = det["condition"]
    items = {k: v for k, v in det.items() if k != "condition"}
    hits = []
    for ev in events:
        truth = {name: match_item(ev, item) for name, item in items.items()}
        if eval_condition(condition, truth):
            hits.append(ev)
    return hits


def parse_oslog_line(line: str) -> dict:
    ev: dict = {}
    for key, _, quoted, bare in re.findall(
        r"([\w.]+)=(\"([^\"]*)\"|(\S+))", line
    ):
        ev[key] = quoted if quoted else bare
    return ev


def oslog_events(path: str) -> list[dict]:
    events = []
    with open(path) as fh:
        for line in fh:
            if "event.category=" in line:
                events.append(parse_oslog_line(line))
    return events


def flow_events(path: str) -> list[dict]:
    """Enriched network-flow fixtures (key=value, one flow per line) for the
    C2 relay/beacon rule. Reuses the oslog key=value tokenizer."""
    events = []
    with open(path) as fh:
        for line in fh:
            if "flow.id=" in line:
                events.append(parse_oslog_line(line))
    return events


def pcap_events(path: str) -> list[dict]:
    from scapy.all import ICMP, IP, Raw, rdpcap

    events = []
    for pkt in rdpcap(path):
        if not pkt.haslayer(ICMP):
            continue
        payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
        try:
            text = payload.decode("ascii")
        except UnicodeDecodeError:
            text = payload.decode("latin-1")
        events.append(
            {
                "proto": "icmp",
                "icmp_type": int(pkt[ICMP].type),
                "icmp_payload_len": len(payload),
                "icmp_payload": text,
                "src": pkt[IP].src,
                "dst": pkt[IP].dst,
            }
        )
    return events


if __name__ == "__main__":
    ios_rule = load_rule("rules/ios_shell_abuse.yml")
    icmp_rule = load_rule("rules/icmp_exfil.yml")
    c2_rule = load_rule("rules/c2_relay_beacon.yml")

    ios_events = oslog_events("collected_events.log")
    ios_hits = evaluate(ios_rule, ios_events)
    print(f"ios_shell_abuse: {len(ios_hits)}/{len(ios_events)} fixtures -> "
          f"level={ios_rule['level']}")

    for name in ("icmp_exfil_attack.pcap", "icmp_benign.pcap"):
        events = pcap_events(name)
        hits = evaluate(icmp_rule, events)
        verdict = "ALERT" if hits else "no alert"
        print(f"icmp_exfil on {name}: {verdict} "
              f"({len(hits)}/{len(events)} pkts)")

    for name in ("c2_beacon_attack.flowlog", "c2_beacon_benign.flowlog"):
        events = flow_events(name)
        hits = evaluate(c2_rule, events)
        verdict = "ALERT" if hits else "no alert"
        print(f"c2_relay_beacon on {name}: {verdict} "
              f"({len(hits)}/{len(events)} flows)")

    c2_attack = flow_events("c2_beacon_attack.flowlog")
    c2_benign = flow_events("c2_beacon_benign.flowlog")

    ok = len(ios_hits) == len(ios_events) and len(ios_events) >= 5
    ok = ok and evaluate(icmp_rule, pcap_events("icmp_exfil_attack.pcap"))
    ok = ok and not evaluate(icmp_rule, pcap_events("icmp_benign.pcap"))
    # every attack flow must fire; no benign flow may
    ok = ok and len(c2_attack) >= 1
    ok = ok and len(evaluate(c2_rule, c2_attack)) == len(c2_attack)
    ok = ok and len(evaluate(c2_rule, c2_benign)) == 0
    print("RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)
