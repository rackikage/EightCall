#!/usr/bin/env python3
"""Adversarial harness: fire the Sigma rules at synthetic telemetry and evasion variants."""
from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import fwlog
import wfp

RULES = ROOT / "rules" / "windows"
FIX = Path(__file__).resolve().parent

SYNTHETIC = [
    {"Image": r"C:\Windows\System32\netsh.exe", "CommandLine": "netsh wfp capture start keywords=19"},
    {
        "TargetObject": r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging\EnableLogDroppedPackets",
        "Details": "DWORD (0x00000000)",
    },
]


def _as_list(value):
    return value if isinstance(value, list) else [value]


def _eq(actual, expected):
    if actual is None:
        return expected is None
    if isinstance(expected, bool):
        return actual is expected or str(actual).lower() == str(expected).lower()
    if isinstance(expected, int):
        try:
            return int(actual) == expected
        except (TypeError, ValueError):
            return False
    return str(actual) == str(expected)


def sel_match(event, sel) -> bool:
    for key, expected in sel.items():
        parts = key.split("|")
        field, mods = parts[0], parts[1:]
        value = event.get(field)
        hay = "" if value is None else str(value)
        items = _as_list(expected)
        if "contains" in mods:
            if "all" in mods:
                if not all(str(i) in hay for i in items):
                    return False
            elif not any(str(i) in hay for i in items):
                return False
        elif "startswith" in mods:
            if not any(hay.startswith(str(i)) for i in items):
                return False
        elif "endswith" in mods:
            if not any(hay.endswith(str(i)) for i in items):
                return False
        elif "re" in mods:
            if not any(re.search(str(i), hay) for i in items):
                return False
        elif not any(_eq(value, i) for i in items):
            return False
    return True


def _threshold(condition):
    if isinstance(condition, dict):
        return int(condition.get("gte", condition.get("gt", 0)))
    return int(re.search(r"\d+", str(condition)).group())


def rule_hits(entry, events) -> int:
    detection = entry["detection"]
    names = [n.strip() for n in re.split(r"\s+and\s+", str(detection["condition"]).strip())]
    correlation = entry.get("correlation")
    if correlation:
        sel = detection[names[0]]
        group = (correlation.get("group-by") or [None])[0]
        threshold = _threshold(correlation.get("condition", {}))
        counts: Counter = Counter()
        for event in events:
            if sel_match(event, sel):
                counts[event.get(group)] += 1
        return sum(1 for n in counts.values() if n >= threshold)
    hits = 0
    for event in events:
        if all(sel_match(event, detection[name]) for name in names):
            hits += 1
    return hits


def load_rules() -> dict:
    out = {}
    for path in sorted(RULES.glob("*.yml")):
        docs = [d for d in yaml.safe_load_all(path.read_text()) if d]
        detection = next(d for d in docs if "detection" in d)
        entry = {"detection": detection["detection"]}
        correlation = next((d["correlation"] for d in docs if "correlation" in d), None)
        if correlation:
            entry["correlation"] = correlation
        out[path.name] = entry
    return out


def scenarios():
    fw_attack = [r for r in fwlog.parse(FIX / "fixtures/pfirewall.log") if not r.get("malformed")]
    fw_spread = [r for r in fwlog.parse(FIX / "evasion/pfirewall_spread.log") if not r.get("malformed")]
    wfp_attack = wfp.load(FIX / "fixtures/wfpdiag.xml", FIX / "fixtures/wfpstate.xml")
    wfp_renamed = wfp.load(FIX / "fixtures/wfpdiag.xml", FIX / "evasion/wfpstate_renamed.xml")
    return [
        ("attack  pfirewall burst", "firewall_drop_burst.yml", fw_attack, "fire"),
        ("evasion pfirewall spread across sources", "firewall_drop_burst.yml", fw_spread, "evade"),
        ("attack  wfp no-capability default block", "wfp_default_block_no_capability.yml", wfp_attack, "fire"),
        ("attack  wfp with-capability default block", "wfp_default_block_with_capability.yml", wfp_attack, "fire"),
        ("evasion wfp renamed block filter", "wfp_default_block_no_capability.yml", wfp_renamed, "evade"),
        ("attack  wfp capture started", "wfp_capture_started.yml", SYNTHETIC, "fire"),
        ("attack  firewall logging disabled", "firewall_logging_disabled.yml", SYNTHETIC, "fire"),
    ]


def main() -> int:
    rules = load_rules()
    failed = 0
    print(f"{'scenario':44s} {'rule':44s} {'hits':>4s}  expected  verdict")
    for name, rule_file, events, expect in scenarios():
        hits = rule_hits(rules[rule_file], events)
        fired = hits > 0
        ok = fired == (expect == "fire")
        failed += 0 if ok else 1
        print(f"{name:44s} {rule_file:44s} {hits:>4d}  {expect:8s}  {'PASS' if ok else 'FAIL'}")
    print()
    print("documented blind spots:")
    print("  - burst correlation aggregates per src_ip; a distributed source pool evades it (evasion scenario)")
    print("  - wfp rules depend on joining wfpstate.xml; a renamed or missing filter definition evades the name match")
    print("  - the 5m timespan is not simulated here; batches are treated as a single window")
    print("  - correlation rules require SIEM-side correlation support (pySigma backends vary)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
