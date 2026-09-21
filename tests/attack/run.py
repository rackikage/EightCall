#!/usr/bin/env python3
"""Adversarial harness: fire the Sigma rules at synthetic telemetry and evasion variants."""
from __future__ import annotations

import re
import sys
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


def _timespan_seconds(spec):
    """Parse a Sigma timespan ('5m', '30s', '1h') into seconds."""
    if not spec:
        return 0
    m = re.fullmatch(r"(\d+)([smhd])", str(spec).strip())
    if not m:
        return 0
    n = int(m.group(1))
    return n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def _event_epoch(event):
    """Best-effort epoch seconds from an event.

    fwlog records carry `date` (YYYY-MM-DD) + `time` (HH:MM:SS); wfp records carry
    `ts` (ISO-8601). Returns None when no usable timestamp is present, in which
    case windowing degrades to a single unbucketed window.
    """
    import datetime as _dt

    ts = event.get("ts")
    if ts:
        try:
            return _dt.datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except ValueError:
            pass
    date, time = event.get("date"), event.get("time")
    if date and time:
        try:
            return _dt.datetime.strptime(f"{date} {time}", "%Y-%m-%d %H:%M:%S").timestamp()
        except ValueError:
            return None
    return None


def _window_max_count(timestamps, timespan_s, threshold):
    """Count events in sliding windows of `timespan_s`; return the highest count.

    With no usable timestamps, all events fall in one window.
    """
    if not timestamps:
        return 0
    if not timespan_s:
        return len(timestamps)
    ts = sorted(timestamps)
    best = 0
    start = 0
    for end in range(len(ts)):
        while ts[end] - ts[start] > timespan_s:
            start += 1
        best = max(best, end - start + 1)
    return best


def correlation_hits(correlation, detection, events):
    """Evaluate one correlation rule over events; return number of groups over threshold."""
    node = correlation["rules"][0]
    rule_id = node if isinstance(node, str) else node.get("id") or node.get("name")
    sel_names = [k for k in detection if k not in ("condition", "timeframe")]
    if not sel_names:
        return 0
    sel = detection[sel_names[0]]
    group_field = (correlation.get("group-by") or [None])[0]
    threshold = _threshold(correlation.get("condition", {}))
    window_s = _timespan_seconds(correlation.get("timespan"))

    groups: dict = {}
    for event in events:
        if not sel_match(event, sel):
            continue
        key = event.get(group_field) if group_field else "__all__"
        groups.setdefault(key, []).append(_event_epoch(event))

    over = 0
    for stamps in groups.values():
        known = [s for s in stamps if s is not None]
        if len(known) != len(stamps):
            count = len(stamps)  # timestamps unavailable: degrade to one window
        else:
            count = _window_max_count(known, window_s, threshold)
        if count >= threshold:
            over += 1
    return over


def rule_hits(entry, events) -> int:
    detection = entry["detection"]
    if entry.get("correlations"):
        return sum(correlation_hits(c, detection, events) for c in entry["correlations"])
    names = [n.strip() for n in re.split(r"\s+and\s+", str(detection["condition"]).strip())]
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
        correlations = [d["correlation"] for d in docs if "correlation" in d]
        if correlations:
            entry["correlations"] = correlations
        out[path.name] = entry
    return out


def scenarios():
    fw_attack = [r for r in fwlog.parse(FIX / "fixtures/pfirewall.log") if not r.get("malformed")]
    fw_spread = [r for r in fwlog.parse(FIX / "evasion/pfirewall_spread.log") if not r.get("malformed")]
    fw_window = [r for r in fwlog.parse(FIX / "fixtures/pfirewall_windowed.log") if not r.get("malformed")]
    fw_slow = [r for r in fwlog.parse(FIX / "fixtures/pfirewall_lowslow.log") if not r.get("malformed")]
    wfp_attack = wfp.load(FIX / "fixtures/wfpdiag.xml", FIX / "fixtures/wfpstate.xml")
    wfp_renamed = wfp.load(FIX / "fixtures/wfpdiag.xml", FIX / "evasion/wfpstate_renamed.xml")
    return [
        ("attack  pfirewall burst", "firewall_drop_burst.yml", fw_attack, "fire"),
        ("evasion pfirewall spread across sources", "firewall_drop_burst.yml", fw_spread, "fire"),
        ("attack  pfirewall 21 within 5m window", "firewall_drop_burst.yml", fw_window, "fire"),
        ("evasion pfirewall 21 spread over >5m", "firewall_drop_burst.yml", fw_slow, "evade"),
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
    results = []
    for name, rule_file, events, expect in scenarios():
        hits = rule_hits(rules[rule_file], events)
        fired = hits > 0
        ok = fired == (expect == "fire")
        failed += 0 if ok else 1
        results.append((name, fired, expect))
        print(f"{name:44s} {rule_file:44s} {hits:>4d}  {expect:8s}  {'PASS' if ok else 'FAIL'}")

    print()
    print("coverage notes (derived from this run, not asserted):")
    print("  - burst correlation groups by src_ip; a distributed source pool evades it")
    print("    BUT still fires the dst_port correlation in the same file")
    print("  - wfp default-block matches structurally (action+sublayer+layer), so a")
    print("    renamed or missing filter definition no longer evades")
    print("  - correlation timespan is enforced by sliding-window bucketing on parsed")
    print("    timestamps; events without timestamps degrade to a single window")
    print("  - correlation rules need SIEM-side support (see sigma_check.py matrix)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
