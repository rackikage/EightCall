#!/usr/bin/env python3
"""Validate that each shell_api_map signature is independently covered by its
designated fixture, and that the assembled rule fires on the live capture."""
from __future__ import annotations

import sys

import yaml

from validate_rules import (
    evaluate,
    load_rule,
    match_item,
    oslog_events,
)

CAPTURE = "live_capture.log"


def main() -> int:
    with open("schema/shell_api_map.yml") as fh:
        api = yaml.safe_load(fh)
    rule = load_rule("rules/ios_shell_abuse.yml")
    events = oslog_events(CAPTURE)
    by_seq = {ev["seq"]: ev for ev in events}

    print(f"events in capture: {len(events)} (seqs {sorted(by_seq)})")
    ok = True
    for name, sig in api["signatures"].items():
        item = rule["detection"][name]
        matched = sorted(ev["seq"] for ev in events if match_item(ev, item))
        want = [str(sig["fixture_seq"])]
        status = "OK" if matched == want else "MISMATCH"
        if matched != want:
            ok = False
        print(f"  {name:18} -> seq {matched} (want {want}) [{status}]")

    hits = evaluate(rule, events)
    rule_ok = len(events) > 0 and len(hits) == len(events)
    print(f"rule fires: {len(hits)}/{len(events)} -> {'OK' if rule_ok else 'FAIL'}")
    ok = ok and rule_ok

    # every schema signature must map to a rule selection and vice versa
    # (derived from the rule, not a frozen literal, so the check tracks edits)
    rule_selections = set(rule["detection"]) - {"condition", "shell_event"}
    schema_signatures = set(api["signatures"])
    covered = schema_signatures == rule_selections
    print(f"signature coverage: {len(schema_signatures)}/{len(rule_selections)}"
          f" (schema vs rule) -> {'OK' if covered else 'INCOMPLETE'}")
    if not covered:
        print(f"  only in schema: {sorted(schema_signatures - rule_selections)}")
        print(f"  only in rule:   {sorted(rule_selections - schema_signatures)}")
    ok = ok and covered

    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
