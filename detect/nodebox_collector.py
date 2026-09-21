#!/usr/bin/env python3
"""nodebox collector: host-side normalizer + pySigma evaluation.

pySigma stays OFF the node. Nodes emit normalized envelopes; this runs the same
rules across the whole fleet and reports alerts with per-node provenance.

Evaluation uses the repo's own minimal Sigma evaluator (`validate_rules.py`), so
the verdict is the project's. pySigma is used to validate/compile the rules.

Two normalizer stages sit in front of evaluation:

  * `flatten()` (from nodebox_telemetry): dot-flatten for the Sigma evaluator.
  * `to_ecs()` (here): map an envelope to the Elastic Common Schema so the same
    telemetry can be shipped to an ECS backend (Elasticsearch, OpenSearch,
    anything speaking ECS) without a second producer. The original envelope is
    preserved verbatim under the `nodebox` key so nothing is lost in mapping.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import validate_rules as vr
from nodebox_telemetry import flatten

REQUIRED = ("event_type",)

# --- ECS normalization -------------------------------------------------------

ECS_VERSION = "8.11.0"

# event_type -> ECS event.category (a value from the ECS category vocabulary).
_ECS_CATEGORY = {
    "nodebox.session": ["authentication", "session"],
    "nodebox.clone": ["intrusion_detection"],
    "nodebox.command": ["process"],
    "nodebox.result": ["process"],
    "nodebox.ssh_session": ["session"],
    "nodebox.sshgate": ["authentication"],
    "nodebox.enrollment": ["iam"],
    "nodebox.lifecycle": ["host"],
    "nodebox.health": ["host"],
}

# data.outcome -> ECS event.outcome (success | failure | unknown).
_ECS_OUTCOME = {"ok": "success", "denied": "failure", "error": "failure", "timeout": "failure"}


_EPOCH_ISO = datetime.fromtimestamp(0, tz=timezone.utc).isoformat()


def _ecs_timestamp(ts: object) -> str:
    """Epoch seconds (int/float) -> ISO-8601 UTC. Falls back to the string as-is
    if it is already a timestamp, or to the Unix epoch for absent/unparseable
    input. An out-of-range numeric value (a corrupt but well-formed event) falls
    back rather than crashing the whole export."""
    if isinstance(ts, bool):        # bool is an int subclass; never a timestamp
        return _EPOCH_ISO
    if isinstance(ts, (int, float)):
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            return _EPOCH_ISO
    if isinstance(ts, str) and ts:
        return ts
    return _EPOCH_ISO


def _ecs_event_type(event_type: str, data: dict) -> list[str]:
    """ECS event.type (a value from the ECS type vocabulary), derived from the
    outcome/transition when known, else 'info'."""
    outcome = data.get("outcome")
    if outcome == "ok":
        return ["allowed"]
    if outcome == "denied":
        return ["denied"]
    if outcome in ("error", "timeout"):
        return ["error"]
    transition = data.get("transition") or data.get("state")
    if transition in ("AUTHENTICATED", "NETWORK_READY", "BOOT", "RUN"):
        return ["start"]
    if transition in ("DISCONNECTED", "SESSION_CLOSED"):
        return ["end"]
    return ["info"]


def _stringify(value: object) -> str:
    """ECS `labels` values are strings; render non-strings as compact JSON."""
    if isinstance(value, str):
        return value
    return json.dumps(value, separators=(",", ":"), default=str)


def to_ecs(env: dict) -> dict:
    """Map one nodebox envelope to an ECS document.

    Known fields are lifted to ECS names (@timestamp, event.*, host.*, agent.*),
    provenance is flattened into `labels`, and the full original envelope is kept
    under `nodebox` so the mapping is lossless and auditable."""
    data = env.get("data") or {}
    provenance = env.get("provenance") or {}
    event_type = env.get("event_type") or "nodebox.event"
    node_id = env.get("node_id")
    device_type = env.get("device_type") or "unknown"

    category = _ECS_CATEGORY.get(event_type, ["host"])
    kind = "alert" if event_type == "nodebox.clone" else "event"
    doc = {
        "@timestamp": _ecs_timestamp(env.get("ts")),
        "ecs": {"version": ECS_VERSION},
        "event": {
            "kind": kind,
            "module": "nodebox",
            "dataset": event_type,
            "action": event_type,
            "category": category,
            "type": _ecs_event_type(event_type, data),
        },
        "host": {"id": node_id, "type": device_type},
        "agent": {"type": "nodebox", "id": node_id},
        "observer": {"type": "controller", "vendor": "detect", "product": "nodebox"},
        "nodebox": {k: env.get(k) for k in ("schema", "node_id", "device_type",
                                            "ts", "event_type", "data", "provenance")},
    }
    outcome = _ECS_OUTCOME.get(data.get("outcome"))
    if outcome:
        doc["event"]["outcome"] = outcome
    labels = {f"provenance.{k}": _stringify(v) for k, v in provenance.items()}
    if labels:
        doc["labels"] = labels
    reason = data.get("reason") or data.get("gate_reason")
    doc["message"] = f"{event_type} {data.get('outcome') or data.get('transition') or data.get('state') or ''}".strip()
    if reason:
        doc["error"] = {"message": str(reason)}
    return doc


def load_raw_events(telemetry_path: str | Path) -> list[dict]:
    """Read raw (unflattened) envelopes; malformed lines are skipped."""
    out: list[dict] = []
    p = Path(telemetry_path)
    if not p.exists():
        return out
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return out


def normalize_ecs(telemetry_path: str | Path) -> list[dict]:
    """All telemetry events as ECS documents."""
    return [to_ecs(env) for env in load_raw_events(telemetry_path)]


def write_ecs(telemetry_path: str | Path, out_path: str | Path) -> int:
    """Write ECS documents as NDJSON to `out_path`; returns the count."""
    docs = normalize_ecs(telemetry_path)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        fh.writelines(json.dumps(doc, separators=(",", ":")) + "\n" for doc in docs)
    return len(docs)


def load_events(telemetry_path: str | Path) -> list[dict]:
    events = []
    p = Path(telemetry_path)
    if not p.exists():
        return events
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(flatten(json.loads(line)))
        except json.JSONDecodeError:
            pass
    return events


def evaluate(telemetry_path: str | Path, rules_dir: str | Path) -> dict:
    events = load_events(telemetry_path)
    results = {}
    for rule_path in sorted(Path(rules_dir).glob("nodebox_*.yml")):
        rule = vr.load_rule(str(rule_path))
        hits = vr.evaluate(rule, events)
        results[rule["title"]] = {
            "rule": rule_path.name,
            "level": rule.get("level"),
            "hits": len(hits),
            "nodes": sorted({h.get("node_id") for h in hits}),
            "transitions": sorted({str(h.get("data.transition") or h.get("data.outcome") or "") for h in hits}),
        }
    return {"events": len(events), "rules": results}


def report(telemetry_path: str | Path, rules_dir: str | Path) -> int:
    res = evaluate(telemetry_path, rules_dir)
    print(f"== nodebox collector: {res['events']} telemetry events ==")
    total = 0
    for title, r in res["rules"].items():
        total += r["hits"]
        flag = "ALERT" if r["hits"] else "  ok "
        print(f"  [{flag}] {r['level']:6} {title}  hits={r['hits']} nodes={r['nodes']}")
    print(f"== total alerts: {total} ==")
    return total


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="nodebox host-side collector")
    ap.add_argument("telemetry", nargs="?", default="nodebox_telemetry.jsonl")
    ap.add_argument("rules", nargs="?", default="rules")
    ap.add_argument("--ecs", metavar="OUT",
                    help="also write ECS-normalized NDJSON to OUT (for shipping to an ECS backend)")
    args = ap.parse_args()
    total = report(args.telemetry, args.rules)
    if args.ecs:
        n = write_ecs(args.telemetry, args.ecs)
        print(f"== wrote {n} ECS documents to {args.ecs} ==")
    raise SystemExit(0 if total >= 0 else 1)
