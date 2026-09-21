#!/usr/bin/env python3
"""File a proposal into the operator approval queue — the agent's only write.

This runs NOTHING. It validates the capability and its args against
`toolbox_registry.json` and appends a single `created` event to
`toolbox_proposals.jsonl`. The operator then authorizes (or rejects) it in the
panel; only on authorize does the toolbox-rs run spine fire, through
`authz_gate.py`. There is no flag here that runs, and no way to authorize.

Arg values are shape-checked here; option-set membership is re-resolved
server-side at authorize time (the CLI cannot enumerate `view`-sourced sets),
so a value that is not in the live set is refused then, not now.

Run:
    ../bin/python3 toolbox_propose.py --cap validate.demo --note "why I want it" \
        --arg node=gateway --arg task=collect-health
    ../bin/python3 toolbox_propose.py --cap hunt.coverage --args-json '{}'
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REGISTRY = HERE / "toolbox_registry.json"
LOG = HERE / "toolbox_proposals.jsonl"


def load_caps() -> dict:
    doc = json.loads(REGISTRY.read_text())
    return {c["id"]: c for c in doc.get("capabilities", [])}


def args_of(cap: dict, caps: dict) -> list[dict]:
    spec = cap.get("args")
    if isinstance(spec, list):
        return spec
    if isinstance(spec, dict) and "from" in spec:
        target = caps.get(spec["from"])
        if target and isinstance(target.get("args"), list):
            return target["args"]
    return []


def coerce(spec: dict, raw: object) -> object:
    kind = spec.get("kind")
    if kind == "int":
        return int(raw)
    if kind == "bool":
        if isinstance(raw, bool):
            return raw
        return str(raw).lower() in ("1", "true", "yes", "on")
    if kind == "multi-enum":
        if isinstance(raw, list):
            return [str(x) for x in raw]
        return [s for s in str(raw).split(",") if s]
    return raw


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="File a proposal; run nothing.")
    ap.add_argument("--cap", required=True, help="capability id from the registry")
    ap.add_argument("--note", default="", help="why this is being proposed")
    ap.add_argument("--created-by", default="agent", help="who filed it")
    ap.add_argument("--arg", action="append", default=[], metavar="NAME=VALUE",
                    help="one argument (repeatable)")
    ap.add_argument("--args-json", default="", help="arguments as a JSON object")
    args = ap.parse_args(argv)

    caps = load_caps()
    cap = caps.get(args.cap)
    if not cap:
        print(f"no such capability: {args.cap}", file=sys.stderr)
        return 2
    if not cap.get("enabled", True):
        print(f"capability is disabled: {args.cap}", file=sys.stderr)
        return 2

    raw: dict = {}
    if args.args_json:
        try:
            parsed = json.loads(args.args_json)
        except ValueError as exc:
            print(f"--args-json is not JSON: {exc}", file=sys.stderr)
            return 2
        if not isinstance(parsed, dict):
            print("--args-json must be a JSON object", file=sys.stderr)
            return 2
        raw.update(parsed)
    for pair in args.arg:
        name, sep, value = pair.partition("=")
        if not sep:
            print(f"--arg expects NAME=VALUE, got {pair!r}", file=sys.stderr)
            return 2
        raw[name] = value

    specs = {s["name"]: s for s in args_of(cap, caps)}
    out: dict = {}
    for name, value in raw.items():
        if name not in specs:
            print(f"unknown argument {name!r} for {args.cap}", file=sys.stderr)
            return 2
        if specs[name].get("kind") == "server":
            print(f"{name!r} is server-generated; omit it", file=sys.stderr)
            return 2
        try:
            out[name] = coerce(specs[name], value)
        except (TypeError, ValueError):
            print(f"{name!r} has the wrong type for kind {specs[name].get('kind')!r}", file=sys.stderr)
            return 2

    seq = 1
    if LOG.exists():
        with LOG.open() as fh:
            seq = sum(1 for line in fh if line.strip()) + 1
    ts = int(time.time())
    pid = f"p{ts:x}{seq:x}"
    event = {
        "seq": seq,
        "ts": ts,
        "kind": "created",
        "id": pid,
        "capability": args.cap,
        "args": out,
        "note": args.note,
        "created_by": args.created_by,
    }
    with LOG.open("a") as fh:
        fh.write(json.dumps(event) + "\n")

    print(json.dumps({"ok": True, "proposal": pid, "capability": args.cap, "args": out}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
