#!/usr/bin/env python3
"""nodebox CLI.

  nodebox stack                          show the trust stack and what is attestable
  nodebox keygen --out DIR               generate a controller identity
  nodebox enroll ...                     add a node's key to the inventory
  nodebox controller --inventory F ...   run the authenticated controller
  nodebox node ...                       run a node agent (reverse connection)
  nodebox apply --node SEL --cap CAP     dispatch a typed capability
  nodebox collect [telemetry] [rules]    host-side pySigma over telemetry
  nodebox ssh task|shell ...             bounded, attributable SSH admin plane
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import nodebox_crypto as nc
import nodebox_layers as layers


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def cmd_stack(_a) -> int:
    _print(layers.describe_stack())
    print("\nattestation scope with no external anchors:")
    _print(layers.attestation_scope([]))
    return 0


def cmd_keygen(a) -> int:
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    ident = nc.Identity.generate()
    ident.save(out / "controller.key")
    (out / "controller.json").write_text(json.dumps({
        "controller_id": "ctrl-" + ident.fingerprint[:12],
        "pubkey_b64": nc.b64e(ident.pub_raw),
        "fingerprint": ident.fingerprint,
    }, indent=2))
    print(f"wrote {out/'controller.key'} and controller.json")
    return 0


def cmd_enroll(a) -> int:
    from nodebox_controller import enroll, load_inventory, save_inventory
    inv = load_inventory(a.inventory) if Path(a.inventory).exists() else {"nodes": {}}
    node_id = enroll(inv, a.alias, a.pubkey, a.device_type, a.caps, a.machine_binding or "unknown")
    save_inventory(a.inventory, inv)
    print(f"enrolled {a.alias} as {node_id}")
    return 0


def cmd_controller(a) -> int:
    from nodebox_controller import Controller, load_inventory
    inv = load_inventory(a.inventory)
    ident = nc.Identity.load(Path(a.key))
    host, _, port = a.listen.partition(":")
    c = Controller(ident, inv.get("controller_id", "ctrl"), inv, a.telemetry,
                   host=host or "127.0.0.1", port=int(port or 9443))
    try:
        c.serve_forever()
    except KeyboardInterrupt:
        c.stop()
    return 0


def cmd_node(a) -> int:
    from nodebox_agent import NodeAgent
    host, _, port = a.controller.partition(":")
    agent = NodeAgent(
        state_dir=Path(a.state_dir), device_type=a.device_type,
        allowed_capabilities=set(a.caps), controller_addr=(host, int(port)),
        pinned_controller_pubkey=nc.b64d(a.controller_pub), controller_id=a.controller_id,
        telemetry_path=Path(a.telemetry),
        anchors=[] if a.no_supervisor else ["supervisor"],
        telemetry_interval=a.interval)
    try:
        return agent.run()
    except KeyboardInterrupt:
        return 0


def cmd_apply(a) -> int:
    raise SystemExit("apply requires a running controller in-process; use nodebox_demo.py "
                     "for the loopback network demo, or import Controller.apply")


def cmd_collect(a) -> int:
    from nodebox_collector import report, write_ecs
    report(a.telemetry, a.rules)
    if a.ecs:
        n = write_ecs(a.telemetry, a.ecs)
        print(f"wrote {n} ECS documents to {a.ecs}")
    return 0


def cmd_ssh(a) -> int:
    from nodebox_broker import BrokerError, reject_arbitrary, ssh_session
    from nodebox_controller import load_inventory
    inv = load_inventory(a.inventory)
    try:
        reject_arbitrary(getattr(a, "command", None))
        kind = "scheduled_task" if a.ssh_cmd == "task" else "interactive_shell"
        argv = ssh_session(inv, a.node, kind, task_id=getattr(a, "task", None), dry_run=a.dry_run)
    except BrokerError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    print(" ".join(argv))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nodebox")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("stack"); s.set_defaults(func=cmd_stack)

    s = sub.add_parser("keygen"); s.add_argument("--out", default="keys"); s.set_defaults(func=cmd_keygen)

    s = sub.add_parser("enroll")
    s.add_argument("--inventory", required=True); s.add_argument("--alias", required=True)
    s.add_argument("--device-type", required=True); s.add_argument("--pubkey", required=True)
    s.add_argument("--caps", nargs="*", default=[]); s.add_argument("--machine-binding", default="")
    s.set_defaults(func=cmd_enroll)

    s = sub.add_parser("controller")
    s.add_argument("--inventory", required=True); s.add_argument("--key", required=True)
    s.add_argument("--listen", default="127.0.0.1:9443")
    s.add_argument("--telemetry", default="nodebox_telemetry.jsonl")
    s.set_defaults(func=cmd_controller)

    s = sub.add_parser("node")
    s.add_argument("--state-dir", required=True); s.add_argument("--device-type", required=True)
    s.add_argument("--caps", nargs="*", default=[])
    s.add_argument("--controller", required=True); s.add_argument("--controller-pub", required=True)
    s.add_argument("--controller-id", required=True)
    s.add_argument("--telemetry", default="nodebox_telemetry.jsonl")
    s.add_argument("--no-supervisor", action="store_true")
    s.add_argument("--interval", type=float, default=5.0)
    s.set_defaults(func=cmd_node)

    s = sub.add_parser("apply")
    s.add_argument("--node", required=True); s.add_argument("--cap", required=True)
    s.set_defaults(func=cmd_apply)

    s = sub.add_parser("collect")
    s.add_argument("telemetry", nargs="?", default="nodebox_telemetry.jsonl")
    s.add_argument("rules", nargs="?", default="rules")
    s.add_argument("--ecs", metavar="OUT", default=None,
                   help="also write ECS-normalized NDJSON to OUT")
    s.set_defaults(func=cmd_collect)

    s = sub.add_parser("ssh")
    ssh_sub = s.add_subparsers(dest="ssh_cmd", required=True)
    for name in ("task", "shell"):
        q = ssh_sub.add_parser(name)
        q.add_argument("--inventory", required=True); q.add_argument("--node", required=True)
        if name == "task":
            q.add_argument("--task", required=True)
        q.add_argument("--dry-run", action="store_true")
        q.add_argument("--command", default=None, help=argparse.SUPPRESS)  # always refused
        q.set_defaults(func=cmd_ssh)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
