#!/usr/bin/env python3
"""JSON entrypoint for the toolbox's SSH task dispatch (used by toolbox-rs).

Wraps `nodebox_broker.ssh_session` with a machine-readable contract: build the
argv (always, via the broker's own `resolve_task`/`build_ssh_argv` — nothing
here bypasses that) and either print it as JSON (default) or additionally run
it and report the outcome (`--execute`).

This exists because `nodebox_cli.py ssh task` is a human-facing CLI that
prints `" ".join(argv)`; reconstructing an argv by splitting that string back
apart is lossy whenever an element contains internal whitespace (a task's
remote command, for instance). This script passes the argv as a JSON array
instead, so nothing round-trips through string splitting.

The broker's boundary is unchanged and is not re-implemented here:
`reject_arbitrary` refuses a free-text command (this entrypoint has no
`--command` flag at all — there is no argument that could carry one),
`resolve_task` only accepts a task_id already defined in `inventory.json`, and
`resolve_node` refuses a host with no sshd. This script adds no authority of
its own; it is the same call `nodebox_cli.py ssh task` makes, plus an
explicit, opt-in execute step.

Output (always one JSON object on stdout):
    {"argv": [...]}                                            # preview
    {"argv": [...], "exit_code": N, "stdout": "...", "stderr": "..."}  # --execute
    {"error": "..."}                                            # refused, exit 2

Run:
    ../bin/python3 toolbox_ssh_exec.py --inventory inventory.json \
        --node gateway --task collect-health [--execute]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys

from nodebox_broker import BrokerError, reject_arbitrary, ssh_session
from nodebox_controller import load_inventory

TIMEOUT_SECONDS = 25.0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--inventory", required=True)
    ap.add_argument("--node", required=True)
    ap.add_argument("--task", required=True)
    ap.add_argument("--execute", action="store_true", help="run the argv, not just build it")
    args = ap.parse_args(argv)

    inv = load_inventory(args.inventory)
    try:
        reject_arbitrary(None)  # no --command flag exists here to carry one; this is belt-and-braces
        built = ssh_session(inv, args.node, "scheduled_task", task_id=args.task, dry_run=True)
    except BrokerError as exc:
        print(json.dumps({"error": str(exc)}))
        return 2

    if not args.execute:
        print(json.dumps({"argv": built}))
        return 0

    try:
        proc = subprocess.run(built, capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=False)
    except subprocess.TimeoutExpired as exc:
        out = exc.output if isinstance(exc.output, str) else (exc.output or b"").decode("utf-8", "replace")
        err = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode("utf-8", "replace")
        print(json.dumps({"argv": built, "error": f"timed out after {TIMEOUT_SECONDS}s", "stdout": out, "stderr": err}))
        return 2
    print(json.dumps({"argv": built, "exit_code": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
