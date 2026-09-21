#!/usr/bin/env python3
"""nodebox SSH broker: the attributable admin plane (separate from the agent).

This is NOT a general-purpose remote execution launcher. It:

  * resolves nodes from the inventory (unknown host -> refuse);
  * resolves TASKS from the inventory (arbitrary --command -> refuse);
  * builds a hardened OpenSSH argv (pinned host key, no agent forwarding, no
    port forwards, short-lived multiplexing in a per-user control socket);
  * emits an ssh_session event recording the AUTHORIZATION PATH (who launched
    it, inventory revision, node id, pinned host key alias, command category,
    outcome) so the system can PROVE the session was legitimate -- rather than
    trying to look like something it is not.
"""
from __future__ import annotations

import os
import socket
import sys
import uuid
from pathlib import Path

from nodebox_telemetry import envelope


class BrokerError(Exception):
    pass


def _control_dir() -> Path:
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Caches" / "nodebox"
    else:
        base = Path(f"/run/user/{os.getuid()}") / "nodebox"
    base.mkdir(parents=True, exist_ok=True)
    os.chmod(base, 0o700)          # per-user, not group/world writable
    return base


def resolve_node(inventory: dict, selector: str) -> dict:
    nodes = inventory.get("nodes") or {}
    rec: dict | None = None
    if selector in nodes:
        rec = {"key": selector, **nodes[selector]}
    else:
        for node_id, r in nodes.items():
            if r.get("alias") == selector:
                rec = {"key": node_id, **r}
                break
    if rec is None:
        raise BrokerError(f"unknown node: {selector} (not in inventory)")
    # The SSH admin plane only reaches hosts that actually run sshd. A node
    # marked `sshd: false` (e.g. a router whose port 22 is filtered) is refused
    # here rather than having a hardened SSH argv built that could never connect.
    if rec.get("sshd") is False:
        note = rec.get("note", "host does not run sshd")
        raise BrokerError(f"node {selector} does not run sshd ({note}); "
                          f"use its read-only HTTP API, not the SSH admin plane")
    return rec


def resolve_task(inventory: dict, node: dict, task_id: str) -> list[str]:
    tasks = (node.get("tasks") or {})
    if task_id not in tasks:
        raise BrokerError(f"unknown task: {task_id} (no reviewed definition)")
    task = tasks[task_id]
    cmd = task.get("remote_command")
    if not isinstance(cmd, list) or not cmd or not all(isinstance(x, str) for x in cmd):
        raise BrokerError(f"task {task_id} has no allowlisted remote_command")
    return cmd


def _safe_token(field: str, value: object) -> str:
    """A node field that becomes a bare argv token must be a string that does not
    begin with '-', or ssh would parse it as an option (e.g. a `user` of
    `-oProxyCommand=...` turns the destination token into an injected option).
    Inventory is operator-controlled, but this is cheap defense-in-depth."""
    if not isinstance(value, str) or not value or value.startswith("-"):
        raise BrokerError(f"inventory {field} {value!r} is invalid "
                          f"(must be a non-empty string not starting with '-')")
    return value


def build_ssh_argv(node: dict, remote_command: list[str] | None) -> list[str]:
    if "address" not in node or "user" not in node:
        raise BrokerError("node missing address/user")
    user = _safe_token("user", node["user"])
    address = _safe_token("address", node["address"])
    known_hosts = node.get("known_hosts") or str(Path.home() / ".ssh" / "known_hosts")
    argv = [
        "ssh",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", f"HostKeyAlias={node.get('host_key_alias', node['key'])}",
        "-o", "ForwardAgent=no",
        "-o", "ClearAllForwardings=yes",
        "-o", "ControlMaster=auto",
        "-o", f"ControlPath={_control_dir() / 'cm-%C'}",
        "-o", "ControlPersist=5m",
    ]
    # Non-default sshd port (e.g. the gateway on 2222). Coerced to int so a
    # malformed inventory value can never inject extra argv tokens; a non-numeric
    # value is surfaced as a BrokerError (which callers handle), not a raw
    # ValueError that would escape the broker's error contract.
    port = node.get("port")
    if port is not None:
        try:
            port_int = int(port)
        except (TypeError, ValueError) as exc:
            raise BrokerError(f"inventory port {port!r} is not an integer") from exc
        argv += ["-p", str(port_int)]
    argv.append(f"{user}@{address}")
    if remote_command:
        argv += remote_command
    return argv


def _emit(inventory: dict, node: dict, request_kind: str, outcome: str, extra: dict) -> None:
    telemetry = inventory.get("telemetry_path", "nodebox_telemetry.jsonl")
    env = envelope(
        node_id=node.get("key", "?"),
        device_type=node.get("device_type", "unknown"),
        event_type="nodebox.ssh_session",
        data={"request_kind": request_kind, "outcome": outcome, **extra},
        provenance={
            "launcher": "nodebox-cli",
            "launcher_user": os.environ.get("USER", "?"),
            "host": socket.gethostname(),
            "inventory_revision": inventory.get("revision", "unknown"),
            "dst_node": node.get("key"),
            "dst_address": node.get("address"),
            "host_key_alias": node.get("host_key_alias"),
        },
    )
    Path(telemetry).parent.mkdir(parents=True, exist_ok=True)
    with open(telemetry, "a", encoding="utf-8") as fh:
        import json
        fh.write(json.dumps(env, separators=(",", ":")) + "\n")


def ssh_session(inventory: dict, selector: str, request_kind: str, task_id: str | None = None,
                dry_run: bool = False) -> list[str]:
    """Build (and optionally run) a bounded, attributable SSH session."""
    node = resolve_node(inventory, selector)
    if request_kind == "interactive_shell":
        remote_command = None
    elif request_kind == "scheduled_task":
        if not task_id:
            raise BrokerError("scheduled_task requires --task")
        remote_command = resolve_task(inventory, node, task_id)
    else:
        raise BrokerError(f"unknown request_kind: {request_kind}")

    argv = build_ssh_argv(node, remote_command)
    session_id = str(uuid.uuid4())
    _emit(inventory, node, request_kind, "requested", {
        "session_id": session_id,
        "task_id": task_id,
        "command_category": "allowlisted" if remote_command else "interactive",
        "argv0": argv[0],
    })
    if dry_run:
        return argv
    return argv


def reject_arbitrary(command: str | None) -> None:
    """The broker has no path for an arbitrary remote command string."""
    if command:
        raise BrokerError("arbitrary --command is not supported; define a reviewed task")
