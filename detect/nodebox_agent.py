#!/usr/bin/env python3
"""nodebox node agent: lifecycle, controller-auth-first session, typed commands.

Runs INSIDE the microVM (guest userspace, bottom of the trust stack). It owns
identity, interfaces, service inventory, connection state, session ids and
telemetry output -- and NOTHING ELSE. No shell, no exec, no subprocess: every
"action" is a fixed, typed capability operating on the node's own state.

Lifecycle: BOOT -> IDENTITY -> ENROLL -> NETWORK_READY -> SERVICES_READY ->
AUTHENTICATED_TO_CONTROLLER -> EMIT_TELEMETRY -> RUN
"""
from __future__ import annotations

import hashlib
import json
import os
import select
import socket
import sys
import time
from pathlib import Path

import nodebox_crypto as nc
import nodebox_layers as layers
from nodebox_identity import IdentityStore, boot_id
from nodebox_protocol import CAPABILITIES, MUTATING, client_handshake
from nodebox_telemetry import envelope

LIFECYCLE = ["BOOT", "IDENTITY", "ENROLL", "NETWORK_READY", "SERVICES_READY",
             "AUTHENTICATED_TO_CONTROLLER", "EMIT_TELEMETRY", "RUN"]


class NodeAgent:
    def __init__(
        self,
        state_dir: Path,
        device_type: str,
        allowed_capabilities: set[str],
        controller_addr: tuple[str, int],
        pinned_controller_pubkey: bytes,
        controller_id: str,
        telemetry_path: Path,
        anchors: list[str] | None = None,
        telemetry_interval: float = 1.0,
        connect_timeout: float = 5.0,
    ):
        self.state_dir = Path(state_dir)
        self.device_type = device_type
        self.allowed = set(allowed_capabilities)
        self.controller_addr = controller_addr
        self.pinned_controller_pubkey = pinned_controller_pubkey
        self.controller_id = controller_id
        self.telemetry_path = Path(telemetry_path)
        self.anchors = ["supervisor"] if anchors is None else anchors
        self.telemetry_interval = telemetry_interval
        self.connect_timeout = connect_timeout
        self.boot_id = boot_id()
        self.started = time.time()
        self.counters = {"events": 0, "commands": 0, "denied": 0, "reconnects": 0}
        self.last_command_id: str | None = None
        self._ring: list[dict] = []

    # -- telemetry -----------------------------------------------------------
    def _emit(self, event_type: str, data: dict) -> dict:
        env = envelope(
            node_id=self.identity.node_id,
            device_type=self.device_type,
            event_type=event_type,
            data=data,
            provenance={
                "boot_id": self.boot_id,
                "machine_binding": self.record.machine_binding,
                "layer": "PROCESS",
                "attestation_depth": layers.attestation_scope(self.anchors)["depth"],
                "supervisor": layers.supervisor_identity(),
                "code_digest": layers.process_provenance(Path(__file__).resolve().parent)["code_digest"],
            },
        )
        self._ring.append(env)
        self._ring = self._ring[-50:]
        self.counters["events"] += 1
        with open(self.telemetry_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(env, separators=(",", ":")) + "\n")
        return env

    # -- identity ------------------------------------------------------------
    def load_identity(self) -> None:
        store = IdentityStore(self.state_dir)
        ident, rec, first = store.load_or_create()
        self.identity = ident
        self.record = rec
        self._emit("nodebox.lifecycle", {"state": "BOOT"})
        self._emit("nodebox.lifecycle", {"state": "IDENTITY", "first_boot": first})
        if not rec.enrolled:
            self._emit("nodebox.enrollment", {"state": "ENROLL", "enrolled": False,
                                              "reason": "awaiting controller enrollment"})

    # -- attestation ---------------------------------------------------------
    def attestation(self) -> dict:
        scope = layers.attestation_scope(self.anchors)
        proc = layers.process_provenance(Path(__file__).resolve().parent)
        return {
            "node_id": self.identity.node_id,
            "pubkey": nc.b64e(self.identity.pub_raw),
            "machine_binding": self.record.machine_binding,
            "boot_id": self.boot_id,
            "capability_manifest": sorted(self.allowed),
            "attestation_scope": scope,
            "code_digest": proc["code_digest"],
            "supervisor": proc["supervisor"],
            "process": {"pid": proc["pid"], "ppid": proc["ppid"], "argv0": proc["argv0"],
                        "user": proc["user"], "platform": proc["platform"]},
        }

    # -- commands (typed; no exec) ------------------------------------------
    def handle_command(self, msg: dict, policy_caps: set[str]) -> dict:
        cap = msg.get("capability")
        cid = msg.get("command_id")
        params = msg.get("params") or {}
        self.counters["commands"] += 1
        self.last_command_id = cid
        allowed = cap in self.allowed and cap in policy_caps
        if cap not in CAPABILITIES:
            outcome, data = "denied", {"reason": "unknown_capability"}
        elif not allowed:
            outcome, data = "denied", {"reason": "not_authorized", "capability": cap}
        else:
            outcome, data = self._execute(cap, params)
        if outcome == "denied":
            self.counters["denied"] += 1
        result = {"type": "RESULT", "command_id": cid, "capability": cap,
                  "outcome": outcome, "data": data}
        self._emit("nodebox.command", {"command_id": cid, "capability": cap,
                                       "outcome": outcome, "mutating": cap in MUTATING,
                                       "reason": data.get("reason")})
        return result

    def _execute(self, cap: str, params: dict) -> tuple[str, dict]:
        if cap == "PING":
            return "ok", {"pong": True, "ts": int(time.time())}
        if cap == "INFO":
            return "ok", {"node_id": self.identity.node_id, "device_type": self.device_type,
                          "capabilities": sorted(self.allowed),
                          "attestation_scope": layers.attestation_scope(self.anchors)}
        if cap == "STATUS":
            return "ok", {"uptime_s": round(time.time() - self.started, 1),
                          "counters": self.counters, "last_command_id": self.last_command_id,
                          "state": "RUN"}
        if cap == "SYNC_CONFIG":
            cfg = params.get("config")
            if not isinstance(cfg, dict):
                return "denied", {"reason": "config_must_be_object"}
            p = self.state_dir / "config.json"
            p.write_text(json.dumps(cfg, indent=2))
            return "ok", {"digest": hashlib.sha256(p.read_bytes()).hexdigest(), "path": str(p.name)}
        if cap == "UPDATE_RULESET":
            rs = params.get("ruleset")
            sig = params.get("sig")
            if not isinstance(rs, str) or not isinstance(sig, str):
                return "denied", {"reason": "ruleset_and_sig_required"}
            try:
                nc.Identity.verify(self.pinned_controller_pubkey, nc.b64d(sig), rs.encode())
            except Exception:  # noqa: BLE001 - fail closed on any verify/decode error
                return "denied", {"reason": "controller_signature_invalid"}
            d = self.state_dir / "ruleset"
            d.mkdir(exist_ok=True)
            (d / "ruleset.yml").write_text(rs)
            return "ok", {"digest": hashlib.sha256(rs.encode()).hexdigest()}
        if cap == "FETCH_LOGS":
            p = self.telemetry_path
            if not p.exists():
                return "ok", {"lines": []}
            tail = p.read_text(encoding="utf-8").splitlines()[-int(params.get("lines", 20)):]
            return "ok", {"lines": tail}
        if cap == "CAPTURE_TELEMETRY":
            return "ok", {"events": self._ring[-int(params.get("count", 10)):]}
        if cap == "RESTART_SERVICE":
            # Legitimate restart is owned by the SERVICE MANAGER, not the agent:
            # the agent records the authorized request and exits with EX_TEMPFAIL
            # so launchd/systemd restarts it. No exec, no kill, no shell.
            if os.environ.get("NODEBOX_ALLOW_RESTART") == "1":
                return "ok", {"action": "exit_for_supervisor_restart", "exit_code": 75}
            return "denied", {"reason": "restart_requires_supervisor_and_optin"}
        if cap == "DISCONNECT":
            return "ok", {"bye": True}
        return "denied", {"reason": "unimplemented"}

    # -- session -------------------------------------------------------------
    def run(self) -> int:
        self.load_identity()
        if not self.record.enrolled:
            print(f"[node {self.identity.node_id}] not enrolled; run `nodebox enroll` first", file=sys.stderr)
            return 2
        self._emit("nodebox.lifecycle", {"state": "NETWORK_READY",
                                         "controller": f"{self.controller_addr[0]}:{self.controller_addr[1]}"})
        self._emit("nodebox.lifecycle", {"state": "SERVICES_READY",
                                         "services": sorted(self.allowed)})
        try:
            sock = socket.create_connection(self.controller_addr, timeout=self.connect_timeout)
        except OSError as exc:
            self._emit("nodebox.session", {"transition": "CONNECT_FAILED", "reason": str(exc)})
            return 3
        sock.settimeout(None)
        try:
            sess = client_handshake(sock, self.identity, self.pinned_controller_pubkey,
                                    self.controller_id)
        except Exception as exc:  # noqa: BLE001
            # Unknown controller / bad signature => reject BEFORE session creation.
            self._emit("nodebox.session", {"transition": "AUTH_REJECTED",
                                           "reason": type(exc).__name__ + ": " + str(exc),
                                           "controller_id": self.controller_id})
            sock.close()
            return 4

        self._emit("nodebox.lifecycle", {"state": "AUTHENTICATED_TO_CONTROLLER",
                                         "session_id": sess.session_id})
        sess.send({"type": "ATTEST", "attestation": self.attestation()})
        policy = sess.recv()
        if policy.get("type") != "POLICY_SYNC":
            self._emit("nodebox.session", {"transition": "SYNC_FAILED", "reason": "no POLICY_SYNC"})
            sock.close()
            return 5
        policy_caps = set(policy.get("allowed_capabilities", []))
        self._emit("nodebox.lifecycle", {"state": "EMIT_TELEMETRY",
                                         "policy_digest": policy.get("policy_digest")})
        self._emit("nodebox.lifecycle", {"state": "RUN"})

        last_emit = 0.0
        while True:
            r, _, _ = select.select([sock], [], [], 0.2)
            if r:
                try:
                    msg = sess.recv()
                except Exception as exc:  # noqa: BLE001
                    self._emit("nodebox.session", {"transition": "SESSION_CLOSED",
                                                   "reason": type(exc).__name__})
                    break
                if msg.get("type") == "COMMAND":
                    result = self.handle_command(msg, policy_caps)
                    sess.send(result)
                    if result["capability"] == "DISCONNECT" and result["outcome"] == "ok":
                        break
                elif msg.get("type") == "DISCONNECT":
                    break
            if time.time() - last_emit >= self.telemetry_interval:
                self._emit("nodebox.health", {
                    "uptime_s": round(time.time() - self.started, 1),
                    "counters": dict(self.counters),
                    "services": sorted(self.allowed),
                })
                last_emit = time.time()
        sock.close()
        return 0
