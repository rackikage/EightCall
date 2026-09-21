#!/usr/bin/env python3
"""nodebox controller: enrollment, authenticated session listener, typed dispatch,
and clone detection.

Host-side. It authenticates each node (enrolled key), syncs policy, receives
telemetry, and dispatches ONLY typed capabilities. It never sends a command the
node's policy does not grant, and it flags a node_id that reappears with a
different boot_id / machine binding (a cloned disk carrying a copied key).
"""
from __future__ import annotations

import json
import socket
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import nodebox_crypto as nc
from nodebox_crypto import Identity
from nodebox_protocol import server_handshake
from nodebox_telemetry import envelope

try:
    import yaml
except Exception:  # noqa: BLE001
    yaml = None


def load_inventory(path: str | Path) -> dict:
    text = Path(path).read_text()
    if str(path).endswith((".yml", ".yaml")) and yaml is not None:
        return yaml.safe_load(text)
    return json.loads(text)


def save_inventory(path: str | Path, inv: dict) -> None:
    Path(path).write_text(json.dumps(inv, indent=2))


def enroll(inv: dict, alias: str, pubkey_b64: str, device_type: str,
           allowed_capabilities: list[str], machine_binding: str) -> str:
    pub_raw = nc.b64d(pubkey_b64)
    node_id = nc.node_id_for(pub_raw)
    inv.setdefault("nodes", {})[node_id] = {
        "alias": alias,
        "device_type": device_type,
        "pubkey_b64": pubkey_b64,
        "machine_binding": machine_binding,
        "allowed_capabilities": sorted(allowed_capabilities),
        "enrolled_at": time.time(),
    }
    return node_id


@dataclass
class SessionHandle:
    node_id: str
    sock: socket.socket
    session: object
    policy_caps: set[str]
    boot_id: str = ""
    machine_binding: str = ""
    lock: threading.Lock = field(default_factory=threading.Lock)


class Controller:
    """Host-side controller.

    Dispatch (`apply`) has two independent authorization boundaries, both
    deny-by-default:

      1. the node's inventory `allowed_capabilities` (controller policy), and
      2. optionally, the deterministic response gate (`authz_gate.AuthzGate`).

    When a gate is configured, NO capability is dispatched without a signed
    allow: `apply` builds an HMAC-signed request (caller/action/target/nonce/
    issued_at), submits it to the gate, and dispatches only on `decision.allow`.
    Every decision (allow or deny) is written to the gate's hash-chained audit
    trail, and the returned `decision_id` is attached to the result telemetry.
    A denied dispatch still emits a `nodebox.command`/`outcome=denied` event, so
    `rules/nodebox_unauthorized_capability.yml` catches it like any other denial.
    """

    def __init__(self, identity: Identity, controller_id: str, inventory: dict,
                 telemetry_path: str | Path, host: str = "127.0.0.1", port: int = 9443,
                 *, gate: object | None = None, gate_caller: str | None = None,
                 gate_key: bytes | None = None):
        self.identity = identity
        self.controller_id = controller_id
        self.inventory = inventory
        self.telemetry_path = Path(telemetry_path)
        self.host = host
        self.port = port
        self.sessions: dict[str, SessionHandle] = {}
        self._pending: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        # Optional response gate. If set, both gate_caller and gate_key are
        # required so the controller can sign requests as a registered caller.
        if gate is not None and (not gate_caller or not gate_key):
            raise ValueError("gate requires both gate_caller and gate_key")
        self.gate = gate
        self.gate_caller = gate_caller
        self.gate_key = gate_key

    # -- enrollment ----------------------------------------------------------
    def _resolve_node(self, node_id: str) -> bytes | None:
        rec = (self.inventory.get("nodes") or {}).get(node_id)
        return nc.b64d(rec["pubkey_b64"]) if rec else None

    def _policy_caps(self, node_id: str) -> list[str]:
        rec = (self.inventory.get("nodes") or {}).get(node_id) or {}
        return list(rec.get("allowed_capabilities") or [])

    def _emit(self, node_id: str, event_type: str, data: dict, provenance: dict | None = None) -> None:
        env = envelope(node_id, (self.inventory.get("nodes", {}).get(node_id, {}) or {}).get("device_type", "unknown"),
                       event_type, data, provenance)
        self.telemetry_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.telemetry_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(env, separators=(",", ":")) + "\n")

    # -- server --------------------------------------------------------------
    def serve_forever(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(16)
        srv.settimeout(0.5)
        print(f"[controller {self.controller_id}] listening on {self.host}:{self.port}")
        while not self._stop.is_set():
            try:
                conn, addr = srv.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()
        srv.close()

    def stop(self) -> None:
        self._stop.set()

    def _handle(self, conn: socket.socket, addr) -> None:
        try:
            sess = server_handshake(conn, self.identity, self.controller_id, self._resolve_node)
        except Exception as exc:  # noqa: BLE001
            print(f"[controller] rejected {addr[0]}: {type(exc).__name__}: {exc}")
            conn.close()
            return

        node_id = sess.node_id
        att = sess.recv()
        if att.get("type") != "ATTEST":
            conn.close()
            return
        a = att["attestation"]
        handle = SessionHandle(node_id, conn, sess, set(self._policy_caps(node_id)),
                               boot_id=a.get("boot_id", ""),
                               machine_binding=a.get("machine_binding", ""))

        # clone detection: same node_id, different boot/machine while another
        # session for that node_id is live => a copied key on a second instance.
        with self._lock:
            prior = self.sessions.get(node_id)
            if prior and (prior.boot_id != handle.boot_id or prior.machine_binding != handle.machine_binding):
                self._emit(node_id, "nodebox.clone", {
                    "transition": "CLONE_SUSPECTED",
                    "prior_boot_id": prior.boot_id, "new_boot_id": handle.boot_id,
                    "prior_machine_binding": prior.machine_binding,
                    "new_machine_binding": handle.machine_binding,
                    "reason": "same node_id, different boot_id or machine_binding",
                })
            self.sessions[node_id] = handle

        enrolled_binding = (self.inventory.get("nodes", {}).get(node_id, {}) or {}).get("machine_binding")
        if enrolled_binding and handle.machine_binding and enrolled_binding != handle.machine_binding:
            self._emit(node_id, "nodebox.clone", {
                "transition": "BINDING_MISMATCH",
                "enrolled_machine_binding": enrolled_binding,
                "presented_machine_binding": handle.machine_binding,
            })

        self._emit(node_id, "nodebox.session", {
            "transition": "AUTHENTICATED",
            "session_id": sess.session_id,
            "capability_manifest": a.get("capability_manifest"),
            "attestation_scope": a.get("attestation_scope"),
            "code_digest": a.get("code_digest"),
            "supervisor": a.get("supervisor"),
            "peer": addr[0],
        }, provenance={"boot_id": handle.boot_id, "machine_binding": handle.machine_binding})

        policy_digest = nc.b64e(__import__("hashlib").sha256(
            json.dumps(sorted(handle.policy_caps)).encode()).digest())
        sess.send({"type": "POLICY_SYNC", "allowed_capabilities": sorted(handle.policy_caps),
                   "policy_digest": policy_digest})

        try:
            while True:
                msg = sess.recv()
                mtype = msg.get("type")
                if mtype == "RESULT":
                    with self._lock:
                        p = self._pending.get(msg.get("command_id"))
                        if p:
                            p["result"] = msg
                            p["event"].set()
                    self._emit(node_id, "nodebox.result", {
                        "command_id": msg.get("command_id"),
                        "capability": msg.get("capability"),
                        "outcome": msg.get("outcome"),
                    })
                elif mtype == "EVENT":
                    env = msg.get("envelope") or {}
                    with open(self.telemetry_path, "a", encoding="utf-8") as fh:
                        fh.write(json.dumps(env, separators=(",", ":")) + "\n")
        except Exception as exc:  # noqa: BLE001
            self._emit(node_id, "nodebox.session", {"transition": "DISCONNECTED",
                                                    "reason": type(exc).__name__})
        finally:
            with self._lock:
                if self.sessions.get(node_id) is handle:
                    del self.sessions[node_id]
            conn.close()

    # -- response gate -------------------------------------------------------
    def _gate_target(self, node_id: str) -> str:
        """Stable, policy-matchable target string for a node (`node:<node_id>`)."""
        return f"node:{node_id}"

    def _gate_decision(self, node_id: str, capability: str,
                       evidence_ref: str | None) -> tuple[bool, str, str | None]:
        """Ask the response gate whether this dispatch may proceed.

        Returns (allow, reason, decision_id). The controller signs the request
        as its registered caller; authority comes only from the gate's policy,
        never from the capability or any node-supplied content."""
        req = {
            "caller": self.gate_caller,
            "action": capability,
            "target": self._gate_target(node_id),
            "nonce": uuid.uuid4().hex,
            "issued_at": datetime.now(timezone.utc).isoformat(),
        }
        if evidence_ref is not None:
            req["evidence_ref"] = evidence_ref
        # AuthzGate.sign is a @staticmethod; call it via the instance's class so
        # the controller needs no direct import of authz_gate.
        req["sig"] = type(self.gate).sign(req, self.gate_key)
        decision = self.gate.authorize(req)
        return decision.allow, decision.reason, decision.decision_id

    # -- dispatch ------------------------------------------------------------
    def apply(self, node_id: str, capability: str, params: dict | None = None,
              timeout: float = 5.0, *, evidence_ref: str | None = None) -> dict:
        handle = self.sessions.get(node_id)
        if not handle:
            return {"outcome": "error", "data": {"reason": "no active session"}}
        if capability not in handle.policy_caps:
            self._emit(node_id, "nodebox.command", {"capability": capability,
                                                    "outcome": "denied",
                                                    "reason": "controller_policy"})
            return {"outcome": "denied", "data": {"reason": "controller_policy"}}
        # Response gate: nothing is dispatched without a signed allow.
        decision_id: str | None = None
        if self.gate is not None:
            allow, reason, decision_id = self._gate_decision(node_id, capability, evidence_ref)
            if not allow:
                self._emit(node_id, "nodebox.command", {"capability": capability,
                                                        "outcome": "denied",
                                                        "reason": "authz_gate",
                                                        "gate_reason": reason,
                                                        "decision_id": decision_id})
                return {"outcome": "denied",
                        "data": {"reason": "authz_gate", "gate_reason": reason,
                                 "decision_id": decision_id}}
        cid = uuid.uuid4().hex
        ev = threading.Event()
        with self._lock:
            self._pending[cid] = {"event": ev, "result": None}
        with handle.lock:
            handle.session.send({"type": "COMMAND", "command_id": cid,
                                 "capability": capability, "params": params or {}})
        got = ev.wait(timeout)
        with self._lock:
            p = self._pending.pop(cid, {})
        if not got:
            result = {"outcome": "timeout", "data": {"reason": "no result"}}
        else:
            result = p.get("result") or {"outcome": "error", "data": {"reason": "no result"}}
        # A gate-allowed dispatch always carries its audited decision_id back to
        # the caller, whatever the node-side outcome (ok/timeout/error).
        if decision_id is not None:
            result["decision_id"] = decision_id
        return result
