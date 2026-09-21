#!/usr/bin/env python3
"""nodebox end-to-end network demonstration (loopback, synthetic).

Stands up one controller and three node agents representing the classes of
device found on the live LAN (router, tv, phone, workstation), then exercises:

  1. authenticated sessions + policy sync,
  2. typed capability dispatch (PING/INFO/STATUS),
  3. a DENIED capability (mutating, not granted) -> telemetry,
  4. a node refusing an UNKNOWN CONTROLLER (pinned-key mismatch) -> telemetry,
  5. a CLONED identity (same node_id, second boot_id) -> telemetry,
  6. host-side collector + pySigma over all of it.

No real device is touched; nodes are in-process. Run:
    cd detect && ./venv69/bin/python3 nodebox_demo.py
"""
from __future__ import annotations

import os
import shutil
import socket
import threading
import time
from pathlib import Path

import nodebox_crypto as nc
from authz_gate import AuthzGate, verify_audit_chain
from nodebox_agent import NodeAgent
from nodebox_collector import report
from nodebox_controller import Controller, enroll, save_inventory
from nodebox_identity import IdentityStore

HERE = Path(__file__).resolve().parent
STATE = HERE / "nodebox_demo_state"
TELEMETRY = STATE / "nodebox_telemetry.jsonl"
INVENTORY = STATE / "inventory.json"


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def make_node(name: str, device_type: str, caps: list[str], anchors: list[str],
              controller_addr, controller_pub, controller_id) -> NodeAgent:
    return NodeAgent(
        state_dir=STATE / f"node-{name}",
        device_type=device_type,
        allowed_capabilities=set(caps),
        controller_addr=controller_addr,
        pinned_controller_pubkey=controller_pub,
        controller_id=controller_id,
        telemetry_path=TELEMETRY,
        anchors=anchors,
        telemetry_interval=0.4,
    )


def main() -> int:
    if STATE.exists():
        shutil.rmtree(STATE)
    STATE.mkdir(parents=True)

    # --- controller identity + inventory ---
    ctrl = nc.Identity.generate()
    controller_id = "ctrl-" + ctrl.fingerprint[:12]
    inv = {"controller_id": controller_id, "controller_pubkey": nc.b64e(ctrl.pub_raw), "nodes": {}}
    port = free_port()
    addr = ("127.0.0.1", port)

    # --- response gate: nothing is dispatched without a signed allow ---
    # Mirrors nodebox_authz_policy.yml. RESTART_SERVICE is deliberately NOT
    # granted, so the gate denies it by default even when a node's policy allows
    # it. A random per-run HMAC key keeps this self-contained.
    gate_key = os.urandom(32)
    gate_grants = [{"action": a, "targets": ["node:*"]}
                   for a in ("PING", "INFO", "STATUS", "FETCH_LOGS", "CAPTURE_TELEMETRY", "DISCONNECT")]
    gate_grants += [{"action": a, "targets": ["node:*"], "not_after": "2026-12-31T23:59:59Z"}
                    for a in ("SYNC_CONFIG", "UPDATE_RULESET")]
    gate = AuthzGate.from_policy(
        {"schema": "detect.authz.policy/v1",
         "callers": {"nodebox-controller": {"key_hex": gate_key.hex(), "grants": gate_grants}}},
        audit_path=STATE / "gate_audit.jsonl", nonce_path=STATE / "gate_nonces.log")

    controller = Controller(ctrl, controller_id, inv, TELEMETRY, host="127.0.0.1", port=port,
                            gate=gate, gate_caller="nodebox-controller", gate_key=gate_key)
    threading.Thread(target=controller.serve_forever, daemon=True).start()
    time.sleep(0.3)

    # --- three nodes, identity generated on first boot ---
    specs = [
        # router also allows RESTART_SERVICE locally, so the GATE (not the node)
        # is what blocks it below -- deny-by-default at the response boundary.
        ("router", "router", ["PING", "INFO", "STATUS", "SYNC_CONFIG", "FETCH_LOGS", "UPDATE_RULESET", "RESTART_SERVICE", "DISCONNECT"], ["supervisor"]),
        ("tv", "tv", ["PING", "INFO", "STATUS", "CAPTURE_TELEMETRY", "DISCONNECT"], ["supervisor"]),
        ("ws", "workstation", ["PING", "INFO", "STATUS", "UPDATE_RULESET", "DISCONNECT"], []),  # no supervisor -> PROCESS depth
    ]
    nodes = {}
    for name, dtype, caps, anchors in specs:
        agent = make_node(name, dtype, caps, anchors, addr, ctrl.pub_raw, controller_id)
        agent.load_identity()                      # first boot -> generate key
        # enroll out-of-band with the controller
        enroll(inv, name, nc.b64e(agent.identity.pub_raw), dtype, caps, agent.record.machine_binding)
        IdentityStore(agent.state_dir).mark_enrolled()
        agent.record.enrolled = True
        nodes[name] = agent
    save_inventory(INVENTORY, inv)

    # start agents
    threads = [threading.Thread(target=a.run, daemon=True) for a in nodes.values()]
    for t in threads:
        t.start()
    deadline = time.time() + 10.0
    while len(controller.sessions) < len(nodes) and time.time() < deadline:
        time.sleep(0.05)
    print(f"[demo] active sessions: {sorted(controller.sessions)}")

    # --- 2. typed dispatch ---
    for name, agent_obj in nodes.items():
        node_id = agent_obj.identity.node_id
        for cap in ("PING", "STATUS"):
            r = controller.apply(node_id, cap)
            print(f"[demo] {name:6} {cap:14} -> {r.get('outcome')}")

    # --- 3. denied capability (router policy allows SYNC_CONFIG; ask TV for it) ---
    tv_id = nodes["tv"].identity.node_id
    r = controller.apply(tv_id, "SYNC_CONFIG", {"config": {"x": 1}})
    print(f"[demo] tv     SYNC_CONFIG    -> {r.get('outcome')} {r.get('data')}")

    # --- 3a. GATE deny: router allows RESTART_SERVICE, but the response gate has
    #         no grant for it -> refused before any COMMAND is sent, with an
    #         audited decision_id. This is the "gate the response" boundary.
    router_id = nodes["router"].identity.node_id
    r = controller.apply(router_id, "RESTART_SERVICE", evidence_ref="nodebox_demo:restart")
    print(f"[demo] router RESTART_SERVICE-> {r.get('outcome')} (gate: {r.get('data', {}).get('gate_reason')})")

    # --- 3b. mutating action that SUCCEEDS on a node with NO supervisor anchor ---
    ws_id = nodes["ws"].identity.node_id
    ruleset = "title: demo\nlogsource: {product: nodebox}\ndetection:\n  sel:\n    event_type: x\n  condition: sel\nlevel: low\n"
    sig = nc.b64e(ctrl.sign(ruleset.encode()))
    r = controller.apply(ws_id, "UPDATE_RULESET", {"ruleset": ruleset, "sig": sig})
    print(f"[demo] ws     UPDATE_RULESET -> {r.get('outcome')} (no supervisor -> PROCESS depth)")

    # --- 4. unknown controller: a second controller with a different key ---
    evil = nc.Identity.generate()
    evil_port = free_port()
    evil_controller = Controller(evil, "ctrl-" + evil.fingerprint[:12], inv, STATE / "evil.jsonl",
                                 host="127.0.0.1", port=evil_port)
    threading.Thread(target=evil_controller.serve_forever, daemon=True).start()
    time.sleep(0.2)
    # point a fresh node at the EVIL controller but pin the REAL controller key
    victim = NodeAgent(
        state_dir=STATE / "node-victim", device_type="sensor",
        allowed_capabilities={"PING", "INFO", "STATUS", "DISCONNECT"},
        controller_addr=("127.0.0.1", evil_port),
        pinned_controller_pubkey=ctrl.pub_raw,     # pinned to the REAL controller
        controller_id=controller_id,
        telemetry_path=TELEMETRY, anchors=["supervisor"], telemetry_interval=0.4)
    victim.load_identity()
    enroll(inv, "victim", nc.b64e(victim.identity.pub_raw), "sensor",
           sorted(victim.allowed), victim.record.machine_binding)
    save_inventory(INVENTORY, inv)
    IdentityStore(victim.state_dir).mark_enrolled()
    victim.record.enrolled = True
    victim.run()                                   # expect AUTH_REJECTED
    print("[demo] victim node -> refused unknown controller (see telemetry)")

    # --- 5. cloned identity: same node_id, different boot_id on a 2nd connection ---
    clone = NodeAgent(
        state_dir=nodes["tv"].state_dir,           # SAME identity dir (cloned disk)
        device_type="tv",
        allowed_capabilities=nodes["tv"].allowed,
        controller_addr=addr,
        pinned_controller_pubkey=ctrl.pub_raw,
        controller_id=controller_id,
        telemetry_path=TELEMETRY, anchors=["supervisor"], telemetry_interval=0.4)
    clone.load_identity()                          # loads the SAME key + node_id
    clone_thread = threading.Thread(target=clone.run, daemon=True)
    clone_thread.start()
    print(f"[demo] cloned tv boot_id={clone.boot_id[:8]} vs live={nodes['tv'].boot_id[:8]}")

    deadline = time.time() + 10.0
    while time.time() < deadline:
        if "CLONE_SUSPECTED" in TELEMETRY.read_text():
            break
        time.sleep(0.05)
    controller.stop()
    evil_controller.stop()

    # --- 6. host-side collector + pySigma ---
    print()
    report(TELEMETRY, HERE / "rules")
    print()

    # --- 6a. the gate's own tamper-evident audit trail ---
    ok, n, bad = verify_audit_chain(STATE / "gate_audit.jsonl")
    print(f"== gate audit: {n} decisions -> {'OK' if ok else f'BROKEN at seq {bad}'} ==")
    print()

    print("== layer attestation scope (what each node honestly attests) ==")
    for name, agent_obj in nodes.items():
        a = agent_obj.attestation()
        print(f"  {name:6} depth={a['attestation_scope']['depth']:16} "
              f"not_attested={a['attestation_scope']['not_attested']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
