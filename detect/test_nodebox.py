#!/usr/bin/env python3
"""nodebox tests: trust-stack scope, mutual auth, capability gating, replay,
clone detection, and the SSH broker's refusals."""
from __future__ import annotations

import json
import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

import nodebox_crypto as nc
import nodebox_layers as layers
from authz_gate import AuthzGate, verify_audit_chain
from nodebox_agent import NodeAgent
from nodebox_broker import BrokerError, build_ssh_argv, reject_arbitrary, resolve_node, resolve_task
from nodebox_collector import normalize_ecs, to_ecs, write_ecs
from nodebox_controller import Controller, enroll
from nodebox_identity import IdentityStore
from nodebox_telemetry import envelope, flatten

# Capabilities the sample gate policy (nodebox_authz_policy.yml) grants; mutating
# actions are time-boxed and RESTART_SERVICE is deliberately absent (deny by default).
_GATE_GRANTS = [
    {"action": a, "targets": ["node:*"]}
    for a in ("PING", "INFO", "STATUS", "FETCH_LOGS", "CAPTURE_TELEMETRY", "DISCONNECT")
] + [
    {"action": "SYNC_CONFIG", "targets": ["node:*"], "not_after": "2026-12-31T23:59:59Z"},
    {"action": "UPDATE_RULESET", "targets": ["node:*"], "not_after": "2026-12-31T23:59:59Z"},
]


def make_gate(tmp: Path, key: bytes) -> AuthzGate:
    """A response gate mirroring nodebox_authz_policy.yml, with per-test stores."""
    policy = {
        "schema": "detect.authz.policy/v1",
        "max_request_age_seconds": 120,
        "clock_skew_seconds": 30,
        "callers": {"nodebox-controller": {"key_hex": key.hex(), "grants": _GATE_GRANTS}},
    }
    return AuthzGate.from_policy(policy, audit_path=tmp / "gate_audit.jsonl",
                                nonce_path=tmp / "gate_nonces.log")


def free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def make_agent(tmp: Path, ctrl, controller_id, addr, name, caps, anchors, policy_caps=None):
    state = tmp / f"node-{name}"
    agent = NodeAgent(state, "test", set(caps), addr, ctrl.pub_raw, controller_id,
                      tmp / "telemetry.jsonl", anchors=anchors, telemetry_interval=0.2)
    agent.load_identity()
    return agent


def start_controller(tmp: Path, inv, ctrl, controller_id, **gate_kwargs):
    port = free_port()
    c = Controller(ctrl, controller_id, inv, tmp / "controller-telemetry.jsonl",
                   host="127.0.0.1", port=port, **gate_kwargs)
    threading.Thread(target=c.serve_forever, daemon=True).start()
    time.sleep(0.2)
    return c, ("127.0.0.1", port)


def wait_for_session(c, node_id: str, timeout: float = 8.0) -> None:
    """Block until the node has an authenticated session, or fail with a clear
    message. Replaces tight ~2s poll loops that flaked under thread/port
    contention (a not-yet-connected node made apply() return 'no active
    session', not the behavior under test)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if node_id in c.sessions:
            return
        time.sleep(0.05)
    raise AssertionError(f"node {node_id} did not establish a session within {timeout}s")


# --- trust stack -------------------------------------------------------------

def test_attestation_scope_depth_is_deepest_layer():
    assert layers.attestation_scope([])["depth"] == "PROCESS"
    assert layers.attestation_scope(["supervisor"])["depth"] == "GUEST_USERSPACE"
    assert layers.attestation_scope(["supervisor", "measured_boot"])["depth"] == "GUEST_KERNEL"
    assert layers.attestation_scope(["hardware_root"])["depth"] == "HARDWARE"
    scope = layers.attestation_scope([])
    assert "HYPERVISOR" in scope["not_attested"] and "HARDWARE" in scope["not_attested"]


def test_node_id_derived_from_key():
    a, b = nc.Identity.generate(), nc.Identity.generate()
    assert nc.node_id_for(a.pub_raw) == nc.node_id_for(a.pub_raw)
    assert nc.node_id_for(a.pub_raw) != nc.node_id_for(b.pub_raw)


# --- handshake + typed dispatch ---------------------------------------------

def test_authenticated_session_and_typed_commands(tmp_path):
    ctrl = nc.Identity.generate(); cid = "ctrl-" + ctrl.fingerprint[:12]
    inv = {"nodes": {}}
    agent = make_agent(tmp_path, ctrl, cid, ("127.0.0.1", 1), "a", ["PING", "STATUS"], ["supervisor"])
    enroll(inv, "a", nc.b64e(agent.identity.pub_raw), "router", ["PING", "STATUS"], agent.record.machine_binding)
    IdentityStore(agent.state_dir).mark_enrolled(); agent.record.enrolled = True
    c, addr = start_controller(tmp_path, inv, ctrl, cid)
    agent.controller_addr = addr
    threading.Thread(target=agent.run, daemon=True).start()
    wait_for_session(c, agent.identity.node_id)
    assert agent.identity.node_id in c.sessions
    assert c.apply(agent.identity.node_id, "PING")["outcome"] == "ok"
    assert c.apply(agent.identity.node_id, "STATUS")["outcome"] == "ok"
    c.stop()


def test_controller_policy_denies_ungranted_capability(tmp_path):
    ctrl = nc.Identity.generate(); cid = "ctrl-" + ctrl.fingerprint[:12]
    inv = {"nodes": {}}
    agent = make_agent(tmp_path, ctrl, cid, ("127.0.0.1", 1), "a", ["PING", "SYNC_CONFIG"], ["supervisor"])
    enroll(inv, "a", nc.b64e(agent.identity.pub_raw), "router", ["PING"], agent.record.machine_binding)
    IdentityStore(agent.state_dir).mark_enrolled(); agent.record.enrolled = True
    c, addr = start_controller(tmp_path, inv, ctrl, cid)
    agent.controller_addr = addr
    threading.Thread(target=agent.run, daemon=True).start()
    wait_for_session(c, agent.identity.node_id)
    r = c.apply(agent.identity.node_id, "SYNC_CONFIG", {"config": {}})
    assert r["outcome"] == "denied"
    c.stop()


def test_node_local_denial_when_policy_grants_but_node_does_not(tmp_path):
    ctrl = nc.Identity.generate(); cid = "ctrl-" + ctrl.fingerprint[:12]
    inv = {"nodes": {}}
    # node local allowlist lacks SYNC_CONFIG, but inventory policy grants it
    agent = make_agent(tmp_path, ctrl, cid, ("127.0.0.1", 1), "a", ["PING"], ["supervisor"])
    enroll(inv, "a", nc.b64e(agent.identity.pub_raw), "router", ["PING", "SYNC_CONFIG"], agent.record.machine_binding)
    IdentityStore(agent.state_dir).mark_enrolled(); agent.record.enrolled = True
    c, addr = start_controller(tmp_path, inv, ctrl, cid)
    agent.controller_addr = addr
    threading.Thread(target=agent.run, daemon=True).start()
    wait_for_session(c, agent.identity.node_id)
    r = c.apply(agent.identity.node_id, "SYNC_CONFIG", {"config": {}})
    deadline = time.time() + 8.0
    while r["outcome"] != "denied" and time.time() < deadline:
        time.sleep(0.1)
        r = c.apply(agent.identity.node_id, "SYNC_CONFIG", {"config": {}})
    assert r["outcome"] == "denied"
    assert r["data"]["reason"] == "not_authorized"
    c.stop()


# --- unknown controller ------------------------------------------------------

def test_unknown_controller_is_rejected_before_session(tmp_path):
    real = nc.Identity.generate(); cid = "ctrl-" + real.fingerprint[:12]
    evil = nc.Identity.generate()
    inv = {"nodes": {}}
    agent = make_agent(tmp_path, real, cid, ("127.0.0.1", 1), "v", ["PING"], ["supervisor"])
    enroll(inv, "v", nc.b64e(agent.identity.pub_raw), "sensor", ["PING"], agent.record.machine_binding)
    IdentityStore(agent.state_dir).mark_enrolled(); agent.record.enrolled = True
    # evil controller runs on its own port; node pins the REAL controller key
    evil_port = free_port()
    evil_c = Controller(evil, "ctrl-evil", inv, tmp_path / "evil.jsonl",
                        host="127.0.0.1", port=evil_port)
    threading.Thread(target=evil_c.serve_forever, daemon=True).start()
    time.sleep(0.2)
    agent.controller_addr = ("127.0.0.1", evil_port)
    rc = agent.run()                       # returns 4 on auth rejection
    assert rc == 4
    tele = (tmp_path / "telemetry.jsonl").read_text()
    assert "AUTH_REJECTED" in tele and "unknown controller" in tele
    evil_c.stop()


# --- replay protection -------------------------------------------------------

def test_secure_channel_rejects_replayed_frame():
    key = b"0" * 32
    a, b = socket.socketpair()
    tx = nc.SecureChannel(a, key, b"transcript", is_server=False)
    tx.send({"n": 1})
    frame = b.recv(65535)          # capture the framed ciphertext
    c, d = socket.socketpair()
    rx = nc.SecureChannel(d, key, b"transcript", is_server=True)
    c.sendall(frame)
    assert rx.recv() == {"n": 1}
    c.sendall(frame)               # replay the SAME frame -> counter already advanced
    with pytest.raises(nc.ProtocolError):
        rx.recv()
    for s in (a, b, c, d):
        s.close()


# --- clone detection ---------------------------------------------------------

def test_cloned_identity_is_flagged(tmp_path):
    ctrl = nc.Identity.generate(); cid = "ctrl-" + ctrl.fingerprint[:12]
    inv = {"nodes": {}}
    agent = make_agent(tmp_path, ctrl, cid, ("127.0.0.1", 1), "tv", ["PING"], ["supervisor"])
    enroll(inv, "tv", nc.b64e(agent.identity.pub_raw), "tv", ["PING"], agent.record.machine_binding)
    IdentityStore(agent.state_dir).mark_enrolled(); agent.record.enrolled = True
    c, addr = start_controller(tmp_path, inv, ctrl, cid)
    agent.controller_addr = addr
    threading.Thread(target=agent.run, daemon=True).start()
    wait_for_session(c, agent.identity.node_id)
    # second instance loading the SAME identity dir -> same node_id, new boot_id
    clone = NodeAgent(agent.state_dir, "tv", {"PING"}, addr, ctrl.pub_raw, cid,
                      tmp_path / "clone-telemetry.jsonl", anchors=["supervisor"], telemetry_interval=0.2)
    clone.load_identity()
    threading.Thread(target=clone.run, daemon=True).start()
    deadline = time.time() + 8.0
    while time.time() < deadline:
        if "CLONE_SUSPECTED" in (tmp_path / "controller-telemetry.jsonl").read_text():
            break
        time.sleep(0.05)
    c.stop()
    tele = (tmp_path / "controller-telemetry.jsonl").read_text()
    assert "CLONE_SUSPECTED" in tele


# --- response gate (authz_gate wiring) ---------------------------------------

def test_gate_requires_caller_and_key():
    """A Controller given a gate but no caller/key must refuse to construct
    (it could not sign a request, so it would fail open)."""
    ctrl = nc.Identity.generate()
    with pytest.raises(ValueError):
        Controller(ctrl, "ctrl", {"nodes": {}}, "t.jsonl", gate=object())


def test_gate_decision_is_deny_by_default_and_audited(tmp_path):
    key = b"k" * 32
    gate = make_gate(tmp_path, key)
    ctrl = nc.Identity.generate()
    c = Controller(ctrl, "ctrl", {"nodes": {}}, tmp_path / "tele.jsonl",
                   gate=gate, gate_caller="nodebox-controller", gate_key=key)
    allow, _reason, did_ok = c._gate_decision("node-x", "PING", evidence_ref="unit:1")
    assert allow and did_ok
    # RESTART_SERVICE has no grant -> denied even though it is a known capability
    denied, reason, did_deny = c._gate_decision("node-x", "RESTART_SERVICE", None)
    assert not denied and "RESTART_SERVICE" in reason and did_deny
    # every decision is written to the tamper-evident chain
    ok, n, bad = verify_audit_chain(tmp_path / "gate_audit.jsonl")
    assert ok and n == 2 and bad is None
    # the returned decision_id IS the audit record's chain hash, in order: the
    # allow first, the deny second. This ties the controller's result to the log.
    records = [json.loads(ln) for ln in (tmp_path / "gate_audit.jsonl").read_text().splitlines() if ln.strip()]
    assert [r["decision"] for r in records] == ["allow", "deny"]
    assert records[0]["record_hash"] == did_ok
    assert records[1]["record_hash"] == did_deny


def test_gate_uses_a_fresh_nonce_per_dispatch(tmp_path):
    """Each dispatch signs a distinct nonce, so two identical apply() calls both
    succeed with distinct decision_ids (they are not accidental replays)."""
    key = b"k" * 32
    gate = make_gate(tmp_path, key)
    ctrl = nc.Identity.generate()
    c = Controller(ctrl, "ctrl", {"nodes": {}}, tmp_path / "tele.jsonl",
                   gate=gate, gate_caller="nodebox-controller", gate_key=key)
    a1, _, d1 = c._gate_decision("node-x", "PING", None)
    a2, _, d2 = c._gate_decision("node-x", "PING", None)
    assert a1 and a2 and d1 != d2   # fresh nonce each time -> both allow, distinct ids


def test_gate_rejects_a_replayed_request(tmp_path):
    """The gate is single-use per nonce: resubmitting the SAME signed request is
    refused as a replay, so a captured dispatch request cannot be reused."""
    key = b"k" * 32
    gate = make_gate(tmp_path, key)
    req = {
        "caller": "nodebox-controller", "action": "PING", "target": "node:node-x",
        "nonce": "fixed-nonce-123", "issued_at": datetime.now(timezone.utc).isoformat(),
    }
    req["sig"] = AuthzGate.sign(req, key)
    first = gate.authorize(req)
    second = gate.authorize(req)     # byte-for-byte identical resubmission
    assert first.allow is True
    assert second.allow is False and "replay" in second.reason


def test_apply_routes_through_gate_end_to_end(tmp_path):
    key = b"k" * 32
    gate = make_gate(tmp_path, key)
    ctrl = nc.Identity.generate(); cid = "ctrl-" + ctrl.fingerprint[:12]
    inv = {"nodes": {}}
    # node is enrolled WITH RESTART_SERVICE so the inventory check passes; the
    # gate is then the boundary that blocks it (deny by default).
    agent = make_agent(tmp_path, ctrl, cid, ("127.0.0.1", 1), "a",
                       ["PING", "RESTART_SERVICE"], ["supervisor"])
    enroll(inv, "a", nc.b64e(agent.identity.pub_raw), "router",
           ["PING", "RESTART_SERVICE"], agent.record.machine_binding)
    IdentityStore(agent.state_dir).mark_enrolled(); agent.record.enrolled = True
    c, addr = start_controller(tmp_path, inv, ctrl, cid,
                               gate=gate, gate_caller="nodebox-controller", gate_key=key)
    agent.controller_addr = addr
    threading.Thread(target=agent.run, daemon=True).start()
    wait_for_session(c, agent.identity.node_id)
    assert agent.identity.node_id in c.sessions
    # granted capability -> allowed, and the decision_id is attached to the result
    ok = c.apply(agent.identity.node_id, "PING", evidence_ref="nodebox:seq1")
    assert ok["outcome"] == "ok" and ok.get("decision_id")
    # ungranted-at-the-gate capability -> denied before any COMMAND is sent
    denied = c.apply(agent.identity.node_id, "RESTART_SERVICE")
    assert denied["outcome"] == "denied"
    assert denied["data"]["reason"] == "authz_gate" and denied["data"].get("decision_id")
    time.sleep(0.3)   # let any (erroneously) dispatched command land in node telemetry
    c.stop()
    # the denial is observable telemetry (same shape the collector rule keys on)
    tele = (tmp_path / "controller-telemetry.jsonl").read_text()
    assert '"outcome":"denied"' in tele and '"reason":"authz_gate"' in tele
    # and it was denied BEFORE dispatch: the node never *handled* a
    # RESTART_SERVICE command. (The capability name appears in the node's own
    # services allowlist telemetry, so check handled commands precisely, not a
    # substring.)
    handled = [json.loads(ln) for ln in (tmp_path / "telemetry.jsonl").read_text().splitlines()
               if ln.strip() and '"event_type":"nodebox.command"' in ln]
    assert all(e["data"].get("capability") != "RESTART_SERVICE" for e in handled)
    assert agent.counters["commands"] == 1   # only the earlier PING reached the node


# --- SSH broker --------------------------------------------------------------

def _inv():
    return {
        "revision": "git:test",
        "telemetry_path": "/tmp/nodebox-test-telemetry.jsonl",
        "nodes": {
            "node-abc": {
                "alias": "router", "device_type": "router",
                "address": "192.168.8.1", "user": "admin",
                "host_key_alias": "router", "allowed_capabilities": ["PING"],
                "tasks": {"collect-health": {"remote_command": ["/usr/local/lib/nodebox/collect-health"],
                                             "timeout_seconds": 30, "tty": False,
                                             "allowed_exit_codes": [0]}},
            }
        },
    }


def test_broker_refuses_unknown_node_and_task_and_arbitrary():
    inv = _inv()
    with pytest.raises(BrokerError):
        resolve_node(inv, "unknown-host")
    node = resolve_node(inv, "router")
    with pytest.raises(BrokerError):
        resolve_task(inv, node, "not-a-task")
    with pytest.raises(BrokerError):
        reject_arbitrary("rm -rf /")


def test_broker_builds_hardened_argv_with_only_allowlisted_command():
    inv = _inv()
    node = resolve_node(inv, "router")
    argv = build_ssh_argv(node, resolve_task(inv, node, "collect-health"))
    joined = " ".join(argv)
    assert "StrictHostKeyChecking=yes" in joined
    assert "GlobalKnownHostsFile=/dev/null" in joined
    assert "ForwardAgent=no" in joined
    assert "ClearAllForwardings=yes" in joined
    assert "ControlPersist=5m" in joined
    assert argv[-1] == "/usr/local/lib/nodebox/collect-health"


def test_broker_omits_port_when_absent_and_adds_when_present():
    inv = _inv()
    node = resolve_node(inv, "router")   # _inv() router has no explicit port
    assert "-p" not in build_ssh_argv(node, ["true"])
    node["port"] = 2222
    argv = build_ssh_argv(node, ["true"])
    assert argv[argv.index("-p") + 1] == "2222"


def test_broker_port_is_int_coerced_and_malformed_is_broker_error():
    inv = _inv()
    node = resolve_node(inv, "router")
    node["port"] = "2222"                       # numeric string -> coerced
    assert build_ssh_argv(node, ["true"])[build_ssh_argv(node, ["true"]).index("-p") + 1] == "2222"
    node["port"] = "22; rm -rf /"               # non-numeric -> BrokerError, not ValueError
    with pytest.raises(BrokerError):
        build_ssh_argv(node, ["true"])


def test_broker_rejects_option_injection_in_user_and_address():
    """A user/address that begins with '-' would be parsed by ssh as an option
    (e.g. -oProxyCommand=...); the broker refuses it."""
    inv = _inv()
    node = resolve_node(inv, "router")
    node["user"] = "-oProxyCommand=touch /tmp/pwn"
    with pytest.raises(BrokerError):
        build_ssh_argv(node, ["true"])
    node = resolve_node(_inv(), "router")
    node["address"] = "-oProxyCommand=evil"
    with pytest.raises(BrokerError):
        build_ssh_argv(node, ["true"])


# --- sample inventory.json (documented CLI + supervisor target) --------------

def _sample_inventory() -> dict:
    import json
    return json.loads((Path(__file__).resolve().parent / "inventory.json").read_text())


def test_sample_inventory_gateway_task_builds_hardened_argv():
    inv = _sample_inventory()
    node = resolve_node(inv, "gateway")
    argv = build_ssh_argv(node, resolve_task(inv, node, "collect-health"))
    joined = " ".join(argv)
    assert "StrictHostKeyChecking=yes" in joined and "ForwardAgent=no" in joined
    assert argv[argv.index("-p") + 1] == "2222"        # gateway sshd on 2222
    assert argv[-2:] == ["/usr/local/lib/nodebox/collect-health", "--json"]


def test_sample_inventory_router_refused_no_sshd():
    inv = _sample_inventory()
    for selector in ("b628", "router"):               # key and alias both refuse
        with pytest.raises(BrokerError) as ei:
            resolve_node(inv, selector)
        assert "does not run sshd" in str(ei.value)


def test_cli_ssh_task_dry_run_prints_argv(capsys):
    import nodebox_cli
    inv = str(Path(__file__).resolve().parent / "inventory.json")
    rc = nodebox_cli.main(["ssh", "task", "--inventory", inv,
                           "--node", "gateway", "--task", "collect-health", "--dry-run"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "StrictHostKeyChecking=yes" in out and "collect-health" in out


def test_cli_ssh_task_router_refused(capsys):
    import nodebox_cli
    inv = str(Path(__file__).resolve().parent / "inventory.json")
    rc = nodebox_cli.main(["ssh", "task", "--inventory", inv,
                           "--node", "router", "--task", "collect-health", "--dry-run"])
    assert rc == 2
    assert "does not run sshd" in capsys.readouterr().err


# --- telemetry normalization -------------------------------------------------

def test_flatten_promotes_data_and_provenance():
    env = {"schema": "nodebox.event/v1", "node_id": "n1", "device_type": "router",
           "ts": 1, "event_type": "nodebox.command",
           "data": {"capability": "PING", "outcome": "ok"},
           "provenance": {"attestation_depth": "PROCESS"}}
    f = flatten(env)
    assert f["data.capability"] == "PING"
    assert f["provenance.attestation_depth"] == "PROCESS"


# --- ECS normalization -------------------------------------------------------

def test_to_ecs_maps_core_fields():
    env = {"schema": "nodebox.event/v1", "node_id": "node-abc", "device_type": "router",
           "ts": 1_700_000_000, "event_type": "nodebox.command",
           "data": {"capability": "RESTART_SERVICE", "outcome": "denied",
                    "reason": "authz_gate", "gate_reason": "not permitted"},
           "provenance": {"attestation_depth": "PROCESS", "boot_id": "b1"}}
    doc = to_ecs(env)
    assert doc["@timestamp"] == "2023-11-14T22:13:20+00:00"   # epoch -> ISO UTC
    assert doc["event"]["action"] == "nodebox.command"
    assert doc["event"]["outcome"] == "failure"               # denied -> failure
    assert doc["event"]["type"] == ["denied"]
    assert doc["event"]["category"] == ["process"]
    assert doc["host"] == {"id": "node-abc", "type": "router"}
    assert doc["agent"] == {"type": "nodebox", "id": "node-abc"}
    assert doc["labels"]["provenance.attestation_depth"] == "PROCESS"
    assert doc["error"]["message"] == "authz_gate"
    # lossless: the original envelope is preserved under `nodebox`
    assert doc["nodebox"]["data"]["capability"] == "RESTART_SERVICE"


def test_to_ecs_clone_is_alert():
    env = envelope("node-x", "tv", "nodebox.clone", {"transition": "CLONE_SUSPECTED"})
    doc = to_ecs(env)
    assert doc["event"]["kind"] == "alert"
    assert "intrusion_detection" in doc["event"]["category"]


def test_to_ecs_labels_stringifies_nested_provenance():
    env = envelope("n", "t", "nodebox.session", {"transition": "AUTHENTICATED"},
                   provenance={"supervisor": {"kind": "systemd", "unit": "u"}})
    doc = to_ecs(env)
    # ECS labels values must be strings; a nested value is rendered as JSON
    assert doc["labels"]["provenance.supervisor"] == '{"kind":"systemd","unit":"u"}'
    assert doc["event"]["type"] == ["start"]


def test_to_ecs_outcome_and_type_branches():
    ok = to_ecs(envelope("n", "t", "nodebox.command", {"outcome": "ok"}))
    assert ok["event"]["outcome"] == "success" and ok["event"]["type"] == ["allowed"]
    err = to_ecs(envelope("n", "t", "nodebox.command", {"outcome": "error", "reason": "boom"}))
    assert err["event"]["outcome"] == "failure" and err["event"]["type"] == ["error"]
    assert err["error"]["message"] == "boom"
    to = to_ecs(envelope("n", "t", "nodebox.command", {"outcome": "timeout"}))
    assert to["event"]["outcome"] == "failure" and to["event"]["type"] == ["error"]
    # an event with no outcome carries no event.outcome and defaults type to info
    plain = to_ecs(envelope("n", "t", "nodebox.health", {"uptime_s": 1}))
    assert "outcome" not in plain["event"] and plain["event"]["type"] == ["info"]
    assert plain["event"]["category"] == ["host"]


def test_ecs_timestamp_string_passthrough_and_missing_fallback():
    # a string ts is passed through unchanged
    d1 = to_ecs({"node_id": "n", "event_type": "nodebox.health", "ts": "2026-01-02T03:04:05+00:00",
                 "data": {}})
    assert d1["@timestamp"] == "2026-01-02T03:04:05+00:00"
    # an absent/None ts falls back to the Unix epoch rather than raising
    d2 = to_ecs({"node_id": "n", "event_type": "nodebox.health", "data": {}})
    assert d2["@timestamp"].startswith("1970-01-01T00:00:00")
    # a corrupt but well-formed out-of-range numeric ts must not crash the export
    d3 = to_ecs({"node_id": "n", "event_type": "nodebox.health", "ts": 10 ** 30, "data": {}})
    assert d3["@timestamp"].startswith("1970-01-01T00:00:00")


def test_normalize_and_write_ecs_roundtrip_and_skips_malformed(tmp_path):
    src = tmp_path / "telemetry.jsonl"
    events = [
        envelope("n1", "router", "nodebox.command", {"capability": "PING", "outcome": "ok"}),
        envelope("n2", "tv", "nodebox.clone", {"transition": "CLONE_SUSPECTED"}),
    ]
    # include a corrupt line: normalize/write must skip it, not crash
    src.write_text("\n".join(json.dumps(e) for e in events) + "\n{ this is not json\n")
    docs = normalize_ecs(src)
    assert len(docs) == 2 and all(d["ecs"]["version"] for d in docs)
    out = tmp_path / "sub" / "ecs.ndjson"        # nested dir -> exercises mkdir
    n = write_ecs(src, out)
    assert n == 2 and out.exists()
    lines = [json.loads(ln) for ln in out.read_text().splitlines() if ln.strip()]
    assert len(lines) == 2
    assert lines[0]["event"]["outcome"] == "success"
    assert lines[1]["event"]["kind"] == "alert"


def test_cli_collect_writes_ecs(tmp_path, capsys):
    import nodebox_cli
    tele = tmp_path / "telemetry.jsonl"
    tele.write_text(json.dumps(envelope("n1", "router", "nodebox.command",
                                        {"capability": "PING", "outcome": "ok"})) + "\n")
    rules_dir = str(Path(__file__).resolve().parent / "rules")
    out = tmp_path / "ecs.ndjson"
    rc = nodebox_cli.main(["collect", str(tele), rules_dir, "--ecs", str(out)])
    assert rc == 0 and out.exists()
    assert "wrote 1 ECS documents" in capsys.readouterr().out
    assert json.loads(out.read_text().splitlines()[0])["event"]["action"] == "nodebox.command"
