#!/usr/bin/env python3
"""Tests for the authorization gate. Runs under pytest, or standalone:
    ./venv69/bin/python3 test_authz_gate.py

Every test drives the public contract (`authorize`) and asserts on the
Decision plus the audit side effects. The clock is injected so expiry and
staleness are exercised deterministically.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from authz_gate import AuthzGate, verify_audit_chain

KEY_HEX = "aa" * 32
FIXED_NOW = datetime(2026, 9, 17, 12, 0, 0, tzinfo=timezone.utc)


def build_gate(tmp: Path, now: datetime = FIXED_NOW, grants=None) -> AuthzGate:
    if grants is None:
        grants = [
            {
                "action": "run_osascript",
                "targets": ["host:test-sim-01"],
                "params": {"script": "notify_soc"},
                "not_after": "2026-12-31T23:59:59Z",
            },
            {
                "action": "quarantine_process",
                "targets": ["host:test-sim-*"],
                "not_after": "2026-12-31T23:59:59Z",
            },
        ]
    policy = {
        "schema": "detect.authz.policy/v1",
        "max_request_age_seconds": 120,
        "clock_skew_seconds": 30,
        "callers": {"responder": {"key_hex": KEY_HEX, "grants": grants}},
    }
    return AuthzGate.from_policy(
        policy,
        audit_path=tmp / "audit.jsonl",
        nonce_path=tmp / "nonces.log",
        now_fn=lambda: now,
    )


def make_request(nonce="n1", issued=FIXED_NOW, sign=True, key=None, **overrides) -> dict:
    req = {
        "caller": "responder",
        "action": "quarantine_process",
        "target": "host:test-sim-01",
        "nonce": nonce,
        "issued_at": issued.isoformat(),
    }
    req.update(overrides)
    if sign:
        req["sig"] = AuthzGate.sign(req, bytes.fromhex(key or KEY_HEX))
    else:
        req["sig"] = "deadbeef"
    return req


# --- allow paths -----------------------------------------------------------

def test_allow_returns_decision_id_matching_audit(tmp_path):
    gate = build_gate(tmp_path)
    d = gate.authorize(make_request())
    assert d.allow and d.reason.startswith("granted")
    last = json.loads((tmp_path / "audit.jsonl").read_text().splitlines()[-1])
    assert last["decision"] == "allow"
    assert last["record_hash"] == d.decision_id  # decision_id IS the audit hash


def test_allow_osascript_with_pinned_param(tmp_path):
    gate = build_gate(tmp_path)
    d = gate.authorize(
        make_request(action="run_osascript", params={"script": "notify_soc"})
    )
    assert d.allow


# --- deny by default -------------------------------------------------------

def test_unknown_caller_denied(tmp_path):
    gate = build_gate(tmp_path)
    d = gate.authorize(make_request(caller="ghost"))
    assert not d.allow and "unknown caller" in d.reason


def test_action_not_granted_denied(tmp_path):
    gate = build_gate(tmp_path)
    d = gate.authorize(make_request(action="wipe_disk"))
    assert not d.allow and "not permitted" in d.reason


def test_target_out_of_scope_denied(tmp_path):
    gate = build_gate(tmp_path)
    d = gate.authorize(make_request(target="host:prod-db-07"))
    assert not d.allow and "out of scope" in d.reason


def test_osascript_wrong_script_denied(tmp_path):
    gate = build_gate(tmp_path)
    d = gate.authorize(
        make_request(action="run_osascript", params={"script": "unlisted_script"})
    )
    assert not d.allow and "param" in d.reason


def test_osascript_extra_param_denied(tmp_path):
    gate = build_gate(tmp_path)
    d = gate.authorize(
        make_request(
            action="run_osascript",
            params={"script": "notify_soc", "arg": "; rm -rf /"},
        )
    )
    assert not d.allow and "not allowed" in d.reason


# --- identity / integrity --------------------------------------------------

def test_bad_signature_denied(tmp_path):
    gate = build_gate(tmp_path)
    d = gate.authorize(make_request(sign=False))
    assert not d.allow and "bad signature" in d.reason


def test_tampered_target_denied(tmp_path):
    gate = build_gate(tmp_path)
    req = make_request()
    req["target"] = "host:prod-db-07"  # change after signing
    d = gate.authorize(req)
    assert not d.allow and "bad signature" in d.reason


# --- content cannot authorize ---------------------------------------------

def test_smuggled_verdict_field_rejected(tmp_path):
    gate = build_gate(tmp_path)
    req = make_request()
    req["authorized"] = True  # try to assert own authority
    d = gate.authorize(req)
    assert not d.allow and "unexpected field" in d.reason


# --- malformed input must DENY, never raise --------------------------------

def test_non_string_caller_denied_not_raised(tmp_path):
    gate = build_gate(tmp_path)
    d = gate.authorize(make_request(caller=["responder"]))  # unhashable type
    assert not d.allow and "malformed" in d.reason


def test_non_string_action_denied_not_raised(tmp_path):
    gate = build_gate(tmp_path)
    d = gate.authorize(make_request(action=7))
    assert not d.allow and "malformed" in d.reason


def test_signed_non_string_target_denied_not_raised(tmp_path):
    gate = build_gate(tmp_path)
    d = gate.authorize(make_request(nonce="typed", target=123))  # validly signed
    assert not d.allow and "malformed" in d.reason
    # a malformed request is denied before nonce consumption: the same nonce
    # on a well-formed request must still work (malformed traffic burns nothing)
    assert gate.authorize(make_request(nonce="typed")).allow


# --- expiry / staleness ----------------------------------------------------

def test_stale_request_denied(tmp_path):
    gate = build_gate(tmp_path, now=FIXED_NOW + timedelta(seconds=200))
    d = gate.authorize(make_request(issued=FIXED_NOW))
    assert not d.allow and "stale" in d.reason


def test_future_request_denied(tmp_path):
    gate = build_gate(tmp_path)
    d = gate.authorize(make_request(issued=FIXED_NOW + timedelta(seconds=120)))
    assert not d.allow and "future" in d.reason


def test_expired_grant_denied(tmp_path):
    gate = build_gate(tmp_path, now=datetime(2027, 1, 2, tzinfo=timezone.utc))
    d = gate.authorize(
        make_request(issued=datetime(2027, 1, 2, tzinfo=timezone.utc))
    )
    assert not d.allow and "expired" in d.reason


# --- replay protection -----------------------------------------------------

def test_replay_same_nonce_denied(tmp_path):
    gate = build_gate(tmp_path)
    first = gate.authorize(make_request(nonce="once"))
    assert first.allow
    second = gate.authorize(make_request(nonce="once"))
    assert not second.allow and "replay" in second.reason


def test_nonce_consumed_across_restart(tmp_path):
    g1 = build_gate(tmp_path)
    assert g1.authorize(make_request(nonce="persist")).allow
    g2 = build_gate(tmp_path)  # fresh process, same store
    assert not g2.authorize(make_request(nonce="persist")).allow


# --- audit immutability ----------------------------------------------------

def test_audit_chain_verifies(tmp_path):
    gate = build_gate(tmp_path)
    gate.authorize(make_request(nonce="a"))
    gate.authorize(make_request(nonce="b", target="host:prod-db-07"))
    ok, n, bad = verify_audit_chain(tmp_path / "audit.jsonl")
    assert ok and n == 2 and bad is None


def test_audit_tamper_detected(tmp_path):
    gate = build_gate(tmp_path)
    gate.authorize(make_request(nonce="a"))
    gate.authorize(make_request(nonce="b"))
    path = tmp_path / "audit.jsonl"
    lines = path.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["decision"] = "allow"  # flip a denied record without rehashing
    rec["reason"] = "tampered"
    lines[0] = json.dumps(rec, sort_keys=True, ensure_ascii=False)
    path.write_text("\n".join(lines) + "\n")
    ok, _, bad = verify_audit_chain(path)
    assert not ok and bad is not None


def test_every_decision_writes_one_record(tmp_path):
    gate = build_gate(tmp_path)
    gate.authorize(make_request(nonce="a"))
    gate.authorize(make_request(nonce="b", caller="ghost"))
    gate.authorize(make_request(nonce="c", action="wipe_disk"))
    assert len((tmp_path / "audit.jsonl").read_text().splitlines()) == 3


def _run_standalone() -> int:
    import tempfile
    import traceback

    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in tests:
        with tempfile.TemporaryDirectory() as td:
            try:
                fn(Path(td))
                print(f"  PASS {fn.__name__}")
            except Exception:  # noqa: BLE001 - test runner reports any failure
                failed += 1
                print(f"  FAIL {fn.__name__}")
                traceback.print_exc()
    print(f"RESULT: {len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    import sys

    sys.exit(_run_standalone())
