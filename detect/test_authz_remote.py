#!/usr/bin/env python3
"""Tests for the pt2 remote gate: Ed25519 identity, fingerprint pinning, and
the HTTP transport. Runs under pytest, or standalone:
    ./venv69/bin/python3 test_authz_remote.py
"""
from __future__ import annotations

import base64
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

import authz_client
import authz_http
from authz_gate import AuthzGate, pubkey_fingerprint


def keypair() -> tuple[str, str, str]:
    """Returns (priv_b64, pub_b64, fingerprint_hex)."""
    priv = Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return (
        base64.b64encode(priv_raw).decode(),
        base64.b64encode(pub_raw).decode(),
        pubkey_fingerprint(pub_raw),
    )


def build_gate(tmp: Path, pub_b64: str, fp: str, *, pin: str | None = "match") -> AuthzGate:
    caller = {
        "alg": "ed25519",
        "pubkey_b64": pub_b64,
        "grants": [
            {
                "action": "quarantine_process",
                "targets": ["host:test-sim-*"],
                "not_after": "2026-12-31T23:59:59Z",
            }
        ],
    }
    if pin == "match":
        caller["key_sha256"] = fp
    elif pin == "wrong":
        caller["key_sha256"] = "00" * 32
    policy = {"schema": "detect.authz.policy/v1", "callers": {"responder-vm-01": caller}}
    return AuthzGate.from_policy(
        policy, audit_path=tmp / "audit.jsonl", nonce_path=tmp / "nonces.log"
    )


def req(priv_b64: str, **over) -> dict:
    kwargs = {
        "caller": "responder-vm-01",
        "action": "quarantine_process",
        "target": "host:test-sim-09",
        "private_key_b64": priv_b64,
    }
    kwargs.update(over)
    return authz_client.build_request(**kwargs)


# --- Ed25519 identity ------------------------------------------------------

def test_ed25519_allow(tmp_path):
    priv, pub, fp = keypair()
    gate = build_gate(tmp_path, pub, fp)
    d = gate.authorize(req(priv))
    assert d.allow and d.reason.startswith("granted")
    # the audit record carries the cryptographic identity, not just the label
    last = (tmp_path / "audit.jsonl").read_text().splitlines()[-1]
    assert fp in last


def test_ed25519_wrong_key_denied(tmp_path):
    _, pub, fp = keypair()
    other_priv, _, _ = keypair()  # signs with a key the policy doesn't pin
    gate = build_gate(tmp_path, pub, fp)
    d = gate.authorize(req(other_priv))
    assert not d.allow and "bad signature" in d.reason


def test_ed25519_tampered_after_signing_denied(tmp_path):
    priv, pub, fp = keypair()
    gate = build_gate(tmp_path, pub, fp)
    r = req(priv)
    r["target"] = "host:prod-01"  # change a signed field after signing
    d = gate.authorize(r)
    assert not d.allow and "bad signature" in d.reason


def test_fingerprint_pin_mismatch_denied(tmp_path):
    priv, pub, fp = keypair()
    gate = build_gate(tmp_path, pub, fp, pin="wrong")
    d = gate.authorize(req(priv))
    assert not d.allow and "fingerprint does not match" in d.reason


def test_ed25519_out_of_scope_denied(tmp_path):
    priv, pub, fp = keypair()
    gate = build_gate(tmp_path, pub, fp)
    d = gate.authorize(req(priv, target="host:prod-01"))
    assert not d.allow and "out of scope" in d.reason


def test_ed25519_replay_denied(tmp_path):
    priv, pub, fp = keypair()
    gate = build_gate(tmp_path, pub, fp)
    one = req(priv, nonce="fixed-nonce")
    assert gate.authorize(one).allow
    assert not gate.authorize(one).allow  # same signed request, replayed


# --- HTTP transport --------------------------------------------------------

def _serve(gate) -> tuple[ThreadingHTTPServer, str]:
    authz_http._Handler.gate = gate
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), authz_http._Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    host, port = httpd.server_address
    return httpd, f"http://{host}:{port}"


def test_http_allow_and_deny(tmp_path):
    priv, pub, fp = keypair()
    gate = build_gate(tmp_path, pub, fp)
    httpd, base = _serve(gate)
    try:
        ok = authz_client.submit(base, req(priv))
        assert ok["allow"] and ok["decision_id"]

        try:
            authz_client.submit(base, req(priv, target="host:prod-01"))
            assert False, "expected RemoteDenied"
        except authz_client.RemoteDenied as exc:
            assert "out of scope" in exc.reason
            assert exc.decision_id  # deny still returns an audited decision id
    finally:
        httpd.shutdown()


def test_http_healthz(tmp_path):
    import urllib.request

    _priv, pub, fp = keypair()
    gate = build_gate(tmp_path, pub, fp)
    httpd, base = _serve(gate)
    try:
        with urllib.request.urlopen(base + "/healthz", timeout=5) as resp:
            assert resp.status == 200
    finally:
        httpd.shutdown()


def test_http_malformed_body_is_400(tmp_path):
    import urllib.error
    import urllib.request

    _priv, pub, fp = keypair()
    gate = build_gate(tmp_path, pub, fp)
    httpd, base = _serve(gate)
    try:
        bad = urllib.request.Request(
            base + "/authorize", data=b"not json",
            headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(bad, timeout=5)
            assert False, "expected HTTP 400"
        except urllib.error.HTTPError as exc:
            assert exc.code == 400
    finally:
        httpd.shutdown()


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
