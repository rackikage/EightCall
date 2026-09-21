#!/usr/bin/env python3
"""Runner-side client: build, sign, and submit a request to the remote gate.

This is what runs on a guest VM. It signs with the guest's Ed25519 PRIVATE key
(which never leaves the guest) and consumes the narrow contract: it treats a
non-200 response as a hard deny and refuses to execute. A detection can decide
*to ask*; only the gate's allow authorizes.

    from authz_client import build_request, submit
    req = build_request(caller="responder-vm-01", action="quarantine_process",
                        target="host:test-sim-09", private_key_b64=KEY,
                        evidence_ref="ios_shell_abuse:seq3")
    decision = submit("http://10.0.0.5:8787", req)   # raises on deny
    # ... execute, quoting decision["decision_id"] ...
"""
from __future__ import annotations

import base64
import json
import secrets
import urllib.error
import urllib.request
from datetime import datetime, timezone

from authz_gate import ed25519_sign


class RemoteDenied(Exception):
    def __init__(self, reason: str, decision_id: str | None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.decision_id = decision_id


def build_request(
    *,
    caller: str,
    action: str,
    target: str,
    private_key_b64: str,
    params: dict | None = None,
    evidence_ref: str | None = None,
    nonce: str | None = None,
    issued_at: str | None = None,
) -> dict:
    """Assemble and Ed25519-sign a request. `params`/`evidence_ref` are
    included only when given, matching the gate's closed schema."""
    req: dict = {
        "caller": caller,
        "action": action,
        "target": target,
        "nonce": nonce or secrets.token_hex(16),
        "issued_at": issued_at or datetime.now(timezone.utc).isoformat(),
    }
    if params:
        req["params"] = params
    if evidence_ref is not None:
        req["evidence_ref"] = evidence_ref
    priv = base64.b64decode(private_key_b64, validate=True)
    req["sig"] = ed25519_sign(req, priv)
    return req


def submit(base_url: str, request: dict, *, timeout: float = 5.0) -> dict:
    """POST to <base_url>/authorize. Returns the decision dict on allow;
    raises RemoteDenied on any deny or transport failure (fail closed)."""
    url = base_url.rstrip("/") + "/authorize"
    data = json.dumps(request).encode("utf-8")
    http_req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(http_req, timeout=timeout) as resp:
            payload = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read())
        except (ValueError, OSError):
            raise RemoteDenied(f"gate returned HTTP {exc.code}", None) from exc
        raise RemoteDenied(payload.get("reason", f"HTTP {exc.code}"), payload.get("decision_id")) from exc
    except (urllib.error.URLError, OSError) as exc:
        # Cannot reach the gate -> fail closed, never execute.
        raise RemoteDenied(f"gate unreachable: {exc}", None) from exc
    if not payload.get("allow"):
        raise RemoteDenied(payload.get("reason", "denied"), payload.get("decision_id"))
    return payload
