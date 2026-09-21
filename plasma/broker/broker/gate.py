"""broker.gate — the enforcement point.

authorize() is the only path that produces a lease + single-use action token.
Design invariants:
  1. deny by default             — authority comes only from the policy file
  2. authority never inferred    — closed request schema; no verdict smuggling
  3. identity proven, not claimed — Ed25519 over canonical bytes; the gate
                                    holds PUBLIC keys only
  4. every decision audited      — hash-chained; decision_id IS the chain hash
  5. gate at dispatch AND at use — token re-verified before the action runs
  6. keys separated by role      — callers sign requests; the gate alone signs
                                    execution tokens (executor holds only the
                                    gate's public key)
"""
from __future__ import annotations

import base64
import json
import os
import time
from typing import Any, Optional

from . import crypto, registry
from .canon import canonical, digest
from .store import Denied, Store

REQUEST_KEYS = {
    "caller",
    "action",
    "target_id",
    "params",
    "policy_digest",
    "enrollment_revision",
    "nonce",
    "issued_at",
    "expiry",
}
TOKEN_KEYS = {"caller", "target_id", "action", "params", "fencing", "decision_id", "policy_digest", "expiry"}
GATE_KEY_ID = "__gate__"
POLICY_ENVELOPE_KEYS = {"version", "body", "signer", "signature"}


def load_keys(path: str) -> dict[str, dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as handle:
        keys = json.load(handle)
    if not isinstance(keys, dict) or not keys:
        raise Denied("no_trusted_keys")
    for caller, entry in keys.items():
        if not isinstance(entry, dict) or not isinstance(entry.get("public"), str):
            raise Denied("malformed_trusted_keys", caller=caller)
        try:
            bytes.fromhex(entry["public"])
        except ValueError:
            raise Denied("malformed_trusted_keys", caller=caller)
    return keys


def _public_for(keys: dict, caller: str) -> Optional[str]:
    entry = keys.get(caller)
    if not entry or entry.get("status", "enabled") != "enabled":
        return None
    return entry.get("public")


def load_policy(path: str, keys: dict) -> tuple[dict, str, int]:
    """Verify the signed policy envelope and return (body, digest, version)."""
    with open(path, "r", encoding="utf-8") as handle:
        envelope = json.load(handle)
    if not isinstance(envelope, dict) or set(envelope) != POLICY_ENVELOPE_KEYS:
        raise Denied("malformed_policy_envelope")
    signer = envelope["signer"]
    public = _public_for(keys, signer)
    if not public:
        raise Denied("policy_signer_unknown")
    signed = canonical({"version": int(envelope["version"]), "body": envelope["body"]})
    try:
        good = crypto.verify_hex(public, signed, envelope["signature"])
    except crypto.CryptoError:
        raise Denied("crypto_unavailable")
    if not good:
        raise Denied("policy_signature_invalid")
    return envelope["body"], digest(envelope["body"]), int(envelope["version"])


def build_request(caller: str, action: str, target_id: str, params: dict, policy_digest: str, enrollment_revision: int, nonce: str, ttl_s: int = 30) -> dict:
    now = int(time.time())
    return {
        "caller": caller,
        "action": action,
        "target_id": target_id,
        "params": params or {},
        "policy_digest": policy_digest,
        "enrollment_revision": int(enrollment_revision),
        "nonce": nonce,
        "issued_at": now,
        "expiry": now + int(ttl_s),
    }


def sign(request: dict, private_key_path: str) -> str:
    return crypto.sign_hex(private_key_path, canonical(request))


def _token_payload(fields: dict) -> str:
    return base64.urlsafe_b64encode(canonical(fields)).decode("ascii").rstrip("=")


def _decision(store: Store, allow: bool, reason: str, req: Optional[dict], **extra: Any) -> dict:
    record = {
        "allow": bool(allow),
        "reason": reason,
        "caller": (req or {}).get("caller", ""),
        "action": (req or {}).get("action", ""),
        "target_id": (req or {}).get("target_id", ""),
        "params": (req or {}).get("params", {}),
        "policy_digest": (req or {}).get("policy_digest", ""),
        "enrollment_revision": (req or {}).get("enrollment_revision", 0),
        "nonce": (req or {}).get("nonce", ""),
        "ts": int(time.time()),
    }
    record.update(extra)
    decision_id = store.append_decision(record)
    out = {"allow": allow, "reason": reason, "decision_id": decision_id}
    out.update(extra)
    return out


def _grant_for(policy: dict, caller: str, action: str, target_id: str) -> Optional[dict]:
    caller_spec = (policy.get("callers") or {}).get(caller)
    if not caller_spec:
        return None
    for item in caller_spec.get("grants") or []:
        if item.get("action") != action:
            continue
        targets = item.get("targets") or []
        if "*" in targets or target_id in targets:
            return item
    return None


def authorize(store: Store, policy: dict, keys: dict, request: dict, signature: str, owner: str, gate_key_path: Optional[str] = None) -> dict:
    request = dict(request)

    # 1. closed schema
    extra = set(request) - REQUEST_KEYS
    missing = REQUEST_KEYS - set(request)
    if extra or missing:
        return _decision(store, False, "malformed_request", request, extra=sorted(extra), missing=sorted(missing))

    req_digest = digest(request)
    caller = request["caller"]

    # 2. identity proven (asymmetric: only the caller holds the private key)
    public = _public_for(keys, caller)
    if not public:
        store.record_request(req_digest, request["nonce"], caller, request["action"], request["target_id"])
        out = _decision(store, False, "unknown_caller", request)
        store.settle_request(req_digest, "deny", out["reason"], out["decision_id"])
        return out
    try:
        valid = crypto.verify_hex(public, canonical(request), signature or "")
    except crypto.CryptoError:
        return _decision(store, False, "crypto_unavailable", request)
    if not valid:
        store.record_request(req_digest, request["nonce"], caller, request["action"], request["target_id"])
        out = _decision(store, False, "bad_signature", request)
        store.settle_request(req_digest, "deny", out["reason"], out["decision_id"])
        return out

    # 3. the gate must be able to sign tokens; fail closed if not
    gate_key_path = gate_key_path or os.environ.get("BROKER_GATE_KEY")
    if not _public_for(keys, GATE_KEY_ID) or not gate_key_path or not os.path.exists(gate_key_path):
        return _decision(store, False, "gate_key_unavailable", request)

    # 4. freshness
    now = int(time.time())
    max_age = int(policy.get("max_request_age_s", 60))
    skew = int(policy.get("clock_skew_s", 30))
    if abs(now - int(request["issued_at"])) > max_age + skew:
        store.record_request(req_digest, request["nonce"], caller, request["action"], request["target_id"])
        out = _decision(store, False, "stale_request", request)
        store.settle_request(req_digest, "deny", out["reason"], out["decision_id"])
        return out
    if int(request["expiry"]) < now:
        store.record_request(req_digest, request["nonce"], caller, request["action"], request["target_id"])
        out = _decision(store, False, "expired_request", request)
        store.settle_request(req_digest, "deny", out["reason"], out["decision_id"])
        return out

    # 5. replay (also claims the nonce): one nonce, one outcome, forever
    try:
        store.record_request(req_digest, request["nonce"], caller, request["action"], request["target_id"])
    except Denied as exc:
        return _decision(store, False, exc.reason, request)

    def deny(reason: str, **extra: Any) -> dict:
        out = _decision(store, False, reason, request, **extra)
        store.settle_request(req_digest, "deny", reason, out["decision_id"])
        return out

    # 6. policy digest (a request bound to a different policy is refused)
    current_digest = digest(policy)
    if request["policy_digest"] != current_digest:
        return deny("policy_digest_mismatch")

    # 7. capability + bounded params
    try:
        params = registry.validate_params(request["action"], request["params"])
    except registry.RegistryError as exc:
        return deny("capability_refused", detail=str(exc))

    # 8. policy grant (deny by default)
    if _grant_for(policy, caller, request["action"], request["target_id"]) is None:
        return deny("not_granted")
    grant = _grant_for(policy, caller, request["action"], request["target_id"])

    # 9. enrollment still current
    enrollment = store.enrollment_by_target(request["target_id"])
    if enrollment is None:
        return deny("target_not_enrolled")
    if enrollment["status"] != "enabled":
        return deny("enrollment_disabled")
    caps = [c for c in (enrollment["caps"] or "").split(",") if c]
    if request["action"] not in caps:
        return deny("capability_not_granted_to_pod")
    if int(request["enrollment_revision"]) != int(enrollment["revision"]):
        return deny("enrollment_revision_mismatch")

    target = store.target(request["target_id"])
    if target is None:
        return deny("target_disabled")
    if target["state"] != "approved" or not target["public_key"]:
        return deny("target_not_approved")
    if target["status"] != "enabled":
        return deny("target_disabled")

    # 10. exclusive lease + monotonic fence
    ttl = int(grant.get("ttl_s") or registry.get(request["action"])["ttl_s"])
    try:
        lease = store.acquire_lease(request["target_id"], owner, request["action"], ttl, req_digest)
    except Denied as exc:
        return deny(exc.reason)

    # 11. single-use token, signed by the gate, bound to everything material
    expires = min(int(request["expiry"]), int(lease["expires_ts"]))
    payload = {
        "caller": caller,
        "target_id": request["target_id"],
        "action": request["action"],
        "params": params,
        "fencing": int(lease["fencing"]),
        "decision_id": "",
        "policy_digest": current_digest,
        "expiry": expires,
    }
    record = {
        "allow": True,
        "reason": "allow",
        "caller": caller,
        "action": request["action"],
        "target_id": request["target_id"],
        "params": params,
        "policy_digest": current_digest,
        "enrollment_revision": int(enrollment["revision"]),
        "nonce": request["nonce"],
        "fencing": int(lease["fencing"]),
        "ts": int(time.time()),
    }
    decision_id = store.append_decision(record)
    payload["decision_id"] = decision_id
    body = _token_payload(payload)
    try:
        token = f"{body}.{crypto.sign_hex(gate_key_path, body.encode('ascii'))}"
    except crypto.CryptoError:
        return deny("gate_key_unavailable")
    store.mint_token(digest({"tok": token}), decision_id, request["target_id"], request["action"], int(lease["fencing"]), expires)
    store.settle_request(req_digest, "allow", "allow", decision_id)

    return {
        "allow": True,
        "reason": "allow",
        "decision_id": decision_id,
        "token": token,
        "fencing": int(lease["fencing"]),
        "expires_ts": expires,
        "target_id": request["target_id"],
        "action": request["action"],
        "params": params,
        "lease_reused": bool(lease.get("reused")),
    }


def verify_token(store: Store, keys: dict, token: str, target_id: str, action: str) -> dict:
    """Gate at use. Verifies signature/scope/freshness/fencing/enrollment.

    Does not mutate state; store.claim_run() consumes the token atomically with
    recording the run.
    """
    if not token or "." not in token:
        raise Denied("token_malformed")
    body, _, sig = token.rpartition(".")
    try:
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)).decode("ascii"))
    except (ValueError, json.JSONDecodeError):
        raise Denied("token_malformed")
    if not isinstance(payload, dict) or set(payload) != TOKEN_KEYS:
        raise Denied("token_malformed")

    public = _public_for(keys, GATE_KEY_ID)
    if not public:
        raise Denied("gate_key_unavailable")
    try:
        good = crypto.verify_hex(public, body.encode("ascii"), sig)
    except crypto.CryptoError:
        raise Denied("crypto_unavailable")
    if not good:
        raise Denied("bad_token_signature")
    if int(payload["expiry"]) < int(time.time()):
        raise Denied("token_expired")
    if payload["target_id"] != target_id or payload["action"] != action:
        raise Denied("token_scope_mismatch")
    if int(payload["fencing"]) != store.current_fencing(target_id):
        raise Denied("stale_fencing")

    enrollment = store.enrollment_by_target(target_id)
    if enrollment is None or enrollment["status"] != "enabled":
        raise Denied("target_not_enrolled")
    caps = [c for c in (enrollment["caps"] or "").split(",") if c]
    if action not in caps:
        raise Denied("capability_not_granted_to_pod")
    target = store.target(target_id)
    if target is None:
        raise Denied("target_disabled")
    if target["state"] != "approved" or not target["public_key"]:
        raise Denied("target_not_approved")
    if target["status"] != "enabled":
        raise Denied("target_disabled")
    return payload


def checkpoint(store: Store, out_path: str, witness_url: Optional[str] = None) -> dict:
    """Write the chain head locally and anchor it with an external witness.

    A local hash chain is only tamper-evident if the head is also held where the
    device cannot rewrite it. The witness must return the highest sequence it
    has accepted; a regression is treated as rollback and denied.
    """
    head = store.head()
    if not head:
        raise Denied("chain_verification_failed")
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    prev = None
    if os.path.exists(out_path):
        try:
            with open(out_path, "r", encoding="utf-8") as handle:
                prev = json.load(handle)
        except (OSError, json.JSONDecodeError):
            prev = None
    seq = int(store.get_meta("checkpoint_seq") or 0) + 1
    entry = {"seq": seq, "head": head, "ts": int(time.time()), "prev_head": (prev or {}).get("head")}
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(entry, handle, sort_keys=True)
    store.set_meta("checkpoint_seq", str(seq))
    result = {"head": head, "seq": seq, "path": out_path, "non_monotonic": bool(prev and prev.get("head") == head)}

    if witness_url:
        import urllib.request

        try:
            req = urllib.request.Request(
                witness_url,
                data=json.dumps(entry).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                ack = json.loads(resp.read().decode())
            result["witness"] = ack
            seen = store.get_meta("witness_seq")
            if isinstance(ack, dict) and "seq" in ack:
                if seen is not None and int(ack["seq"]) < int(seen):
                    raise Denied("witness_rollback", witness_seq=ack["seq"], local_seq=int(seen))
                store.set_meta("witness_seq", str(int(ack["seq"])))
        except Denied:
            raise
        except Exception as exc:  # noqa: BLE001 - witness failure must be visible, not silent
            if os.environ.get("BROKER_REQUIRE_WITNESS") == "1":
                raise Denied("witness_unavailable", error=f"{type(exc).__name__}: {exc}")
            result["witness_error"] = f"{type(exc).__name__}: {exc}"
    elif os.environ.get("BROKER_REQUIRE_WITNESS") == "1":
        raise Denied("witness_unavailable", error="no witness configured")
    return result
