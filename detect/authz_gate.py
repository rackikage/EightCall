#!/usr/bin/env python3
"""Deterministic API authorization gate for the detect pipeline.

This module is the SINGLE boundary between parsed evidence / detection output
(the `evaluate()` hits produced by `validate_rules.py`) and any executor that
can act on a host (osascript runners, XPC services, response APIs).

Design invariants — read before changing anything:

  1. DENY BY DEFAULT. Authority is granted only by the operator-controlled
     policy file (`authz_policy.yml`). Anything not explicitly granted is
     denied. There is no allow-by-omission path.

  2. AUTHORITY IS NEVER INFERRED FROM CONTENT. The gate decides using only the
     request's structural fields (caller, action, target, params, nonce,
     issued_at) matched against the policy. It never reads packet bytes, log
     lines, model output, or a detection's "verdict" to grant access. A
     detection can *trigger* a runner to build a request; it can never *be*
     the authorization. The request schema is closed (`_ALLOWED_KEYS`), so a
     caller cannot smuggle an `allow`/`verdict`/`authorized` field past the
     gate — such a request is rejected as malformed.

  3. IDENTITY IS PROVEN, NOT CLAIMED. Each caller holds an HMAC-SHA256 key
     registered in the policy. The request is signed over its canonical bytes;
     the gate recomputes and compares in constant time. An unsigned or
     wrongly-signed request is denied before any grant is consulted.

  4. EVERY DECISION IS AUDITED IMMUTABLY. Each `authorize()` call appends
     exactly one record to a hash-chained JSONL audit trail. The returned
     `decision_id` IS that record's chain hash, so a runner's log line ties
     back to the exact, tamper-evident audit entry.

The narrow contract downstream runners consume:

    gate = AuthzGate.from_policy_file("authz_policy.yml")
    decision = gate.authorize(request)      # -> Decision(allow, reason, decision_id)
    if not decision.allow:
        abort(decision.reason)
    # ... only now may the executor run, quoting decision.decision_id ...

or, fail-closed in one line:

    decision_id = gate.require(request)     # raises AuthorizationDenied on deny
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml

SCHEMA = "detect.authz/v1"
GENESIS_HASH = "0" * 64

# The request schema is closed. Any key outside this set is rejected as
# malformed — this is what stops a caller smuggling an authorization verdict
# (e.g. "allow", "authorized", "detection_says") into the request.
_ALLOWED_KEYS = frozenset(
    {"caller", "action", "target", "params", "nonce", "issued_at", "evidence_ref", "sig"}
)
_REQUIRED_KEYS = frozenset({"caller", "action", "target", "nonce", "issued_at", "sig"})
# Fields covered by the HMAC signature (everything the caller asserts, minus
# the signature itself). Ordering is irrelevant: canonicalization sorts keys.
_SIGNED_KEYS = frozenset({"caller", "action", "target", "params", "nonce", "issued_at", "evidence_ref"})


class AuthorizationDenied(Exception):
    """Raised by AuthzGate.require() when a request is not authorized."""

    def __init__(self, reason: str, decision_id: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.decision_id = decision_id


@dataclass(frozen=True)
class Decision:
    """The only thing the gate ever returns. `allow` is authoritative;
    `reason` is human-readable; `decision_id` is the audit chain hash."""

    allow: bool
    reason: str
    decision_id: str


def canonical_bytes(obj: dict) -> bytes:
    """Deterministic serialization used for both signatures and audit hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def signed_message(request: dict) -> bytes:
    """The exact bytes a caller signs and the gate verifies: the canonical
    serialization of the signed fields only (never the `sig` itself)."""
    signed = {k: request[k] for k in _SIGNED_KEYS if k in request}
    return canonical_bytes(signed)


def pubkey_fingerprint(pubkey_raw: bytes) -> str:
    """SHA-256 hex of a raw 32-byte Ed25519 public key. This 'keyhash' is the
    caller's cryptographic identity: the gate pins it, and key rotation means
    publishing a new fingerprint — no secret is ever involved."""
    return hashlib.sha256(pubkey_raw).hexdigest()


def ed25519_verify(pubkey_raw: bytes, message: bytes, sig_hex: str) -> bool:
    """Verify an Ed25519 signature (hex) over `message` with a raw public key.
    `cryptography` is imported lazily so HMAC-only deployments need no crypto
    dependency. Any malformed key/signature verifies as False, never raises."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        sig = bytes.fromhex(sig_hex)
    except (ImportError, ValueError):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(pubkey_raw).verify(sig, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def ed25519_sign(request: dict, private_key_raw: bytes) -> str:
    """Runner-side helper: sign a request with a raw 32-byte Ed25519 private
    key, returning the signature as hex. The private key stays on the runner;
    it is never sent to or stored by the gate."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.from_private_bytes(private_key_raw)
    return key.sign(signed_message(request)).hex()


def _parse_ts(value: str) -> datetime:
    """Parse an ISO-8601 timestamp; a trailing Z is treated as UTC. Naive
    timestamps are rejected (an ambiguous time cannot gate a security action)."""
    if not isinstance(value, str) or not value:
        raise ValueError("timestamp must be a non-empty ISO-8601 string")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return dt.astimezone(timezone.utc)


def _target_matches(pattern: str, target: str) -> bool:
    """Explicit scope match: exact string, or a single trailing '*' prefix
    glob with at least one literal character before it. A bare '*' never
    matches — scope must be spelled out."""
    if not isinstance(pattern, str) or not pattern:
        return False
    if pattern == "*":
        return False
    if pattern.endswith("*"):
        prefix = pattern[:-1]
        return bool(prefix) and target.startswith(prefix)
    return pattern == target


@dataclass
class _Grant:
    action: str
    targets: tuple[str, ...]
    params: dict
    not_before: datetime | None
    not_after: datetime | None


@dataclass
class _Caller:
    name: str
    alg: str                      # "hmac" (pt1, local) or "ed25519" (pt2, remote)
    key: bytes | None             # hmac shared secret; None for ed25519
    pubkey: bytes | None          # ed25519 raw public key (verify-only); None for hmac
    fingerprint: str | None       # sha256 hex of pubkey — the pinned "keyhash"
    key_error: str | None         # non-None => caller is unusable, deny with this
    grants: list[_Grant] = field(default_factory=list)


class AuthzGate:
    """Loaded once per process; thread-safe for concurrent runners."""

    def __init__(
        self,
        callers: dict[str, _Caller],
        *,
        max_request_age_seconds: int,
        clock_skew_seconds: int,
        audit_path: Path,
        nonce_path: Path,
        now_fn: Callable[[], datetime] | None = None,
    ) -> None:
        self._callers = callers
        self._max_age = max_request_age_seconds
        self._skew = clock_skew_seconds
        self._audit_path = audit_path
        self._nonce_path = nonce_path
        self._now = now_fn or (lambda: datetime.now(timezone.utc))
        self._lock = threading.Lock()
        self._seen_nonces = self._load_nonces()
        self._prev_hash, self._seq = self._load_chain_tip()

    # ---- construction -----------------------------------------------------

    @classmethod
    def from_policy_file(
        cls,
        policy_path: str | os.PathLike,
        *,
        audit_path: str | os.PathLike | None = None,
        nonce_path: str | os.PathLike | None = None,
        now_fn: Callable[[], datetime] | None = None,
    ) -> AuthzGate:
        policy_path = Path(policy_path)
        with open(policy_path) as fh:
            policy = yaml.safe_load(fh)
        base = policy_path.parent
        return cls.from_policy(
            policy,
            base_dir=base,
            audit_path=audit_path,
            nonce_path=nonce_path,
            now_fn=now_fn,
        )

    @classmethod
    def from_policy(
        cls,
        policy: dict,
        *,
        base_dir: Path | None = None,
        audit_path: str | os.PathLike | None = None,
        nonce_path: str | os.PathLike | None = None,
        now_fn: Callable[[], datetime] | None = None,
    ) -> AuthzGate:
        base_dir = Path(base_dir or ".")
        if policy.get("schema") != "detect.authz.policy/v1":
            raise ValueError(
                f"unexpected policy schema {policy.get('schema')!r}; "
                "refusing to load (a mislabeled policy could silently widen access)"
            )
        callers: dict[str, _Caller] = {}
        for name, spec in (policy.get("callers") or {}).items():
            alg, key, pubkey, fingerprint, key_error = cls._resolve_caller(spec)
            grants = [cls._parse_grant(g) for g in (spec.get("grants") or [])]
            callers[name] = _Caller(
                name=name, alg=alg, key=key, pubkey=pubkey,
                fingerprint=fingerprint, key_error=key_error, grants=grants,
            )
        return cls(
            callers,
            max_request_age_seconds=int(policy.get("max_request_age_seconds", 120)),
            clock_skew_seconds=int(policy.get("clock_skew_seconds", 30)),
            audit_path=Path(audit_path) if audit_path else base_dir / "authz_audit.jsonl",
            nonce_path=Path(nonce_path) if nonce_path else base_dir / "authz_nonces.log",
            now_fn=now_fn,
        )

    @staticmethod
    def _resolve_caller(spec: dict) -> tuple[str, bytes | None, bytes | None, str | None, str | None]:
        """Returns (alg, hmac_key, ed25519_pubkey, fingerprint, error)."""
        alg = spec.get("alg", "hmac")
        if alg == "hmac":
            if "key_hex" in spec:
                try:
                    return alg, bytes.fromhex(spec["key_hex"]), None, None, None
                except ValueError:
                    return alg, None, None, None, "key_hex is not valid hex"
            if "key_env" in spec:
                raw = os.environ.get(spec["key_env"])
                if not raw:
                    return alg, None, None, None, f"env var {spec['key_env']} unset or empty"
                return alg, raw.encode("utf-8"), None, None, None
            return alg, None, None, None, "no key_hex or key_env configured for caller"
        if alg == "ed25519":
            if "pubkey_b64" not in spec:
                return alg, None, None, None, "ed25519 caller missing pubkey_b64"
            try:
                pub = base64.b64decode(spec["pubkey_b64"], validate=True)
            except (ValueError, TypeError):
                return alg, None, None, None, "pubkey_b64 is not valid base64"
            if len(pub) != 32:
                return alg, None, None, None, f"ed25519 pubkey must be 32 raw bytes, got {len(pub)}"
            fp = pubkey_fingerprint(pub)
            # Fingerprint pinning: if the policy declares key_sha256, the pubkey
            # must hash to it. This catches a pubkey swapped without updating
            # the pin, and makes the keyhash the authoritative identity.
            pinned = spec.get("key_sha256")
            if pinned is not None and not hmac.compare_digest(fp, str(pinned).lower()):
                return alg, None, None, fp, "pubkey fingerprint does not match pinned key_sha256"
            return alg, None, pub, fp, None
        return alg, None, None, None, f"unknown alg {alg!r}"

    @staticmethod
    def _parse_grant(g: dict) -> _Grant:
        targets = g.get("targets") or []
        if isinstance(targets, str):
            targets = [targets]
        return _Grant(
            action=g["action"],
            targets=tuple(targets),
            params=dict(g.get("params") or {}),
            not_before=_parse_ts(g["not_before"]) if g.get("not_before") else None,
            not_after=_parse_ts(g["not_after"]) if g.get("not_after") else None,
        )

    # ---- the contract -----------------------------------------------------

    def authorize(self, request: dict) -> Decision:
        """Evaluate one request. Always returns a Decision and always writes
        exactly one audit record. Never raises on a denial (that is a normal
        outcome); raises only on an unusable audit/nonce store."""
        with self._lock:
            allow, reason, audit_extra = self._evaluate(request)
            decision_id = self._append_audit(request, allow, reason, audit_extra)
            return Decision(allow=allow, reason=reason, decision_id=decision_id)

    def require(self, request: dict) -> str:
        """Fail-closed helper for runners: returns decision_id on allow,
        raises AuthorizationDenied otherwise."""
        decision = self.authorize(request)
        if not decision.allow:
            raise AuthorizationDenied(decision.reason, decision.decision_id)
        return decision.decision_id

    # ---- decision logic (deny by default at every step) -------------------

    def _evaluate(self, request: dict) -> tuple[bool, str, dict]:
        if not isinstance(request, dict):
            return False, "malformed request: not an object", {}

        extra_keys = set(request) - _ALLOWED_KEYS
        if extra_keys:
            # This is the smuggling guard: an unknown key is refused rather
            # than ignored, so a request can never carry its own verdict.
            return False, f"malformed request: unexpected field(s) {sorted(extra_keys)}", {}
        missing = _REQUIRED_KEYS - set(request)
        if missing:
            return False, f"malformed request: missing field(s) {sorted(missing)}", {}

        # Structural typing is part of the closed schema: caller/action/target
        # must be strings. Without this, a non-string caller can be unhashable
        # (crashing the policy lookup) and a non-string target can crash scope
        # matching — a malformed request must be DENIED, never raise.
        for key in ("caller", "action", "target"):
            if not isinstance(request[key], str) or not request[key]:
                return False, f"malformed request: {key} must be a non-empty string", {}

        caller_name = request["caller"]
        params = request.get("params") or {}
        if not isinstance(params, dict):
            return False, "malformed request: params must be an object", {}
        if not isinstance(request["nonce"], str) or not request["nonce"]:
            return False, "malformed request: nonce must be a non-empty string", {}

        caller = self._callers.get(caller_name)
        if caller is None:
            return False, f"unknown caller {caller_name!r}", {}
        if caller.key_error is not None:
            return False, f"caller {caller_name!r} has no usable key ({caller.key_error})", {}

        fp_extra = {"caller_fingerprint": caller.fingerprint}
        # Prove identity + integrity before anything else touches state.
        if not self._verify_signature(request, caller):
            return False, "bad signature: request not signed by caller key", fp_extra

        # Freshness. issued_at must be recent and not in the future.
        try:
            issued = _parse_ts(request["issued_at"])
        except ValueError as exc:
            return False, f"malformed request: issued_at {exc}", fp_extra
        now = self._now()
        age = (now - issued).total_seconds()
        if age > self._max_age:
            return False, f"stale request: issued {int(age)}s ago (max {self._max_age}s)", fp_extra
        if age < -self._skew:
            return False, f"request issued in the future by {int(-age)}s (skew {self._skew}s)", fp_extra

        # Replay protection. A nonce is consumed the moment an authenticated
        # request is seen, for ANY decision, so a captured signed request can
        # never be replayed regardless of the first outcome.
        nonce_key = f"{caller_name}\t{request['nonce']}"
        if nonce_key in self._seen_nonces:
            return False, "replay: nonce already used by this caller", fp_extra
        self._consume_nonce(nonce_key)
        consumed = {**fp_extra, "nonce_consumed": True}

        # Match against explicitly granted authority.
        action = request["action"]
        target = request["target"]
        candidate_actions = [g for g in caller.grants if g.action == action]
        if not candidate_actions:
            return False, f"action {action!r} not permitted for caller {caller_name!r}", consumed

        reasons: list[str] = []
        for g in candidate_actions:
            if g.not_before and now < g.not_before:
                reasons.append("grant not yet valid")
                continue
            if g.not_after and now > g.not_after:
                reasons.append("grant expired")
                continue
            if not any(_target_matches(p, target) for p in g.targets):
                reasons.append("target out of scope")
                continue
            ok, why = self._params_within(g.params, params)
            if not ok:
                reasons.append(why)
                continue
            return True, f"granted: {action} on {target}", consumed

        detail = "; ".join(sorted(set(reasons))) or "no matching grant"
        return False, f"denied for {action} on {target}: {detail}", consumed

    @staticmethod
    def _params_within(allowed: dict, requested: dict) -> tuple[bool, str]:
        """The grant's params are the complete allowlist. Every requested
        param must be present in the grant with an equal value, and no extra
        params are permitted — a grant with no params matches only paramless
        requests. This is what pins e.g. run_osascript to named scripts."""
        for key, value in requested.items():
            if key not in allowed:
                return False, f"param {key!r} not allowed by grant"
            if allowed[key] != value:
                return False, f"param {key!r} value not permitted"
        return True, "ok"

    def _verify_signature(self, request: dict, caller: _Caller) -> bool:
        provided = request.get("sig", "")
        if not isinstance(provided, str) or not provided:
            return False
        msg = signed_message(request)
        if caller.alg == "hmac":
            expected = hmac.new(caller.key, msg, hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected, provided)
        if caller.alg == "ed25519":
            return ed25519_verify(caller.pubkey, msg, provided)
        return False

    @staticmethod
    def sign(request: dict, key: bytes) -> str:
        """Helper for HMAC runners/tests: compute the sig for a request dict.
        (Ed25519 runners use the module-level `ed25519_sign`.)"""
        return hmac.new(key, signed_message(request), hashlib.sha256).hexdigest()

    # ---- durable state: nonces + hash-chained audit -----------------------

    def _load_nonces(self) -> set[str]:
        seen: set[str] = set()
        if self._nonce_path.exists():
            with open(self._nonce_path) as fh:
                for line in fh:
                    line = line.rstrip("\n")
                    if line:
                        seen.add(line)
        return seen

    def _consume_nonce(self, nonce_key: str) -> None:
        self._seen_nonces.add(nonce_key)
        with open(self._nonce_path, "a") as fh:
            fh.write(nonce_key + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def _load_chain_tip(self) -> tuple[str, int]:
        prev, seq = GENESIS_HASH, 0
        if self._audit_path.exists():
            with open(self._audit_path) as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    rec = json.loads(line)
                    prev = rec["record_hash"]
                    seq = rec["seq"] + 1
        return prev, seq

    def _append_audit(self, request: dict, allow: bool, reason: str, extra: dict) -> str:
        # The audit record deliberately records the request's structural
        # fields and an opaque evidence_ref for traceability — never evidence
        # contents, which are not part of the authorization decision.
        record = {
            "schema": SCHEMA,
            "seq": self._seq,
            "ts": self._now().isoformat(),
            "decision": "allow" if allow else "deny",
            "reason": reason,
            "caller": request.get("caller") if isinstance(request, dict) else None,
            "caller_fingerprint": extra.get("caller_fingerprint"),
            "action": request.get("action") if isinstance(request, dict) else None,
            "target": request.get("target") if isinstance(request, dict) else None,
            "params": request.get("params") if isinstance(request, dict) else None,
            "nonce": request.get("nonce") if isinstance(request, dict) else None,
            "request_issued_at": request.get("issued_at") if isinstance(request, dict) else None,
            "evidence_ref": request.get("evidence_ref") if isinstance(request, dict) else None,
            "prev_hash": self._prev_hash,
        }
        record["record_hash"] = hashlib.sha256(canonical_bytes(record)).hexdigest()
        with open(self._audit_path, "a") as fh:
            fh.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self._prev_hash = record["record_hash"]
        self._seq += 1
        return record["record_hash"]


def verify_audit_chain(audit_path: str | os.PathLike) -> tuple[bool, int, int | None]:
    """Recompute the hash chain. Returns (ok, records_checked, first_bad_seq).
    A False result means the append-only log was edited or reordered."""
    audit_path = Path(audit_path)
    if not audit_path.exists():
        return True, 0, None
    prev = GENESIS_HASH
    count = 0
    with open(audit_path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            stored = rec.get("record_hash")
            body = {k: v for k, v in rec.items() if k != "record_hash"}
            recomputed = hashlib.sha256(canonical_bytes(body)).hexdigest()
            if rec.get("prev_hash") != prev or recomputed != stored:
                return False, count, rec.get("seq")
            prev = stored
            count += 1
    return True, count, None


if __name__ == "__main__":
    import sys

    if len(sys.argv) >= 3 and sys.argv[1] == "verify":
        ok, n, bad = verify_audit_chain(sys.argv[2])
        print(f"audit chain: {n} records -> {'OK' if ok else f'BROKEN at seq {bad}'}")
        sys.exit(0 if ok else 1)
    print("usage: authz_gate.py verify <audit.jsonl>", file=sys.stderr)
    sys.exit(2)
