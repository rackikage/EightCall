"""broker.actions — fixed, read-only capability implementations.

Capability implementations are private (_ping, _neigh, ...) and are reachable
only through run(), which refuses to execute without a gate-minted Grant.
run_authorized() is the only public entry the CLI uses: it verifies a
gate-signed single-use token, atomically claims the run, then dispatches.

Each implementation receives the target's *stored* address (never a
caller-supplied host) and already-validated params. No shell, no eval,
absolute argv only, bounded output.
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import uuid
from typing import Any

from . import failpoints, gate, grant, possession
from .canon import digest
from .store import Denied

PING_BIN = "/system/bin/ping" if os.path.exists("/system/bin/ping") else "ping"
IP_BIN = "ip"

MAC_RE = re.compile(r"lladdr\s+([0-9a-f:]{17})", re.I)
STATE_RE = re.compile(r"\b(REACHABLE|STALE|DELAY|PROBE|FAILED|INCOMPLETE|PERMANENT)\b", re.I)


def _run_argv(argv: list, timeout: int = 6) -> tuple[int, str]:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, (proc.stdout or "")[:4096]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        return 127, f"{type(exc).__name__}: {exc}"


def _ping(address: str) -> dict[str, Any]:
    rc, out = _run_argv([PING_BIN, "-c", "1", "-W", "2", address], timeout=8)
    match = re.search(r"time[=<]([0-9.]+)\s*ms", out)
    return {"ok": rc == 0, "rtt_ms": float(match.group(1)) if match else None, "up": rc == 0}


def _neigh(address: str) -> dict[str, Any]:
    rc, out = _run_argv([IP_BIN, "neigh", "show", address], timeout=6)
    mac = MAC_RE.search(out)
    state = STATE_RE.search(out)
    return {
        "ok": rc == 0,
        "mac": mac.group(1).lower() if mac else None,
        "state": state.group(1).upper() if state else None,
        "raw": out.strip()[:200],
    }


def _tcp_probe(address: str, port: int) -> dict[str, Any]:
    try:
        with socket.create_connection((address, int(port)), timeout=3.0):
            return {"ok": True, "open": True, "port": int(port)}
    except (socket.timeout, TimeoutError):
        return {"ok": True, "open": False, "port": int(port), "reason": "timeout"}
    except OSError as exc:
        return {"ok": True, "open": False, "port": int(port), "reason": type(exc).__name__}


def _inventory(address: str) -> dict[str, Any]:
    return {"ping": _ping(address), "neigh": _neigh(address)}


_DISPATCH = {
    "ping": lambda addr, prm: _ping(addr),
    "neigh": lambda addr, prm: _neigh(addr),
    "tcp_probe": lambda addr, prm: _tcp_probe(addr, prm["port"]),
    "inventory": lambda addr, prm: _inventory(addr),
}


def run(action: str, address: str, params: dict[str, Any], execution_grant) -> dict[str, Any]:
    """Execute one capability. Refuses without a valid gate-minted grant."""
    if not isinstance(execution_grant, grant.Grant):
        raise PermissionError("no execution grant: capabilities run only under the gate")
    execution_grant.check(action)
    fn = _DISPATCH.get(action)
    if fn is None:
        return {"ok": False, "error": f"no implementation for {action!r}"}
    execution_grant.consume()
    return fn(address, params or {})


def run_authorized(store, keys, token: str, target_id: str, action: str, pod: str) -> dict[str, Any]:
    """The only public execution path: verify token, claim atomically, dispatch.

    The token is consumed inside the same transaction that records the run, so
    a crash cannot lose the authorization without leaving a run record.
    """
    payload = gate.verify_token(store, keys, token, target_id, action)
    target = store.target(target_id)
    if target is None or target["status"] != "enabled":
        raise Denied("target_disabled")
    # Proof of possession at use: the live peer must hold the pinned key before
    # the grant is consumed. A failure leaves the token unused.
    try:
        possession.verify_target(target["address"], target["transport_port"], target["key_fingerprint"])
        store.add_observation(target_id, "pop", "ok")
    except Denied as exc:
        store.add_observation(target_id, "pop", exc.reason)
        raise
    run_id = uuid.uuid4().hex
    store.claim_run(digest({"tok": token}), target_id, action, int(payload["fencing"]), run_id, pod)
    failpoints.hit("after_claim")
    execution_grant = grant.mint(target_id, action, int(payload["fencing"]), payload.get("params") or {}, run_id)
    try:
        result = run(action, target["address"], payload.get("params") or {}, execution_grant)
    except Exception as exc:
        store.finish_run(run_id, "outcome_unknown", result_digest({"error": str(exc)}))
        raise
    # Crash here (after the external effect, before the result is durable) must
    # leave the run ambiguous, never falsely "done".
    failpoints.hit("after_action")
    state = "done" if result.get("ok", True) else "failed"
    store.finish_run(run_id, state, result_digest(result))
    return {
        "ok": True,
        "run_id": run_id,
        "state": state,
        "target": target_id,
        "action": action,
        "fencing": int(payload["fencing"]),
        "result": result,
    }


def result_digest(result: dict[str, Any]) -> str:
    from .canon import sha256_hex

    return sha256_hex(json.dumps(result, sort_keys=True, separators=(",", ":")).encode())
