#!/usr/bin/env python3
"""Append-only, hash-chained audit log.

Tamper-evident record keeping for authorization decisions and command
execution. Each record commits to the hash of the previous record, so
altering or removing any historical entry breaks the chain and is detectable
with verify().

This is deliberately small: it is a reference for the audit requirement in the
authz-gate model, not a production log store. In real deployments, ship these
records to off-host WORM storage so the component being audited cannot rewrite
its own history.

Stdlib only. Run `python audit_log.py` for the built-in self-test.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._prev = self._tail_hash()

    def _tail_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = None
        for line in self.path.read_text().splitlines():
            if line.strip():
                last = line
        if last is None:
            return GENESIS
        return json.loads(last)["hash"]

    @staticmethod
    def _hash(record: dict[str, Any]) -> str:
        payload = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(payload).hexdigest()

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        record = dict(event)
        record["prev_hash"] = self._prev
        record["timestamp"] = time.time()
        record["hash"] = self._hash(record)
        with self.path.open("a") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
        self._prev = record["hash"]
        return record

    def verify(self) -> tuple[bool, int | None, str]:
        """Return (ok, failing_line, message)."""
        if not self.path.exists():
            return True, None, "no records"
        prev = GENESIS
        for i, line in enumerate(self.path.read_text().splitlines(), 1):
            if not line.strip():
                continue
            record = json.loads(line)
            stored = record.pop("hash")
            if record.get("prev_hash") != prev:
                return False, i, "prev_hash mismatch"
            if self._hash(record) != stored:
                return False, i, "record hash mismatch"
            prev = stored
        return True, None, "chain intact"


def _self_test() -> int:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "audit.jsonl"
        log = AuditLog(path)
        log.append({"event": "authz.decision", "request_id": "req_01", "permit": True, "actor": "user_123"})
        log.append({"event": "command.executed", "request_id": "req_01", "action": "service.restart"})
        log.append({"event": "authz.decision", "request_id": "req_02", "permit": False, "reason": "role is not authorized"})

        ok, line, msg = log.verify()
        print(f"intact chain: ok={ok} line={line} msg={msg}")

        lines = path.read_text().splitlines()
        tampered = json.loads(lines[1])
        tampered["action"] = "service.delete"
        lines[1] = json.dumps(tampered, sort_keys=True)
        path.write_text("\n".join(lines) + "\n")

        ok2, line2, msg2 = AuditLog(path).verify()
        print(f"tampered chain: ok={ok2} line={line2} msg={msg2}")

        passed = ok and not ok2 and line2 == 2
        print("PASS" if passed else "FAIL")
        return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(_self_test())
