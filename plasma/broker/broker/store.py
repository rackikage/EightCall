"""broker.store — transactional authority state (SQLite, WAL).

This is the only authoritative state in broker, and it is authoritative for ONE
host only. WAL requires all participating processes to live on the same host;
this database must never be shared, copied, or mounted across hosts, and a
restored backup must be treated as a potential security rollback.

Bash never writes it; the CLI is the sole writer. Constraints encode the laws
so a bypass cannot express itself as data.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from typing import Any, Optional

from .canon import GENESIS, digest, sha256_hex

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets(
  target_id          TEXT PRIMARY KEY,
  label              TEXT NOT NULL DEFAULT '',
  address            TEXT NOT NULL,
  status             TEXT NOT NULL DEFAULT 'enabled',
  created_ts         INTEGER NOT NULL,
  identity_algorithm TEXT NOT NULL DEFAULT 'ed25519',
  public_key         TEXT,                       -- pinned target identity (hex)
  key_fingerprint    TEXT,                       -- sha256(public_key)
  state              TEXT NOT NULL DEFAULT 'candidate',  -- candidate|approved|revoked
  approval_digest    TEXT NOT NULL DEFAULT '',
  endpoint_revision  INTEGER NOT NULL DEFAULT 1,  -- mutable routing metadata
  approved_ts        INTEGER
);
CREATE TABLE IF NOT EXISTS enrollments(
  pod_name    TEXT PRIMARY KEY,
  target_id   TEXT NOT NULL UNIQUE,          -- ONE TARGET = ONE POD
  caps        TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'enabled',
  revision    INTEGER NOT NULL DEFAULT 1,
  created_ts  INTEGER NOT NULL,
  FOREIGN KEY(target_id) REFERENCES targets(target_id)
);
CREATE TABLE IF NOT EXISTS leases(
  target_id   TEXT PRIMARY KEY,
  fencing     INTEGER NOT NULL,
  owner       TEXT NOT NULL,
  action      TEXT NOT NULL,
  idem_key    TEXT NOT NULL,
  issued_ts   INTEGER NOT NULL,
  expires_ts  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS requests(
  req_digest  TEXT PRIMARY KEY,              -- replay: one digest, one lifetime
  nonce       TEXT NOT NULL UNIQUE,
  caller      TEXT NOT NULL,
  action      TEXT NOT NULL,
  target_id   TEXT NOT NULL,
  issued_ts   INTEGER NOT NULL,
  outcome     TEXT NOT NULL,
  reason      TEXT NOT NULL DEFAULT '',
  decision_id TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS decisions(
  seq         INTEGER PRIMARY KEY AUTOINCREMENT,
  decision_id TEXT NOT NULL UNIQUE,
  prev        TEXT NOT NULL,
  record      TEXT NOT NULL,
  ts          INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens(
  token_digest TEXT PRIMARY KEY,
  decision_id  TEXT NOT NULL,
  target_id    TEXT NOT NULL,
  action       TEXT NOT NULL,
  fencing      INTEGER NOT NULL,
  expires_ts   INTEGER NOT NULL,
  used         INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS runs(
  run_id        TEXT PRIMARY KEY,
  target_id     TEXT NOT NULL,
  action        TEXT NOT NULL,
  fencing       INTEGER NOT NULL,
  pod           TEXT NOT NULL,
  state         TEXT NOT NULL,
  started_ts    INTEGER,
  ended_ts      INTEGER,
  result_digest TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS observations(
  obs_id    INTEGER PRIMARY KEY AUTOINCREMENT,
  target_id TEXT NOT NULL,
  kind      TEXT NOT NULL,
  value     TEXT NOT NULL DEFAULT '',
  ts        INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS checkpoints(
  seq  INTEGER PRIMARY KEY,
  head TEXT NOT NULL,
  ts   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS meta(
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
"""


class Denied(Exception):
    """Structured refusal. Reason strings are stable and auditable."""

    def __init__(self, reason: str, **detail: Any):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


class Store:
    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, mode=0o700, exist_ok=True)
        self.db = sqlite3.connect(self.path, isolation_level=None, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.executescript(SCHEMA)
        self._migrate()
        integrity = self.db.execute("PRAGMA quick_check").fetchone()[0]
        if integrity != "ok":
            self.db.close()
            raise Denied("database_integrity_failed", detail=str(integrity)[:120])
        os.chmod(self.path, 0o600)

    def close(self) -> None:
        self.db.close()

    def _migrate(self) -> None:
        cols = {row["name"] for row in self.db.execute("PRAGMA table_info(targets)")}
        additions = {
            "identity_algorithm": "TEXT NOT NULL DEFAULT 'ed25519'",
            "public_key": "TEXT",
            "key_fingerprint": "TEXT",
            "state": "TEXT NOT NULL DEFAULT 'candidate'",
            "approval_digest": "TEXT NOT NULL DEFAULT ''",
            "endpoint_revision": "INTEGER NOT NULL DEFAULT 1",
            "approved_ts": "INTEGER",
            "transport_port": "INTEGER",
        }
        for name, ddl in additions.items():
            if name not in cols:
                self.db.execute(f"ALTER TABLE targets ADD COLUMN {name} {ddl}")

    # -------------------------------------------------------------------- meta
    def get_meta(self, key: str) -> Optional[str]:
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        self.db.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )

    def accept_policy_version(self, version: int) -> None:
        """Monotonic policy acceptance. A lower version is a rollback: deny."""
        self.db.execute("BEGIN IMMEDIATE")
        try:
            current = self.get_meta("policy_version")
            if current is not None and int(version) < int(current):
                raise Denied("policy_rollback", got=int(version), accepted=int(current))
            self.set_meta("policy_version", str(int(version)))
            self.db.execute("COMMIT")
        except Exception:
            try:
                self.db.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise

    # ---------------------------------------------------------------- targets
    def add_target(self, target_id: str, address: str, label: str = "", public_key: Optional[str] = None) -> None:
        """Discovery/candidate creation. A target is NOT actionable until an
        operator pins its identity with approve_target()."""
        if self.target(target_id) is None:
            self.db.execute(
                "INSERT INTO targets(target_id,label,address,status,public_key,state,created_ts) "
                "VALUES(?,?,?, 'enabled', ?, 'candidate', ?)",
                (target_id, label, address, public_key, int(time.time())),
            )
            return
        current = self.target(target_id)
        bumped = 1 if current["address"] != address else 0
        self.db.execute(
            "UPDATE targets SET address=?, label=?, endpoint_revision=endpoint_revision+? WHERE target_id=?",
            (address, label, bumped, target_id),
        )

    def approve_target(self, target_id: str, public_key: str, fingerprint: str, approval_digest: str) -> None:
        """Out-of-band approval: pin the verified key fingerprint. The address is
        never part of identity, so this survives routing changes."""
        row = self.target(target_id)
        if row is None:
            raise Denied("unknown_target", target_id=target_id)
        try:
            actual = sha256_hex(bytes.fromhex(public_key))
        except ValueError:
            raise Denied("malformed_public_key")
        if actual != fingerprint:
            raise Denied("fingerprint_mismatch", computed=actual)
        if row["state"] == "approved" and row["key_fingerprint"] != fingerprint:
            raise Denied("target_already_approved", existing=row["key_fingerprint"])
        self.db.execute(
            "UPDATE targets SET public_key=?, key_fingerprint=?, identity_algorithm='ed25519', "
            "state='approved', approval_digest=?, approved_ts=? WHERE target_id=?",
            (public_key, fingerprint, approval_digest, int(time.time()), target_id),
        )

    def revoke_target(self, target_id: str) -> None:
        """Atomic revocation: state + revision + lease + unused tokens together.

        Already-running external work cannot be undone; this stops new and
        unused authority and forces outstanding requests onto a stale revision.
        """
        self.db.execute("BEGIN IMMEDIATE")
        try:
            cur = self.db.execute(
                "UPDATE targets SET state='revoked' WHERE target_id=? AND state!='revoked'", (target_id,)
            )
            if cur.rowcount != 1:
                exists = self.target(target_id)
                self.db.execute("ROLLBACK")
                if exists is None:
                    raise Denied("unknown_target", target_id=target_id)
                raise Denied("already_revoked", target_id=target_id)
            self.db.execute("UPDATE enrollments SET revision=revision+1 WHERE target_id=?", (target_id,))
            self.db.execute("UPDATE leases SET expires_ts=0 WHERE target_id=?", (target_id,))
            self.db.execute("UPDATE tokens SET used=1 WHERE target_id=? AND used=0", (target_id,))
            self.db.execute("COMMIT")
        except Exception:
            try:
                self.db.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        row = self.target(target_id)
        self.append_decision({
            "allow": False, "reason": "target_revoked", "caller": "operator", "action": "",
            "target_id": target_id, "params": {}, "policy_digest": "", "enrollment_revision": 0,
            "nonce": "", "key_fingerprint": row["key_fingerprint"] if row else "",
        })

    def set_target_address(self, target_id: str, address: str) -> int:
        cur = self.db.execute(
            "UPDATE targets SET address=?, endpoint_revision=endpoint_revision+1 WHERE target_id=?",
            (address, target_id),
        )
        if cur.rowcount != 1:
            raise Denied("unknown_target", target_id=target_id)
        return int(self.target(target_id)["endpoint_revision"])

    def set_target_endpoint(self, target_id: str, port: int) -> int:
        """Routing metadata only: where the agent listens. Not identity."""
        cur = self.db.execute(
            "UPDATE targets SET transport_port=?, endpoint_revision=endpoint_revision+1 WHERE target_id=?",
            (int(port), target_id),
        )
        if cur.rowcount != 1:
            raise Denied("unknown_target", target_id=target_id)
        return int(self.target(target_id)["endpoint_revision"])

    def targets(self) -> list:
        return list(self.db.execute("SELECT * FROM targets ORDER BY target_id"))

    def target(self, target_id: str):
        return self.db.execute("SELECT * FROM targets WHERE target_id=?", (target_id,)).fetchone()

    # ------------------------------------------------------------ enrollments
    def enroll(self, pod_name: str, target_id: str, caps: list) -> int:
        target = self.target(target_id)
        if target is None:
            raise Denied("unknown_target", target_id=target_id)
        if target["state"] != "approved" or not target["public_key"]:
            raise Denied("target_not_approved", state=target["state"])
        try:
            self.db.execute(
                "INSERT INTO enrollments(pod_name,target_id,caps,status,revision,created_ts) "
                "VALUES(?,?,?, 'enabled', 1, ?)",
                (pod_name, target_id, ",".join(sorted(set(caps))), int(time.time())),
            )
        except sqlite3.IntegrityError:
            raise Denied("enrollment_conflict_one_target_one_pod")
        row = self.db.execute("SELECT revision FROM enrollments WHERE pod_name=?", (pod_name,)).fetchone()
        return int(row["revision"])

    def set_enrollment_status(self, pod_name: str, status: str) -> int:
        cur = self.db.execute(
            "UPDATE enrollments SET status=?, revision=revision+1 WHERE pod_name=?", (status, pod_name)
        )
        if cur.rowcount != 1:
            raise Denied("not_enrolled", pod=pod_name)
        return int(self.enrollment_by_pod(pod_name)["revision"])

    def enrollment_by_pod(self, pod_name: str):
        return self.db.execute("SELECT * FROM enrollments WHERE pod_name=?", (pod_name,)).fetchone()

    def enrollment_by_target(self, target_id: str):
        return self.db.execute("SELECT * FROM enrollments WHERE target_id=?", (target_id,)).fetchone()

    def enrollments(self) -> list:
        return list(self.db.execute("SELECT * FROM enrollments ORDER BY pod_name"))

    # ------------------------------------------------------------------ leases
    def acquire_lease(self, target_id: str, owner: str, action: str, ttl_s: int, idem_key: str) -> dict:
        """Exclusive per target. Idempotent for the same idem_key; otherwise
        denies while an unexpired lease exists. Fencing is monotonic."""
        now = int(time.time())
        self.db.execute("BEGIN IMMEDIATE")
        try:
            cur = self.db.execute(
                "SELECT * FROM leases WHERE target_id=? AND expires_ts>?", (target_id, now)
            ).fetchone()
            if cur is not None:
                if cur["idem_key"] == idem_key:
                    self.db.execute("COMMIT")
                    return {"fencing": int(cur["fencing"]), "expires_ts": int(cur["expires_ts"]), "reused": True}
                self.db.execute("ROLLBACK")
                raise Denied("lease_held_by_other", owner=cur["owner"])
            row = self.db.execute("SELECT MAX(fencing) AS f FROM leases WHERE target_id=?", (target_id,)).fetchone()
            fencing = int(row["f"] or 0) + 1
            self.db.execute(
                "INSERT INTO leases(target_id,fencing,owner,action,idem_key,issued_ts,expires_ts) "
                "VALUES(?,?,?,?,?,?,?) ON CONFLICT(target_id) DO UPDATE SET "
                "fencing=excluded.fencing, owner=excluded.owner, action=excluded.action, "
                "idem_key=excluded.idem_key, issued_ts=excluded.issued_ts, expires_ts=excluded.expires_ts",
                (target_id, fencing, owner, action, idem_key, now, now + int(ttl_s)),
            )
            self.db.execute("COMMIT")
        except Exception:
            try:
                self.db.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        return {"fencing": fencing, "expires_ts": now + int(ttl_s), "reused": False}

    def current_fencing(self, target_id: str) -> int:
        row = self.db.execute("SELECT fencing FROM leases WHERE target_id=?", (target_id,)).fetchone()
        return int(row["fencing"]) if row else 0

    # ---------------------------------------------------------------- requests
    def record_request(self, req_digest: str, nonce: str, caller: str, action: str, target_id: str) -> None:
        try:
            self.db.execute(
                "INSERT INTO requests(req_digest,nonce,caller,action,target_id,issued_ts,outcome) "
                "VALUES(?,?,?,?,?,?, 'pending')",
                (req_digest, nonce, caller, action, target_id, int(time.time())),
            )
        except sqlite3.IntegrityError:
            raise Denied("replay", nonce=nonce)

    def settle_request(self, req_digest: str, outcome: str, reason: str, decision_id: str) -> None:
        self.db.execute(
            "UPDATE requests SET outcome=?, reason=?, decision_id=? WHERE req_digest=?",
            (outcome, reason, decision_id, req_digest),
        )

    # --------------------------------------------------------------- decisions
    def append_decision(self, record: dict) -> str:
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute("SELECT decision_id FROM decisions ORDER BY seq DESC LIMIT 1").fetchone()
            prev = row["decision_id"] if row else GENESIS
            rec = dict(record)
            rec["prev"] = prev
            did = digest(rec)
            rec["decision_id"] = did
            self.db.execute(
                "INSERT INTO decisions(decision_id,prev,record,ts) VALUES(?,?,?,?)",
                (did, prev, json.dumps(rec, sort_keys=True, separators=(",", ":")), int(time.time())),
            )
            self.db.execute("COMMIT")
        except Exception:
            try:
                self.db.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        self.db.execute("INSERT OR REPLACE INTO checkpoints(seq,head,ts) VALUES(1,?,?)", (did, int(time.time())))
        return did

    def decisions(self, limit: int = 20) -> list:
        return list(self.db.execute("SELECT * FROM decisions ORDER BY seq DESC LIMIT ?", (limit,)))

    def verify_chain(self) -> tuple:
        prev = GENESIS
        n = 0
        for row in self.db.execute("SELECT record FROM decisions ORDER BY seq"):
            rec = json.loads(row["record"])
            did = rec.pop("decision_id")
            if rec.get("prev") != prev or digest(rec) != did:
                return False, prev, n
            prev = did
            n += 1
        return True, prev, n

    def head(self) -> str:
        ok, head, _ = self.verify_chain()
        return head if ok else ""

    # ------------------------------------------------------------------ tokens
    def mint_token(self, token_digest: str, decision_id: str, target_id: str, action: str, fencing: int, expires_ts: int) -> None:
        self.db.execute(
            "INSERT INTO tokens(token_digest,decision_id,target_id,action,fencing,expires_ts,used) "
            "VALUES(?,?,?,?,?,?,0)",
            (token_digest, decision_id, target_id, action, fencing, expires_ts),
        )

    def claim_run(self, token_digest: str, target_id: str, action: str, fencing: int, run_id: str, pod: str) -> None:
        """Consume the token and record the run in ONE transaction.

        Re-checks the current fence inside the transaction, so a stale runner
        cannot consume a token that a newer lease has superseded. If this
        returns, the token is used exactly once and a run row exists.
        """
        now = int(time.time())
        self.db.execute("BEGIN IMMEDIATE")
        try:
            lease = self.db.execute("SELECT fencing FROM leases WHERE target_id=?", (target_id,)).fetchone()
            if lease is None or int(lease["fencing"]) != int(fencing):
                self.db.execute("ROLLBACK")
                raise Denied("stale_fencing")
            cur = self.db.execute(
                "UPDATE tokens SET used=1 WHERE token_digest=? AND used=0 AND expires_ts>=? "
                "AND target_id=? AND action=? AND fencing=?",
                (token_digest, now, target_id, action, int(fencing)),
            )
            if cur.rowcount != 1:
                self.db.execute("ROLLBACK")
                raise Denied("token_invalid_or_used")
            self.db.execute(
                "INSERT INTO runs(run_id,target_id,action,fencing,pod,state,started_ts) "
                "VALUES(?,?,?,?,?, 'running', ?)",
                (run_id, target_id, action, int(fencing), pod, now),
            )
            self.db.execute("COMMIT")
        except Exception:
            try:
                self.db.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise

    # -------------------------------------------------------------------- runs
    def finish_run(self, run_id: str, state: str, result_digest: str = "") -> None:
        self.db.execute(
            "UPDATE runs SET state=?, ended_ts=?, result_digest=? WHERE run_id=?",
            (state, int(time.time()), result_digest, run_id),
        )

    def reconcile_runs(self, timeout_s: int = 300) -> int:
        """Runs left running/claimed past the timeout have an unknown outcome."""
        cutoff = int(time.time()) - int(timeout_s)
        cur = self.db.execute(
            "UPDATE runs SET state='outcome_unknown', ended_ts=? WHERE state IN ('claimed','running') AND started_ts<?",
            (int(time.time()), cutoff),
        )
        return int(cur.rowcount)

    def runs(self, limit: int = 20) -> list:
        return list(self.db.execute("SELECT * FROM runs ORDER BY started_ts DESC LIMIT ?", (limit,)))

    # ------------------------------------------------------------ observations
    def add_observation(self, target_id: str, kind: str, value: str) -> None:
        self.db.execute(
            "INSERT INTO observations(target_id,kind,value,ts) VALUES(?,?,?,?)",
            (target_id, kind, value, int(time.time())),
        )

    def last_observation(self, target_id: str, kind: str):
        return self.db.execute(
            "SELECT * FROM observations WHERE target_id=? AND kind=? ORDER BY obs_id DESC LIMIT 1",
            (target_id, kind),
        ).fetchone()

    def checkpoint_head(self) -> tuple:
        row = self.db.execute("SELECT head FROM checkpoints WHERE seq=1").fetchone()
        return (1, row["head"]) if row else (0, GENESIS)
