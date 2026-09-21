"""broker.stress — destructive operational tests.

These are the tests the failure matrix cannot reach from one process: real
concurrent CLI processes, SIGKILL at each persistence boundary, clock-skewed
requests and a migration over a pre-existing database.

Each test provisions its own target so leases never bleed across tests.

Run: broker stress   (or python3 -m broker.stress)
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from . import agent, crypto, gate, mtls
from .canon import canonical
from .store import Denied, Store

PKG_ROOT = str(Path(__file__).resolve().parents[1])
PASS = 0
FAIL = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  PASS {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name} {detail}")


def cli(args, env, timeout=60):
    proc = subprocess.run([sys.executable, "-m", "broker", *args], cwd=PKG_ROOT, env=env,
                          capture_output=True, text=True, timeout=timeout)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def spawn(args, env):
    return subprocess.Popen([sys.executable, "-m", "broker", *args], cwd=PKG_ROOT, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def runs_for(env, tid):
    _, out = cli(["runs", "-n", "20"], env)
    return "\n".join(line for line in out.splitlines() if f'"target_id": "{tid}"' in line)


def add_target(env, keydir, tid, address="127.0.0.1"):
    cli(["target-add", "--id", tid, "--address", address, "--label", tid], env)
    _, keyed = cli(["target-keygen", "--out", str(keydir / f"{tid}.pem")], env)
    info = json.loads(keyed)
    cli(["target-approve", "--id", tid, "--public-key", info["public_key"],
         "--fingerprint", info["fingerprint"]], env)
    cli(["enroll", "--pod", f"pod-{tid}", "--target", tid, "--caps", "ping,inventory"], env)
    _thread, port = agent.start(address, info["certificate"], info["private_key"], str(keydir / "gate-tls.crt"))
    cli(["target-endpoint", "--id", tid, "--port", str(port)], env)
    return info, port


def main() -> int:
    global PASS, FAIL
    PASS = FAIL = 0
    print("broker stress — destructive operational tests")

    with tempfile.TemporaryDirectory(prefix="broker-stress-") as tmp:
        tmp = Path(tmp)
        home, keydir = tmp / "home", tmp / "keys"
        env = dict(os.environ, PYTHONPATH=PKG_ROOT, BROKER_HOME=str(home), BROKER_KEYDIR=str(keydir))
        rc, out = cli(["init"], env)
        if rc != 0:
            print(f"  FAIL init: {out[-200:]}")
            return 1

        print("-- concurrent leases across processes")
        add_target(env, keydir, "tlease")
        procs = [spawn(["lease", "--target", "tlease", "--action", "ping", "--token-only"], env) for _ in range(12)]
        wins = 0
        for proc in procs:
            stdout, _ = proc.communicate(timeout=60)
            if proc.returncode == 0 and stdout.strip().count(".") == 1:
                wins += 1
        check("exactly one of 12 concurrent leases wins", wins == 1, f"(wins={wins})")

        print("-- concurrent token consumption")
        add_target(env, keydir, "tconsume")
        _, token = cli(["lease", "--target", "tconsume", "--action", "ping", "--token-only"], env)
        token = token.strip()
        racers = [spawn(["run", "--token", token, "--target", "tconsume", "--action", "ping", "--pod", "pod-tconsume"], env)
                  for _ in range(2)]
        results = [p.communicate(timeout=60) + (p.returncode,) for p in racers]
        ok_count = sum(1 for _, _, rc in results if rc == 0)
        refused = sum(1 for out, _, rc in results if rc != 0 and "token_invalid_or_used" in out)
        check("exactly one concurrent consumer wins", ok_count == 1 and refused == 1, f"(ok={ok_count}, refused={refused})")

        print("-- proof of possession at use")
        _, good_port = add_target(env, keydir, "tpop")
        decoy_key, decoy_cert = str(keydir / "decoy.key"), str(keydir / "decoy.crt")
        mtls.generate_identity(decoy_cert, decoy_key, "decoy")
        _thread, decoy_port = agent.start("127.0.0.1", decoy_cert, decoy_key, str(keydir / "gate-tls.crt"))
        cli(["target-endpoint", "--id", "tpop", "--port", str(decoy_port)], env)
        _, token = cli(["lease", "--target", "tpop", "--action", "ping", "--token-only"], env)
        rc, out = cli(["run", "--token", token.strip(), "--target", "tpop", "--action", "ping", "--pod", "pod-tpop"], env)
        check("live peer with the wrong key is refused", rc != 0 and "target_identity_mismatch" in out, out[-180:])
        runs = runs_for(env, "tpop")
        check("PoP failure records no run", '"state": "done"' not in runs, runs[-180:])
        cli(["target-endpoint", "--id", "tpop", "--port", str(good_port)], env)
        rc, out = cli(["run", "--token", token.strip(), "--target", "tpop", "--action", "ping", "--pod", "pod-tpop"], env)
        check("token survives a PoP failure unconsumed", rc == 0 and '"state": "done"' in out, out[-180:])

        print("-- crash after claim")
        add_target(env, keydir, "tclaim")
        _, token = cli(["lease", "--target", "tclaim", "--action", "ping", "--token-only"], env)
        crash_env = dict(env, BROKER_FAILPOINT="after_claim")
        rc, out = cli(["run", "--token", token.strip(), "--target", "tclaim", "--action", "ping"], crash_env)
        check("process is killed at the claim boundary", rc != 0, f"(rc={rc})")
        runs = runs_for(env, "tclaim")
        check("crash leaves the run running, never done", '"state": "running"' in runs and '"state": "done"' not in runs, runs[-200:])
        cli(["reconcile", "--timeout=-1"], env)
        runs = runs_for(env, "tclaim")
        check("reconcile resolves the claim to outcome_unknown", '"state": "outcome_unknown"' in runs, runs[-200:])

        print("-- crash after the external effect, before the result is durable")
        add_target(env, keydir, "taction")
        _, token = cli(["lease", "--target", "taction", "--action", "ping", "--token-only"], env)
        token = token.strip()
        crash_env = dict(env, BROKER_FAILPOINT="after_action")
        rc, out = cli(["run", "--token", token, "--target", "taction", "--action", "ping"], crash_env)
        check("process is killed after the action", rc != 0, f"(rc={rc})")
        runs = runs_for(env, "taction")
        check("completed-but-unrecorded action is not marked done", '"state": "done"' not in runs, runs[-200:])
        rc, out = cli(["run", "--token", token, "--target", "taction", "--action", "ping"], env)
        check("consumed token cannot replay the action", rc != 0 and "token_invalid_or_used" in out, out[-200:])
        cli(["reconcile", "--timeout=-1"], env)
        runs = runs_for(env, "taction")
        check("unknown outcome is surfaced, not fabricated", '"state": "outcome_unknown"' in runs, runs[-200:])

        print("-- clock-skewed requests")
        add_target(env, keydir, "tclock")
        store = Store(str(home / "broker.db"))
        keys = gate.load_keys(str(home / "trusted_keys.json"))
        policy, pdigest, _ = gate.load_policy(str(home / "policy.json"), keys)
        rev = int(store.enrollment_by_target("tclock")["revision"])
        rot_key = str(keydir / "rotator.pem")
        gate_key = str(keydir / "gate.pem")

        def signed(req):
            return crypto.sign_hex(rot_key, canonical(req))

        stale = gate.build_request("rotator", "ping", "tclock", {}, pdigest, rev, "n-stale")
        stale["issued_at"] = int(time.time()) - 1000
        check("stale request denied", gate.authorize(store, policy, keys, stale, signed(stale), "o", gate_key)["reason"] == "stale_request")
        fut = gate.build_request("rotator", "ping", "tclock", {}, pdigest, rev, "n-future")
        fut["issued_at"] = int(time.time()) + 1000
        check("future-dated request denied", gate.authorize(store, policy, keys, fut, signed(fut), "o", gate_key)["reason"] == "stale_request")
        exp = gate.build_request("rotator", "ping", "tclock", {}, pdigest, rev, "n-exp")
        exp["expiry"] = int(time.time()) - 5
        check("expired request denied", gate.authorize(store, policy, keys, exp, signed(exp), "o", gate_key)["reason"] == "expired_request")
        store.close()

        print("-- migration of a pre-existing database")
        old = tmp / "old.db"
        conn = sqlite3.connect(str(old))
        conn.execute("CREATE TABLE targets(target_id TEXT PRIMARY KEY,label TEXT NOT NULL DEFAULT '',"
                     "address TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'enabled',created_ts INTEGER NOT NULL)")
        conn.execute("INSERT INTO targets VALUES('old','la\tb','','enabled',0)")
        conn.commit()
        conn.close()
        first = Store(str(old))
        first.close()
        second = Store(str(old))  # idempotent re-open
        row = second.target("old")
        check("migrated row is a candidate", row["state"] == "candidate")
        check("migrated row has no key and revision 1", row["public_key"] is None and int(row["endpoint_revision"]) == 1)
        check("migration is idempotent", {r["name"] for r in second.db.execute("PRAGMA table_info(targets)")} >=
              {"state", "public_key", "key_fingerprint", "endpoint_revision", "approval_digest"})
        try:
            second.enroll("pod-old", "old", ["ping"])
            check("migrated target cannot enroll unapproved", False)
        except Denied as exc:
            check("migrated target cannot enroll unapproved", exc.reason == "target_not_approved")
        second.close()

        print("-- persisted-state corruption")
        bad = tmp / "corrupt.db"
        healthy = Store(str(bad))
        healthy.add_target("x", "127.0.0.1", "will corrupt")
        healthy.close()
        with open(bad, "r+b") as handle:
            handle.seek(0)
            handle.write(b"\xde\xad\xbe\xef")  # clobber the SQLite header magic
        try:
            Store(str(bad))
            check("corrupted database is rejected on open", False, "(opened without error)")
        except Exception:
            check("corrupted database is rejected on open", True)
        print("  NOTE WAL truncation presents as rollback (lost frames look like an older commit); "
              "detecting it requires the external witness, which does not exist yet")

    print(f"\nRESULT: {PASS} pass, {FAIL} fail")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
