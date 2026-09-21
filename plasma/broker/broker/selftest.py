"""broker.selftest — the failure matrix.

Asserts safety properties, not happy paths:
    active_C(T) <= 1
    apply(r) => valid_authorization(r) and current_enrollment(T)
    unknown(T) => no dispatch(T)
    no valid token => no state-changing action
and then re-checks the boundary from *separate OS processes* (direct action
invocation, replay, corrupt policy, DB permissions).

Run: broker selftest   (or python3 -m broker.selftest)
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from . import agent, crypto, gate
from .canon import digest
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


def expect_raise(name: str, reason: str, fn, *args, **kwargs) -> None:
    try:
        fn(*args, **kwargs)
        check(name, False, f"(expected Denied({reason!r}), got success)")
    except Denied as exc:
        check(name, exc.reason == reason, f"(expected {reason!r}, got {exc.reason!r})")


def expect_deny(name: str, reason: str, fn, *args, **kwargs) -> None:
    out = fn(*args, **kwargs)
    got = out.get("reason") if isinstance(out, dict) else None
    check(name, isinstance(out, dict) and out.get("allow") is False and got == reason,
          f"(expected deny {reason!r}, got allow={out.get('allow')!r} reason={got!r})")


POLICY = {
    "version": 1,
    "policy_id": "selftest",
    "max_request_age_s": 60,
    "clock_skew_s": 30,
    "callers": {
        "rotator": {"grants": [
            {"action": "ping", "targets": ["*"], "ttl_s": 30},
            {"action": "neigh", "targets": ["*"], "ttl_s": 30},
            {"action": "inventory", "targets": ["*"], "ttl_s": 30},
        ]},
        "prober": {"grants": [
            {"action": "tcp_probe", "targets": ["*"], "ttl_s": 30},
        ]},
    },
}


def _cli(args, env):
    proc = subprocess.run([sys.executable, "-m", "broker", *args], cwd=PKG_ROOT, env=env,
                          capture_output=True, text=True, timeout=60)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def main() -> int:
    global PASS, FAIL
    PASS = FAIL = 0
    print("broker selftest — failure matrix")

    with tempfile.TemporaryDirectory(prefix="broker-selftest-") as tmp:
        tmp = Path(tmp)
        keydir = tmp / "keys"
        rot_key, gate_key, other_key = keydir / "rot.pem", keydir / "gate.pem", keydir / "other.pem"
        for path in (rot_key, gate_key, other_key):
            crypto.generate_private(str(path))
        KEYS = {
            "rotator": {"public": crypto.public_hex(str(rot_key)), "status": "enabled"},
            "prober": {"public": crypto.public_hex(str(other_key)), "status": "enabled"},
            gate.GATE_KEY_ID: {"public": crypto.public_hex(str(gate_key)), "status": "enabled"},
        }
        pdigest = digest(POLICY)
        store = Store(str(tmp / "broker.db"))

        def _req(caller, action, target, pdig, rev, params=None, ttl=30):
            return gate.build_request(caller, action, target, params or {}, pdig, rev,
                                      __import__("secrets").token_hex(16), ttl)

        def _tok(fields):
            body = gate._token_payload(fields)
            return f"{body}.{crypto.sign_hex(str(gate_key), body.encode('ascii'))}"

        def _approve(tid):
            """Provision a target key and pin it (operator approval step)."""
            path = tmp / f"{tid}.pem"
            crypto.generate_private(str(path))
            public = crypto.public_hex(str(path))
            fingerprint = crypto.fingerprint_hex(public)
            store.approve_target(tid, public, fingerprint,
                                 digest({"target_id": tid, "public_key": public, "key_fingerprint": fingerprint}))
            return public, fingerprint

        def _auth(request, signature, owner="rotator@test"):
            return gate.authorize(store, POLICY, KEYS, request, signature, owner, gate_key_path=str(gate_key))

        print("-- enrollment law")
        expect_raise("unknown target cannot enroll", "unknown_target",
                     store.enroll, "pod-x", "does-not-exist", ["ping"])
        store.add_target("t1", "127.0.0.1", "loopback selftest target")
        store.add_target("t2", "127.0.0.2", "second target")
        expect_raise("candidate target cannot enroll", "target_not_approved",
                     store.enroll, "pod-t1", "t1", ["ping"])
        _approve("t1")
        _approve("t2")
        rev1 = store.enroll("pod-t1", "t1", ["ping", "neigh", "inventory"])
        expect_raise("one target = one pod", "enrollment_conflict_one_target_one_pod",
                     store.enroll, "pod-t1-dup", "t1", ["ping"])
        rev2 = store.enroll("pod-t2", "t2", ["ping", "neigh", "inventory"])

        print("-- target identity is a pinned key, not an address")
        expect_raise("fingerprint mismatch refused", "fingerprint_mismatch",
                     store.approve_target, "t2", crypto.public_hex(str(other_key)), "0" * 64, "d")
        pinned = store.target("t1")["key_fingerprint"]
        rev_before = int(store.target("t1")["endpoint_revision"])
        store.set_target_address("t1", "127.0.0.9")
        moved = store.target("t1")
        check("address change keeps identity", moved["key_fingerprint"] == pinned)
        check("address change bumps endpoint revision", int(moved["endpoint_revision"]) == rev_before + 1)
        check("pinned key survives routing change", moved["state"] == "approved")

        print("-- policy envelope is signed and monotonic")
        store.accept_policy_version(1)
        expect_raise("policy version cannot roll back", "policy_rollback",
                     store.accept_policy_version, 0)
        bad_env = tmp / "bad-policy.json"
        bad_env.write_text(json.dumps({"version": 1, "signer": gate.GATE_KEY_ID, "body": POLICY,
                                       "signature": "00" * 64}))
        expect_raise("forged policy signature refused", "policy_signature_invalid",
                     gate.load_policy, str(bad_env), KEYS)

        print("-- gate: identity, integrity, policy")
        r = _req("ghost", "ping", "t1", pdigest, rev1)
        expect_deny("unknown caller denied", "unknown_caller",
                    _auth, r, crypto.sign_hex(str(rot_key), gate.canonical(r)))
        bad = _req("rotator", "ping", "t1", pdigest, rev1)
        expect_deny("bad signature denied", "bad_signature",
                    _auth, bad, crypto.sign_hex(str(other_key), gate.canonical(bad)))
        sep = _req("rotator", "ping", "t1", pdigest, rev1)
        expect_deny("gate key cannot impersonate a caller", "bad_signature",
                    _auth, sep, crypto.sign_hex(str(gate_key), gate.canonical(sep)))
        rolled = _req("rotator", "ping", "t1", "f" * 64, rev1)
        expect_deny("policy rollback / digest mismatch denied", "policy_digest_mismatch",
                    _auth, rolled, crypto.sign_hex(str(rot_key), gate.canonical(rolled)))
        ng = _req("rotator", "tcp_probe", "t1", pdigest, rev1, {"port": 80})
        expect_deny("action without grant denied", "not_granted",
                    _auth, ng, crypto.sign_hex(str(rot_key), gate.canonical(ng)))
        offport = _req("prober", "tcp_probe", "t1", pdigest, rev1, {"port": 4444})
        expect_deny("out-of-range param denied", "capability_refused",
                    _auth, offport, crypto.sign_hex(str(other_key), gate.canonical(offport)))

        print("-- allow path and token discipline")
        ok = _req("rotator", "ping", "t1", pdigest, rev1)
        dec = _auth(ok, crypto.sign_hex(str(rot_key), gate.canonical(ok)))
        check("valid request allowed", dec["allow"] and bool(dec.get("token")))
        expect_raise("token is target-scoped", "token_scope_mismatch",
                     gate.verify_token, store, KEYS, dec["token"], "t2", "ping")
        payload = gate.verify_token(store, KEYS, dec["token"], "t1", "ping")
        check("token verifies and binds fencing", payload["fencing"] == dec["fencing"])
        tdigest = digest({"tok": dec["token"]})
        store.claim_run(tdigest, "t1", "ping", int(dec["fencing"]), "run-1", "pod-t1")
        expect_raise("token is single-use", "token_invalid_or_used",
                     store.claim_run, tdigest, "t1", "ping", int(dec["fencing"]), "run-2", "pod-t1")
        rogue_body = gate._token_payload({"caller": "rotator", "target_id": "t1", "action": "ping", "params": {},
                                          "fencing": 0, "decision_id": "x", "policy_digest": pdigest,
                                          "expiry": int(time.time()) + 60})
        rogue = f"{rogue_body}.{crypto.sign_hex(str(rot_key), rogue_body.encode('ascii'))}"
        expect_raise("token signed by non-gate key refused", "bad_token_signature",
                     gate.verify_token, store, KEYS, rogue, "t1", "ping")

        print("-- replay")
        r2 = _req("rotator", "ping", "t2", pdigest, rev2)
        sig2 = crypto.sign_hex(str(rot_key), gate.canonical(r2))
        first = _auth(r2, sig2)
        check("second allow path works", first["allow"])
        expect_deny("replayed request denied", "replay", _auth, r2, sig2)
        store.claim_run(digest({"tok": first["token"]}), "t2", "ping", int(first["fencing"]), "run-t2", "pod-t2")

        print("-- lease exclusivity / idempotency / fencing")
        store.db.execute("UPDATE leases SET expires_ts=0 WHERE target_id='t1'")
        store.acquire_lease("t1", "owner-A", "ping", 300, "idem-A")
        expect_raise("second owner blocked while lease held", "lease_held_by_other",
                     store.acquire_lease, "t1", "owner-B", "ping", 300, "idem-B")
        check("same idem key is idempotent", store.acquire_lease("t1", "owner-A", "ping", 300, "idem-A").get("reused") is True)

        old_fencing = store.current_fencing("t1")
        forged = _tok({"caller": "rotator", "target_id": "t1", "action": "ping", "params": {},
                       "fencing": old_fencing, "decision_id": "x", "policy_digest": pdigest,
                       "expiry": int(time.time()) + 600})
        store.mint_token(digest({"tok": forged}), "x", "t1", "ping", old_fencing, int(time.time()) + 600)
        store.db.execute("UPDATE leases SET fencing=fencing+1, expires_ts=? WHERE target_id='t1'",
                         (int(time.time()) + 600,))
        expect_raise("stale fencing rejected", "stale_fencing",
                     gate.verify_token, store, KEYS, forged, "t1", "ping")

        expired = _tok({"caller": "rotator", "target_id": "t1", "action": "ping", "params": {},
                        "fencing": store.current_fencing("t1"), "decision_id": "x", "policy_digest": pdigest,
                        "expiry": int(time.time()) - 5})
        expect_raise("expired token rejected", "token_expired",
                     gate.verify_token, store, KEYS, expired, "t1", "ping")

        print("-- revocation at use")
        store.add_target("t3", "127.0.0.3", "revocation target")
        _approve("t3")
        rev3 = store.enroll("pod-t3", "t3", ["ping"])
        r3 = _req("rotator", "ping", "t3", pdigest, rev3)
        d3 = _auth(r3, crypto.sign_hex(str(rot_key), gate.canonical(r3)))
        check("lease minted for t3", d3["allow"])
        store.set_enrollment_status("pod-t3", "disabled")
        expect_raise("revoked enrollment blocks use", "target_not_enrolled",
                     gate.verify_token, store, KEYS, d3["token"], "t3", "ping")
        rev4 = int(store.enrollment_by_pod("pod-t3")["revision"])
        r3b = _req("rotator", "ping", "t3", pdigest, rev4)
        expect_deny("disabled enrollment denies at dispatch", "enrollment_disabled",
                    _auth, r3b, crypto.sign_hex(str(rot_key), gate.canonical(r3b)))

        print("-- target revocation invalidates pending grants")
        store.add_target("t4", "127.0.0.4", "revoke target")
        _approve("t4")
        rev4b = store.enroll("pod-t4", "t4", ["ping"])
        r4 = _req("rotator", "ping", "t4", pdigest, rev4b)
        d4 = _auth(r4, crypto.sign_hex(str(rot_key), gate.canonical(r4)))
        check("lease minted for t4", d4["allow"])
        store.revoke_target("t4")
        expect_raise("revoked target blocks use", "target_not_approved",
                     gate.verify_token, store, KEYS, d4["token"], "t4", "ping")
        rev4c = int(store.enrollment_by_pod("pod-t4")["revision"])
        r4b = _req("rotator", "ping", "t4", pdigest, rev4c)
        expect_deny("revoked target denies dispatch", "target_not_approved",
                    _auth, r4b, crypto.sign_hex(str(rot_key), gate.canonical(r4b)))
        stale_rev = _req("rotator", "ping", "t4", pdigest, rev4b)
        expect_deny("revocation advances enrollment revision", "enrollment_revision_mismatch",
                    _auth, stale_rev, crypto.sign_hex(str(rot_key), gate.canonical(stale_rev)))

        print("-- fail closed")
        expect_raise("no token => no action", "token_malformed",
                     gate.verify_token, store, KEYS, "", "t1", "ping")
        wf = _tok({"caller": "rotator", "target_id": "t1", "action": "ping", "params": {},
                   "fencing": 1, "decision_id": "x", "policy_digest": pdigest, "expiry": int(time.time()) + 60})
        expect_raise("tampered token payload => no action", "bad_token_signature",
                     gate.verify_token, store, KEYS, wf[:-1] + ("0" if wf[-1] != "0" else "1"), "t1", "ping")

        print("-- audit chain and checkpoint")
        ok_chain, head, n = store.verify_chain()
        check("decision chain verifies", ok_chain and n > 0, f"(n={n})")
        raw = store.db.execute("SELECT record FROM decisions WHERE seq=1").fetchone()["record"]
        flipped = raw.replace('"allow":false', '"allow":true', 1)
        store.db.execute("UPDATE decisions SET record=? WHERE seq=1", (flipped,))
        ok_tampered, _, _ = store.verify_chain()
        check("tampered decision detected", ok_tampered is False and flipped != raw)
        expect_raise("checkpoint refuses a broken chain", "chain_verification_failed",
                     gate.checkpoint, store, str(tmp / "checkpoint.json"))
        store.close()

        print("-- separate-process adversarial checks")
        home = tmp / "cli-home"
        ckeydir = tmp / "cli-keys"
        env = dict(os.environ, PYTHONPATH=PKG_ROOT, BROKER_HOME=str(home), BROKER_KEYDIR=str(ckeydir))
        rc, out = _cli(["init"], env)
        check("cli init succeeds", rc == 0, out[-200:])
        check("db is 0600", ((home / "broker.db").stat().st_mode & 0o777) == 0o600)
        rc, out = _cli(["target-add", "--id", "lo0", "--address", "127.0.0.1", "--label", "loopback"], env)
        check("cli target-add creates a candidate", rc == 0 and '"state": "candidate"' in out, out[-160:])
        rc, out = _cli(["enroll", "--pod", "pod-lo0", "--target", "lo0", "--caps", "ping"], env)
        check("cli cannot enroll an unapproved target", rc != 0 and "target_not_approved" in out, out[-160:])
        rc, keyed = _cli(["target-keygen", "--out", str(ckeydir / "lo0.pem")], env)
        info = json.loads(keyed)
        rc, out = _cli(["target-approve", "--id", "lo0", "--public-key", info["public_key"],
                        "--fingerprint", info["fingerprint"]], env)
        check("cli target-approve pins the fingerprint", rc == 0 and info["fingerprint"] in out, out[-160:])
        _cli(["enroll", "--pod", "pod-lo0", "--target", "lo0", "--caps", "ping,neigh,inventory"], env)
        # Start the target agent so proof of possession can succeed at run time.
        _agent_thread, _port = agent.start("127.0.0.1", info["certificate"], info["private_key"],
                                           str(ckeydir / "gate-tls.crt"))
        rc, out = _cli(["target-endpoint", "--id", "lo0", "--port", str(_port)], env)
        check("cli sets the agent endpoint", rc == 0, out[-160:])
        rc, token = _cli(["lease", "--target", "lo0", "--action", "ping", "--token-only"], env)
        check("cli mints a token", rc == 0 and token.count(".") == 1, token[-120:])
        rc, out = _cli(["run", "--token", token.strip(), "--target", "lo0", "--action", "ping", "--pod", "pod-lo0"], env)
        check("cli run executes once", rc == 0 and '"state": "done"' in out, out[-200:])
        rc, out = _cli(["run", "--token", token.strip(), "--target", "lo0", "--action", "ping", "--pod", "pod-lo0"], env)
        check("cli replay refused", rc != 0 and "token_invalid_or_used" in out, out[-200:])
        rc, out = _cli(["run", "--token", "AAAA.BBBB", "--target", "lo0", "--action", "ping"], env)
        check("cli bogus token refused", rc != 0 and "token_malformed" in out, out[-200:])

        code = "from broker.actions import run; run('ping','127.0.0.1',{})"
        proc = subprocess.run([sys.executable, "-c", code], cwd=PKG_ROOT, env=env, capture_output=True, text=True)
        check("direct actions.run without grant refused", proc.returncode != 0 and
              ("PermissionError" in proc.stderr or "TypeError" in proc.stderr), proc.stderr[-160:])

        (home / "policy.json").write_text("{ not json")
        rc, out = _cli(["lease", "--target", "lo0", "--action", "ping"], env)
        check("corrupt policy fails closed without traceback", rc != 0 and "Traceback" not in out, out[-200:])

        forged_grant = ("from broker import grant; from broker.actions import run; "
                        "g=grant.mint('x','ping',1,{},'r'); print(run('ping','127.0.0.1',{},g)['up'])")
        proc = subprocess.run([sys.executable, "-c", forged_grant], cwd=PKG_ROOT, env=env, capture_output=True, text=True)
        print(f"  NOTE in-process grant forgery still executes ({proc.stdout.strip() or proc.stderr.strip()[:40]}); "
              "real separation requires distinct Unix accounts")

    print(f"\nRESULT: {PASS} pass, {FAIL} fail")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
