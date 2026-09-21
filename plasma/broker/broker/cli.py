"""broker.cli — the only writer to the authority store and the only executor.

Every state-changing path lives here. Bash wrappers call these subcommands;
they never touch the database and never run an action themselves.

Fail closed: authorization denials, invalid input, integrity failures and
internal bugs all produce a controlled, audited non-zero outcome — never a
traceback and never a partial allow.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from pathlib import Path

from . import actions, agent, crypto, gate, mtls, registry
from .canon import canonical, digest
from .paths import (CHECKPOINT, DB, GATE_KEY, GATE_TLS_CERT, GATE_TLS_KEY, HOME, KEYS,
                    KEYDIR, POLICY, ROTATOR_KEY, WITNESS)
from .store import Denied, Store

DEFAULT_POLICY = {
    "version": 1,
    "policy_id": "broker-v1",
    "max_request_age_s": 60,
    "clock_skew_s": 30,
    "callers": {
        "rotator": {
            "grants": [
                {"action": "ping", "targets": ["*"], "ttl_s": 30},
                {"action": "neigh", "targets": ["*"], "ttl_s": 60},
                {"action": "tcp_probe", "targets": ["*"], "ttl_s": 30},
                {"action": "inventory", "targets": ["*"], "ttl_s": 60},
            ]
        }
    },
}


def _secure_home() -> None:
    if os.environ.get("BROKER_SERVICE") == "1" and "BROKER_HOME" in os.environ:
        raise Denied("acb_home_override_forbidden")
    if os.path.islink(str(HOME)):
        raise Denied("state_dir_is_symlink")
    if HOME.exists():
        st = HOME.stat()
        if st.st_uid != os.geteuid():
            raise Denied("state_dir_not_owned")
        if st.st_mode & 0o077:
            raise Denied("state_dir_permissions_too_open")


def _check_symlinks() -> None:
    for path in (POLICY, KEYS, DB):
        if os.path.islink(str(path)):
            raise Denied("state_file_is_symlink", path=str(path))


def _store() -> Store:
    return Store(str(DB))


def _load() -> tuple:
    _check_symlinks()
    keys = gate.load_keys(str(KEYS))
    body, pdigest, version = gate.load_policy(str(POLICY), keys)
    return body, pdigest, version, keys


def _out(obj) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True, default=str))


# --------------------------------------------------------------------- commands
def cmd_init(args) -> int:
    _secure_home()
    HOME.mkdir(parents=True, mode=0o700, exist_ok=True)
    store = _store()
    KEYDIR.mkdir(parents=True, mode=0o700, exist_ok=True)
    if not ROTATOR_KEY.exists():
        crypto.generate_private(str(ROTATOR_KEY))
    if not GATE_KEY.exists():
        crypto.generate_private(str(GATE_KEY))
    if not GATE_TLS_CERT.exists() or not GATE_TLS_KEY.exists():
        mtls.generate_identity(str(GATE_TLS_CERT), str(GATE_TLS_KEY), "broker-gate")
    keys = {
        "rotator": {"public": crypto.public_hex(str(ROTATOR_KEY)), "status": "enabled"},
        gate.GATE_KEY_ID: {"public": crypto.public_hex(str(GATE_KEY)), "status": "enabled"},
    }
    if not KEYS.exists():
        KEYS.write_text(json.dumps(keys, indent=2, sort_keys=True) + "\n")
        os.chmod(KEYS, 0o600)
    if not POLICY.exists():
        version = int(DEFAULT_POLICY["version"])
        envelope = {
            "version": version,
            "signer": gate.GATE_KEY_ID,
            "body": DEFAULT_POLICY,
            "signature": crypto.sign_hex(str(GATE_KEY), canonical({"version": version, "body": DEFAULT_POLICY})),
        }
        POLICY.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n")
        os.chmod(POLICY, 0o600)
        store.accept_policy_version(version)
    ok, head, n = store.verify_chain()
    _out({"home": str(HOME), "keydir": str(KEYDIR), "db": str(DB), "policy": str(POLICY),
          "keys": str(KEYS), "chain_ok": ok, "chain_len": n, "head": head[:16]})
    return 0


def cmd_target_add(args) -> int:
    """Discovery only. Creates an unactionable candidate."""
    store = _store()
    store.add_target(args.id, args.address, args.label, args.public_key or None)
    _out({"ok": True, "target": args.id, "address": args.address, "state": "candidate",
          "note": "not actionable until target-approve pins a verified fingerprint"})
    return 0


def cmd_target_approve(args) -> int:
    """Out-of-band identity approval: pin the fingerprint the operator verified."""
    store = _store()
    row = store.target(args.id)
    if row is None:
        raise Denied("unknown_target", target_id=args.id)
    public_key = args.public_key or row["public_key"]
    if not public_key:
        raise Denied("no_public_key_to_approve")
    fingerprint = args.fingerprint or crypto.fingerprint_hex(public_key)
    approval = digest({"target_id": args.id, "public_key": public_key, "key_fingerprint": fingerprint})
    store.approve_target(args.id, public_key, fingerprint, approval)
    _out({"ok": True, "target": args.id, "state": "approved", "fingerprint": fingerprint,
          "approval_digest": approval, "note": "confirm this fingerprint out-of-band before trusting it"})
    return 0


def cmd_target_revoke(args) -> int:
    store = _store()
    store.revoke_target(args.id)
    _out({"ok": True, "target": args.id, "state": "revoked"})
    return 0


def cmd_target_keygen(args) -> int:
    """BOOTSTRAP HELPER ONLY. In production the target generates its own
    transport identity and the private key never leaves the target. Emits the
    transport certificate's SPKI hex (the pinned identity) and its fingerprint."""
    key_path = args.out
    cert_path = args.cert or str(Path(key_path).with_suffix(".crt"))
    mtls.generate_identity(cert_path, key_path, args.common_name)
    spki = mtls.spki_hex_from_key(key_path)
    fingerprint = mtls.fingerprint_from_cert(cert_path)
    _out({"ok": True, "private_key": key_path, "certificate": cert_path,
          "public_key": spki, "fingerprint": fingerprint,
          "warning": "bootstrap helper: never use for a real target identity"})
    return 0


def cmd_target_endpoint(args) -> int:
    """Where the target agent listens. Routing metadata, never identity."""
    store = _store()
    revision = store.set_target_endpoint(args.id, args.port)
    _out({"ok": True, "target": args.id, "port": int(args.port), "endpoint_revision": revision})
    return 0


def cmd_agent(args) -> int:
    """Run the target agent: proof-of-possession listener, nothing else.

    Long-running. Wires SIGINT/SIGTERM through the platform_runtime lifecycle
    so the accept loop drains cleanly instead of dying mid-handshake.
    """
    store = _store()
    row = store.target(args.target)
    if row is None:
        raise Denied("unknown_target", target_id=args.target)
    key = args.key or str(KEYDIR / f"{args.target}.key")
    cert = args.cert or str(KEYDIR / f"{args.target}.crt")
    if not (os.path.exists(key) and os.path.exists(cert)):
        raise Denied("transport_identity_unavailable", key=key, cert=cert)
    host = args.host or row["address"]
    # Lifecycle: install signal handlers, transition BOOTING → STARTING → READY,
    # drain on SIGTERM. If platform_runtime isn't importable for any reason,
    # fall back to the old signature (backward-compat).
    try:
        from .runtime import build_context
        from platform_runtime import LifecycleManager, install_signal_handlers
        ctx, _cfg = build_context(args)
        lm = LifecycleManager(ctx)
        install_signal_handlers(lm)
        lm.transition("STARTING")
        lm.transition("READY")
        try:
            agent.serve_forever(host, args.port, cert, key, str(GATE_TLS_CERT), cancel=ctx.cancel)
        finally:
            lm.transition("DRAINING")
            lm.transition("STOPPED")
    except ImportError:
        agent.serve_forever(host, args.port, cert, key, str(GATE_TLS_CERT))
    return 0


def cmd_targets(args) -> int:
    store = _store()
    rows = [dict(r) for r in store.targets()]
    if args.json:
        _out(rows)
    else:
        for row in rows:
            enrol = store.enrollment_by_target(row["target_id"])
            fp = (row["key_fingerprint"] or "-")[:16]
            print(f"{row['target_id']}\t{row['address']}\t{row['state']}\t{fp}\t{enrol['pod_name'] if enrol else '-'}")
    return 0


def cmd_enroll(args) -> int:
    store = _store()
    caps = [c for c in (args.caps or "").split(",") if c]
    for cap in caps:
        registry.get(cap)  # unknown capability in an enrollment is a bug, refuse it
    rev = store.enroll(args.pod, args.target, caps)
    _out({"ok": True, "pod": args.pod, "target": args.target, "caps": caps, "revision": rev})
    return 0


def cmd_enable(args) -> int:
    store = _store()
    rev = store.set_enrollment_status(args.pod, "enabled")
    _out({"ok": True, "pod": args.pod, "status": "enabled", "revision": rev})
    return 0


def cmd_disable(args) -> int:
    store = _store()
    rev = store.set_enrollment_status(args.pod, "disabled")
    _out({"ok": True, "pod": args.pod, "status": "disabled", "revision": rev})
    return 0


def cmd_pods(args) -> int:
    store = _store()
    rows = [dict(r) for r in store.enrollments()]
    if args.json:
        _out(rows)
    else:
        for row in rows:
            print(f"{row['pod_name']}\t{row['target_id']}\t{row['status']}\t{row['caps']}\trev={row['revision']}")
    return 0


def cmd_observe(args) -> int:
    """A: observation only. Never enrolls, never dispatches."""
    store = _store()
    target = store.target(args.target)
    if target is None:
        _out({"ok": False, "reason": "unknown_target"})
        return 2
    result = actions._ping(target["address"])
    store.add_observation(args.target, "icmp", "up" if result["up"] else "down")
    _out({"target": args.target, "up": result["up"], "rtt_ms": result["rtt_ms"]})
    return 0


def cmd_lease(args) -> int:
    store = _store()
    policy, pdigest, version, keys = _load()
    store.accept_policy_version(version)
    enrollment = store.enrollment_by_target(args.target)
    rev = int(enrollment["revision"]) if enrollment else 0
    params = {}
    if args.port:
        params["port"] = int(args.port)
    request = gate.build_request(
        caller=args.caller,
        action=args.action,
        target_id=args.target,
        params=params,
        policy_digest=pdigest,
        enrollment_revision=rev,
        nonce=secrets.token_hex(16),
        ttl_s=args.ttl,
    )
    signer = Path(args.signer_key or os.environ.get("BROKER_ROTATOR_KEY") or str(ROTATOR_KEY))
    if not signer.exists():
        raise Denied("signer_key_unavailable", path=str(signer))
    signature = gate.sign(request, str(signer))
    decision = gate.authorize(store, policy, keys, request, signature, owner=args.owner, gate_key_path=str(GATE_KEY))
    if args.token_only and decision.get("allow"):
        print(decision["token"])
        return 0
    _out(decision)
    return 0 if decision.get("allow") else 1


def cmd_run(args) -> int:
    """C-side execution. Fails closed: no valid token, no action."""
    store = _store()
    keys = gate.load_keys(str(KEYS))
    try:
        out = actions.run_authorized(store, keys, args.token, args.target, args.action, args.pod)
        _out(out)
        return 0
    except Denied as exc:
        _out({"ok": False, "reason": exc.reason})
        return 1
    except PermissionError as exc:
        _out({"ok": False, "reason": "grant_refused", "detail": str(exc)})
        return 1
    except Exception as exc:  # noqa: BLE001 - never assume the action had no effect
        _out({"ok": False, "reason": "outcome_unknown", "detail": f"{type(exc).__name__}: {exc}"})
        return 1


def cmd_decisions(args) -> int:
    store = _store()
    for row in store.decisions(args.limit):
        rec = json.loads(row["record"])
        print(json.dumps({"seq": row["seq"], "allow": rec.get("allow"), "reason": rec.get("reason"),
                          "caller": rec.get("caller"), "action": rec.get("action"),
                          "target": rec.get("target_id"), "fencing": rec.get("fencing", ""),
                          "decision_id": row["decision_id"][:16], "ts": row["ts"]}, sort_keys=True))
    return 0


def cmd_runs(args) -> int:
    store = _store()
    for row in store.runs(args.limit):
        print(json.dumps(dict(row), sort_keys=True))
    return 0


def cmd_reconcile(args) -> int:
    store = _store()
    reconciled = store.reconcile_runs(args.timeout)
    ok, head, _ = store.verify_chain()
    _out({"ok": True, "reconciled": reconciled, "chain_ok": ok, "head": head})
    return 0


def cmd_verify(args) -> int:
    store = _store()
    ok, head, n = store.verify_chain()
    _out({"chain_ok": ok, "decisions": n, "head": head})
    return 0 if ok else 1


def cmd_checkpoint(args) -> int:
    store = _store()
    out = gate.checkpoint(store, str(CHECKPOINT), WITNESS or None)
    _out(out)
    return 0 if not out.get("witness_error") else 1


def cmd_status(args) -> int:
    store = _store()
    ok, head, n = store.verify_chain()
    _out({
        "home": str(HOME),
        "chain_ok": ok,
        "decisions": n,
        "policy_version": store.get_meta("policy_version"),
        "witness_seq": store.get_meta("witness_seq"),
        "targets": len(store.targets()),
        "enrollments": len(store.enrollments()),
        "recent_runs": [dict(r) for r in store.runs(5)],
    })
    return 0


def cmd_selftest(args) -> int:
    from .selftest import main as selftest_main

    return selftest_main()


def cmd_stress(args) -> int:
    from .stress import main as stress_main

    return stress_main()


def cmd_pop(args) -> int:
    from .poptest import main as pop_main

    return pop_main()


# ------------------------------------------------------------------------- argp
def build_parser() -> argparse.ArgumentParser:
    from .runtime import build_global_parser, add_config_subcommand, add_doctor_subcommand
    globals_parser = build_global_parser()
    parser = argparse.ArgumentParser(prog="broker", description="authorized control plane",
                                     parents=[globals_parser])
    sub = parser.add_subparsers(dest="cmd", required=True)
    # Contract subcommands — every migrated CLI must expose these.
    add_config_subcommand(sub)
    add_doctor_subcommand(sub)

    sub.add_parser("init").set_defaults(fn=cmd_init)

    t = sub.add_parser("target-add")
    t.add_argument("--id", required=True)
    t.add_argument("--address", required=True)
    t.add_argument("--label", default="")
    t.add_argument("--public-key", default="", help="claimed key observed in discovery (optional)")
    t.set_defaults(fn=cmd_target_add)

    ta = sub.add_parser("target-approve")
    ta.add_argument("--id", required=True)
    ta.add_argument("--fingerprint", default="", help="fingerprint verified out-of-band")
    ta.add_argument("--public-key", default="", help="key to pin (defaults to the candidate's claimed key)")
    ta.set_defaults(fn=cmd_target_approve)

    tr = sub.add_parser("target-revoke")
    tr.add_argument("--id", required=True)
    tr.set_defaults(fn=cmd_target_revoke)

    tk = sub.add_parser("target-keygen")
    tk.add_argument("--out", required=True, help="path to write the target's private key")
    tk.add_argument("--cert", default="", help="cert path (default: alongside the key)")
    tk.add_argument("--common-name", default="target")
    tk.set_defaults(fn=cmd_target_keygen)

    te = sub.add_parser("target-endpoint")
    te.add_argument("--id", required=True)
    te.add_argument("--port", type=int, required=True, help="port the target agent listens on")
    te.set_defaults(fn=cmd_target_endpoint)

    ag = sub.add_parser("agent")
    ag.add_argument("--target", required=True)
    ag.add_argument("--host", default="", help="listen address (default: the target's address)")
    ag.add_argument("--port", type=int, required=True)
    ag.add_argument("--key", default="", help="target private key (default: KEYDIR/<id>.key)")
    ag.add_argument("--cert", default="", help="target certificate (default: KEYDIR/<id>.crt)")
    ag.set_defaults(fn=cmd_agent)

    t = sub.add_parser("targets")
    t.add_argument("--json", action="store_true")
    t.set_defaults(fn=cmd_targets)

    e = sub.add_parser("enroll")
    e.add_argument("--pod", required=True)
    e.add_argument("--target", required=True)
    e.add_argument("--caps", required=True, help="comma list, e.g. ping,neigh,inventory")
    e.set_defaults(fn=cmd_enroll)

    d = sub.add_parser("disable")
    d.add_argument("--pod", required=True)
    d.set_defaults(fn=cmd_disable)

    en = sub.add_parser("enable")
    en.add_argument("--pod", required=True)
    en.set_defaults(fn=cmd_enable)

    pl = sub.add_parser("pods")
    pl.add_argument("--json", action="store_true")
    pl.set_defaults(fn=cmd_pods)

    ob = sub.add_parser("observe")
    ob.add_argument("--target", required=True)
    ob.set_defaults(fn=cmd_observe)

    le = sub.add_parser("lease")
    le.add_argument("--target", required=True)
    le.add_argument("--action", required=True)
    le.add_argument("--port", type=int, default=0)
    le.add_argument("--caller", default="rotator")
    le.add_argument("--owner", default="rotator@" + os.uname().nodename)
    le.add_argument("--signer-key", default="")
    le.add_argument("--ttl", type=int, default=30)
    le.add_argument("--token-only", action="store_true")
    le.set_defaults(fn=cmd_lease)

    rn = sub.add_parser("run")
    rn.add_argument("--token", required=True)
    rn.add_argument("--target", required=True)
    rn.add_argument("--action", required=True)
    rn.add_argument("--pod", default="pod")
    rn.set_defaults(fn=cmd_run)

    de = sub.add_parser("decisions")
    de.add_argument("-n", "--limit", type=int, default=20)
    de.set_defaults(fn=cmd_decisions)

    ru = sub.add_parser("runs")
    ru.add_argument("-n", "--limit", type=int, default=20)
    ru.set_defaults(fn=cmd_runs)

    rc = sub.add_parser("reconcile")
    rc.add_argument("--timeout", type=int, default=300)
    rc.set_defaults(fn=cmd_reconcile)

    sub.add_parser("verify").set_defaults(fn=cmd_verify)
    sub.add_parser("checkpoint").set_defaults(fn=cmd_checkpoint)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    sub.add_parser("selftest").set_defaults(fn=cmd_selftest)
    sub.add_parser("stress").set_defaults(fn=cmd_stress)
    sub.add_parser("pop").set_defaults(fn=cmd_pop)

    return parser


def main(argv=None) -> int:
    os.umask(0o077)
    args = build_parser().parse_args(argv)
    # Install structured JSON logs on stderr and honor global flags. Never
    # imports platform_runtime for the tiny handlers that don't need it —
    # this is the one place the contract touches the process.
    try:
        from .runtime import resolve_log_level, COMPONENT
        from platform_runtime import install_stderr_json, install_deadline
        install_stderr_json(COMPONENT, level=resolve_log_level(args))
        # Arm the --timeout deadline for real (SIGALRM); `agent` is long-running
        # and drives its own cooperative loop, so it opts out.
        if getattr(args, "timeout", None) and getattr(args, "cmd", "") != "agent":
            install_deadline(args.timeout)
    except Exception:  # noqa: BLE001 - logging setup must never break a command
        pass
    try:
        return int(args.fn(args))
    except Denied as exc:
        _out({"ok": False, "reason": exc.reason, "detail": exc.detail})
        return 1
    except Exception as exc:  # noqa: BLE001 - fail closed, audit, never traceback
        # A --timeout deadline maps to exit 3 (dependency/timeout) per contract.
        try:
            from platform_runtime.lifecycle import DeadlineExceeded
            from platform_runtime.errors import ExitCode as _EC
            if isinstance(exc, DeadlineExceeded):
                _out({"ok": False, "reason": "deadline_exceeded", "detail": str(exc),
                      "error": {"code": "DEADLINE_EXCEEDED", "message": str(exc)}})
                return int(_EC.DEPENDENCY)
        except Exception:
            pass
        # ConfigInvalid from platform_runtime maps to exit 2 (usage/config).
        try:
            from platform_runtime.errors import PlatformError
            if isinstance(exc, PlatformError):
                _out({"ok": False, "reason": exc.code.lower(), "detail": exc.message,
                      "error": exc.as_dict()})
                return int(exc.exit_code)
        except Exception:
            pass
        try:
            store = _store()
            store.append_decision({
                "allow": False, "reason": "internal_error", "caller": "", "action": "",
                "target_id": "", "params": {}, "policy_digest": "", "enrollment_revision": 0,
                "nonce": "", "detail": type(exc).__name__,
            })
        except Exception:
            pass
        _out({"ok": False, "reason": "internal_error", "detail": f"{type(exc).__name__}: {exc}"})
        return 2


if __name__ == "__main__":
    sys.exit(main())
