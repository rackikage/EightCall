"""broker.poptest — proof-of-possession over mutual TLS.

Stands up a real loopback mTLS handshake between a target (server) and the gate
(client), then checks that each side derives the *other's* SPKI fingerprint and
that the session machine only reaches AUTHENTICATED when the live fingerprint
equals the pin.

Run: broker pop   (or python3 -m broker.poptest)
"""
from __future__ import annotations

import socket
import sys
import tempfile
import threading
from pathlib import Path

from . import mtls
from .session import ProtocolError, Session, State

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


def main() -> int:
    global PASS, FAIL
    PASS = FAIL = 0
    print("broker pop — proof-of-possession over mTLS")

    with tempfile.TemporaryDirectory(prefix="broker-pop-") as tmp:
        tmp = Path(tmp)
        tkey, tcert = str(tmp / "target.key"), str(tmp / "target.crt")
        gkey, gcert = str(tmp / "gate.key"), str(tmp / "gate.crt")
        dkey, dcert = str(tmp / "decoy.key"), str(tmp / "decoy.crt")
        mtls.generate_identity(tcert, tkey, "target")
        mtls.generate_identity(gcert, gkey, "gate")
        mtls.generate_identity(dcert, dkey, "decoy")

        pinned_target = mtls.fingerprint_from_key(tkey)
        gate_fp = mtls.fingerprint_from_key(gkey)
        check("pinned fingerprint is stable", pinned_target == mtls.fingerprint_from_key(tkey))
        check("key and cert SPKI agree", pinned_target == mtls.fingerprint_from_cert(tcert))

        result = {}

        def serve():
            ctx = mtls.server_context(tcert, tkey, gcert)
            srv = socket.socket()
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            result["port"] = srv.getsockname()[1]
            try:
                conn, _ = srv.accept()
                tls = ctx.wrap_socket(conn, server_side=True)
                result["gate_fp_seen"] = mtls.peer_fingerprint(tls)
                tls.recv(1)
                tls.close()
            except Exception as exc:  # noqa: BLE001 - surfaced to the assertions
                result["error"] = f"{type(exc).__name__}: {exc}"
            finally:
                srv.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        while "port" not in result:
            pass
        client_ctx = mtls.client_context(gcert, gkey, tcert)
        seen = None
        try:
            tls = mtls.connect(client_ctx, "127.0.0.1", result["port"], "target")
            seen = mtls.peer_fingerprint(tls)
            tls.sendall(b"x")
            tls.close()
        except Exception as exc:  # noqa: BLE001
            result["client_error"] = f"{type(exc).__name__}: {exc}"
        thread.join(timeout=10)

        check("mTLS handshake completed", "error" not in result and "client_error" not in result,
              result.get("error") or result.get("client_error") or "")
        check("gate derives the target's pinned fingerprint", seen == pinned_target, f"(seen={seen})")
        check("target derives the gate's fingerprint", result.get("gate_fp_seen") == gate_fp,
              f"(seen={result.get('gate_fp_seen')})")

        print("-- session state machine")
        session = Session(pinned_target)
        for step in (session.connected, session.begin_auth):
            step()
        session.authenticated(seen)
        session.authorize(True)
        session.begin_execute()
        session.finish(State.COMPLETED)
        check("authorized session reaches COMPLETED", session.state is State.COMPLETED)

        mismatch = Session(pinned_target)
        mismatch.connected()
        mismatch.begin_auth()
        try:
            mismatch.authenticated(mtls.fingerprint_from_key(dkey))
            check("fingerprint mismatch is rejected", False, "(accepted a foreign key)")
        except ProtocolError as exc:
            check("fingerprint mismatch is rejected", exc.args[0] == "identity_mismatch" and mismatch.state is State.CLOSED)

        illegal = Session(pinned_target)
        illegal.connected()
        try:
            illegal.begin_execute()
            check("execution before authorization is impossible", False)
        except ProtocolError:
            check("execution before authorization is impossible", illegal.state is State.CLOSED)

        unauth = Session(pinned_target)
        unauth.connected()
        try:
            unauth.authorize(True)
            check("authorization before authentication is impossible", False)
        except ProtocolError:
            check("authorization before authentication is impossible", unauth.state is State.CLOSED)

    print(f"\nRESULT: {PASS} pass, {FAIL} fail")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
