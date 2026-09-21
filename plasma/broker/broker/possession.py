"""broker.possession — proof of possession at use time.

Connect to the target's transport listener, read the certificate the live peer
presents, and require its SPKI fingerprint to equal the pinned one. This is the
step that turns an approval record into a runtime identity boundary: a stale or
stolen public key is useless without the private key behind it.

Fail closed: unreachable, no certificate, malformed SPKI, or a mismatched
fingerprint all raise Denied; the caller must not execute.
"""
from __future__ import annotations

import os

from . import mtls, paths
from .store import Denied

DEFAULT_TIMEOUT = 5.0


def verify_target(address: str, port: int, pinned_fingerprint: str,
                  gate_cert=None, gate_key=None, timeout: float = DEFAULT_TIMEOUT) -> str:
    if not pinned_fingerprint:
        raise Denied("target_not_approved")
    if not port:
        raise Denied("no_transport_endpoint")
    gate_cert = gate_cert or os.environ.get("BROKER_GATE_TLS_CERT") or str(paths.GATE_TLS_CERT)
    gate_key = gate_key or os.environ.get("BROKER_GATE_TLS_KEY") or str(paths.GATE_TLS_KEY)
    if not (os.path.exists(gate_cert) and os.path.exists(gate_key)):
        raise Denied("gate_transport_identity_unavailable")
    try:
        context = mtls.initiator_context(gate_cert, gate_key)
        sock = mtls.connect(context, address, int(port), server_name="target", timeout=timeout)
    except mtls.HandshakeError as exc:
        raise Denied("target_unreachable", detail=str(exc))
    except OSError as exc:
        raise Denied("target_unreachable", detail=type(exc).__name__)
    try:
        seen = mtls.peer_fingerprint(sock)
        if seen != pinned_fingerprint:
            raise Denied("target_identity_mismatch", expected=pinned_fingerprint[:16], seen=seen[:16])
        sock.sendall(b"broker-pop\n")
        return seen
    except mtls.HandshakeError as exc:
        raise Denied("target_identity_unverifiable", detail=str(exc))
    finally:
        try:
            sock.close()
        except OSError:
            pass
