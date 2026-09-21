"""broker.agent — the minimal target agent.

It proves the target holds its pinned private key and returns a fixed banner.
Nothing else: no shell, no RPC, no capability dispatch. Capability probes
(ping/neigh/tcp_probe) are still issued by the gate against the target's
address; this listener exists only for proof of possession.
"""
from __future__ import annotations

import socket
import threading

from . import mtls


def _serve(srv: socket.socket, context, cancel: threading.Event | None = None) -> None:
    """Accept loop. If `cancel` is set, `accept()` unblocks (poll every 0.5s)
    and we exit cleanly. Without `cancel` the loop runs until the socket dies,
    matching the old behavior for callers that don't pass an event.
    """
    if cancel is not None:
        srv.settimeout(0.5)
    while True:
        if cancel is not None and cancel.is_set():
            return
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            return
        try:
            tls = context.wrap_socket(conn, server_side=True)
            tls.recv(64)
            tls.sendall(b"ok\n")
            tls.close()
        except Exception:  # noqa: BLE001 - a failed peer must not kill the agent
            try:
                conn.close()
            except OSError:
                pass


def start(address: str, cert: str, key: str, gate_ca: str, cancel: threading.Event | None = None):
    """Start on an ephemeral port. Returns (thread, port) for tests.

    If `cancel` is provided the loop honors it and exits cleanly when set.
    """
    context = mtls.server_context(cert, key, gate_ca)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((address, 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    thread = threading.Thread(target=_serve, args=(srv, context, cancel), daemon=True)
    thread.start()
    return thread, port


def serve_forever(address: str, port: int, cert: str, key: str, gate_ca: str,
                  cancel: threading.Event | None = None) -> None:
    """Long-running listener. Pass `cancel` for graceful drain on SIGTERM.

    Prints one line to stderr on start so log capture and readiness scrapes
    still work; JSON logs (if wired) go to stderr through the root logger.
    """
    import sys
    context = mtls.server_context(cert, key, gate_ca)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((address, int(port)))
    srv.listen(8)
    print(f"agent: listening on {address}:{port} cert={cert}", file=sys.stderr)
    try:
        _serve(srv, context, cancel)
    finally:
        try:
            srv.close()
        except OSError:
            pass
