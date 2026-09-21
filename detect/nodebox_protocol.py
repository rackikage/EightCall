#!/usr/bin/env python3
"""nodebox protocol: the CONNECT -> AUTHENTICATE -> ATTEST -> SYNC -> OBSERVE ->
APPLY state machine, plus the two handshake drivers.

Ordering is the security property:

  CONTROLLER proves identity FIRST (SERVER_HELLO + signature over transcript1).
  The node verifies the controller's PINNED key before it creates a session or
  reveals its own attestation. Unknown controller => node closes immediately.

Only after the controller is verified does the node ATTEST (CLIENT_AUTH:
identity + hardware binding + capability manifest), both sides derive the
session key, and the controller confirms the full transcript (SERVER_FINISH).
"""
from __future__ import annotations

import socket
from dataclasses import dataclass, field
from enum import Enum

import nodebox_crypto as nc
from nodebox_crypto import (
    Identity,
    ProtocolError,
    SecureChannel,
    b64d,
    b64e,
)


class State(str, Enum):
    CONNECT = "CONNECT"
    AUTHENTICATE = "AUTHENTICATE"
    ATTEST = "ATTEST"
    SYNC = "SYNC"
    OBSERVE = "OBSERVE"
    APPLY = "APPLY"
    DISCONNECT = "DISCONNECT"


# Ordered transitions; a session may only move forward one step at a time.
ORDER = [State.CONNECT, State.AUTHENTICATE, State.ATTEST, State.SYNC,
         State.OBSERVE, State.APPLY, State.DISCONNECT]

CAPABILITIES = frozenset({
    "PING", "INFO", "STATUS", "DISCONNECT",
    "SYNC_CONFIG", "FETCH_LOGS", "CAPTURE_TELEMETRY",
    "RESTART_SERVICE", "UPDATE_RULESET",
})

# capabilities that are inherently local-only / non-mutating vs. those that
# change node state and therefore need an explicit policy grant.
MUTATING = frozenset({"SYNC_CONFIG", "RESTART_SERVICE", "UPDATE_RULESET"})


@dataclass
class Session:
    channel: SecureChannel
    state: State = State.CONNECT
    session_id: str = ""
    node_id: str = ""
    controller_id: str = ""
    transcript: bytes = b""
    history: list[str] = field(default_factory=list)

    def advance(self, to: State) -> None:
        cur = ORDER.index(self.state)
        nxt = ORDER.index(to)
        if nxt != cur + 1 and not (self.state == State.APPLY and to == State.OBSERVE):
            raise ProtocolError(f"illegal transition {self.state} -> {to}")
        self.state = to
        self.history.append(to.value)

    def send(self, obj: dict) -> None:
        self.channel.send(obj)

    def recv(self) -> dict:
        return self.channel.recv()


def server_handshake(
    sock: socket.socket,
    controller_identity: Identity,
    controller_id: str,
    resolve_node,
) -> Session:
    """Controller side. `resolve_node(node_id) -> (pubkey_raw | None)`.

    Returns an established Session, or raises ProtocolError (caller closes)."""
    hello, t1, eph_c = nc.controller_hello(controller_identity, controller_id)
    nc.send_frame(sock, __import__("json").dumps(hello, separators=(",", ":")).encode())

    raw = nc.recv_frame(sock)
    auth = __import__("json").loads(raw)
    if auth.get("type") != "CLIENT_AUTH":
        raise ProtocolError("expected CLIENT_AUTH")
    node_id = auth["node_id"]
    node_pub = b64d(auth["node_pubkey"])
    if nc.node_id_for(node_pub) != node_id:
        raise ProtocolError("node_id does not match node key")
    enrolled = resolve_node(node_id)
    if enrolled is None:
        raise ProtocolError(f"node not enrolled: {node_id}")
    if enrolled != node_pub:
        raise ProtocolError("node key does not match enrollment")

    full = nc.transcript_full(t1, node_id, node_pub,
                              b64d(auth["client_nonce"]), b64d(auth["eph_pub"]))
    Identity.verify(node_pub, b64d(auth["sig"]), full)
    key = nc.finish_key(eph_c, b64d(auth["eph_pub"]), full)
    channel = SecureChannel(sock, key, full, is_server=True)

    sess = Session(channel=channel, state=State.ATTEST, node_id=node_id,
                   controller_id=controller_id, transcript=full)
    sess.advance(State.SYNC)
    channel.send({
        "type": "SERVER_FINISH",
        "sig": b64e(controller_identity.sign(full)),
        "controller_id": controller_id,
        "state": sess.state.value,
    })
    return sess


def client_handshake(
    sock: socket.socket,
    node_identity: Identity,
    pinned_controller_pubkey: bytes,
    expected_controller_id: str,
) -> Session:
    """Node side. Verifies the controller BEFORE creating a session."""
    raw = nc.recv_frame(sock)
    hello = __import__("json").loads(raw)
    if hello.get("type") != "SERVER_HELLO" or hello.get("proto") != nc.PROTO:
        raise ProtocolError("bad SERVER_HELLO")
    if hello.get("controller_id") != expected_controller_id:
        raise ProtocolError("unknown controller id")
    ctrl_pub = b64d(hello["controller_pubkey"])
    if ctrl_pub != pinned_controller_pubkey:
        raise ProtocolError("unknown controller key (pinned key mismatch)")

    t1 = nc.transcript1(hello["controller_id"], b64d(hello["server_nonce"]),
                        b64d(hello["eph_pub"]))
    Identity.verify(ctrl_pub, b64d(hello["sig"]), t1)   # controller proven

    auth, full, eph_n = nc.node_auth(node_identity, t1, hello["controller_id"])
    nc.send_frame(sock, __import__("json").dumps(auth, separators=(",", ":")).encode())
    key = nc.finish_key(eph_n, b64d(hello["eph_pub"]), full)
    channel = SecureChannel(sock, key, full, is_server=False)

    sess = Session(channel=channel, state=State.ATTEST,
                   node_id=node_identity.node_id,
                   controller_id=hello["controller_id"], transcript=full)
    finish = channel.recv()
    if finish.get("type") != "SERVER_FINISH":
        raise ProtocolError("expected SERVER_FINISH")
    Identity.verify(ctrl_pub, b64d(finish["sig"]), full)
    sess.advance(State.SYNC)
    return sess
