#!/usr/bin/env python3
"""nodebox crypto: identity, controller-auth-first handshake, secure channel.

Design goals (see nodebox_layers.py for the trust framing):

  * unique per-node Ed25519 identity, generated on first boot -- never baked
    into the image, so a cloned disk does not clone trust;
  * the NODE authenticates the CONTROLLER FIRST. If the controller's pinned
    public key does not match, the node closes before any session is created
    and before it reveals its own attestation;
  * forward-secret session key from an ephemeral X25519 ECDH, bound to a
    transcript hash that both sides sign;
  * replay protection: per-direction monotonic counters inside AES-GCM nonces.

No subprocess, no shell, no filesystem writes outside the caller's state dir.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import struct
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROTO = "nodebox/1"
INFO = b"nodebox-session-v1"
MAX_FRAME = 1 << 20  # 1 MiB


class ProtocolError(Exception):
    pass


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


def node_id_for(pub_raw: bytes) -> str:
    """node_id is DERIVED from the identity key: same key -> same node_id,
    different key -> different node_id. Identity cannot be forged by copying a
    disk; it can only be re-generated on first boot."""
    return "node-" + hashlib.sha256(pub_raw).hexdigest()[:16]


@dataclass
class Identity:
    priv: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> Identity:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_bytes(cls, raw: bytes) -> Identity:
        return cls(Ed25519PrivateKey.from_private_bytes(raw))

    @property
    def pub_raw(self) -> bytes:
        return self.priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @property
    def node_id(self) -> str:
        return node_id_for(self.pub_raw)

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.pub_raw).hexdigest()

    def sign(self, data: bytes) -> bytes:
        return self.priv.sign(data)

    @staticmethod
    def verify(pub_raw: bytes, sig: bytes, data: bytes) -> None:
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(sig, data)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.priv.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ))
        os.chmod(path, 0o600)

    @classmethod
    def load(cls, path: Path) -> Identity:
        return cls.from_bytes(path.read_bytes())


def _hash(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(struct.pack(">I", len(p)))
        h.update(p)
    return h.digest()


def transcript1(controller_id: str, server_nonce: bytes, eph_c: bytes) -> bytes:
    return _hash(PROTO.encode(), controller_id.encode(), server_nonce, eph_c)


def transcript_full(t1: bytes, node_id: str, node_pub: bytes,
                    client_nonce: bytes, eph_n: bytes) -> bytes:
    return _hash(t1, node_id.encode(), node_pub, client_nonce, eph_n)


def derive_key(shared: bytes, transcript: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=transcript,
                info=INFO).derive(shared)


def send_frame(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ProtocolError("connection closed")
        buf += chunk
    return buf


def recv_frame(sock: socket.socket) -> bytes:
    (length,) = struct.unpack(">I", recv_exact(sock, 4))
    if length > MAX_FRAME:
        raise ProtocolError(f"frame too large: {length}")
    return recv_exact(sock, length)


class SecureChannel:
    """AES-GCM framed channel. Nonce = direction byte || 11-byte counter, so the
    two directions never share a nonce. A monotonic counter gives replay
    protection; AAD binds every frame to the handshake transcript."""

    def __init__(self, sock: socket.socket, key: bytes, transcript: bytes, is_server: bool):
        self.sock = sock
        self.aes = AESGCM(key)
        self.transcript = transcript
        self.send_dir = 0x01 if is_server else 0x02
        self.recv_dir = 0x02 if is_server else 0x01
        self.send_counter = 0
        self.recv_counter = 0

    def _nonce(self, direction: int, counter: int) -> bytes:
        return bytes([direction]) + counter.to_bytes(11, "big")

    def send(self, obj: dict) -> None:
        pt = json.dumps(obj, separators=(",", ":")).encode()
        nonce = self._nonce(self.send_dir, self.send_counter)
        self.send_counter += 1
        ct = self.aes.encrypt(nonce, pt, self.transcript)
        send_frame(self.sock, nonce + ct)

    def recv(self) -> dict:
        frame = recv_frame(self.sock)
        if len(frame) < 12:
            raise ProtocolError("short frame")
        nonce, ct = frame[:12], frame[12:]
        if nonce[0] != self.recv_dir:
            raise ProtocolError("wrong direction")
        counter = int.from_bytes(nonce[1:], "big")
        if counter != self.recv_counter:
            raise ProtocolError(f"replay/out-of-order: got {counter}, want {self.recv_counter}")
        self.recv_counter += 1
        pt = self.aes.decrypt(nonce, ct, self.transcript)
        return json.loads(pt)


def controller_hello(identity: Identity, controller_id: str) -> tuple[dict, bytes, X25519PrivateKey]:
    eph = X25519PrivateKey.generate()
    nonce = os.urandom(16)
    eph_pub = eph.public_key().public_bytes(serialization.Encoding.Raw,
                                            serialization.PublicFormat.Raw)
    t1 = transcript1(controller_id, nonce, eph_pub)
    msg = {
        "type": "SERVER_HELLO",
        "proto": PROTO,
        "controller_id": controller_id,
        "controller_pubkey": b64e(identity.pub_raw),
        "server_nonce": b64e(nonce),
        "eph_pub": b64e(eph_pub),
        "sig": b64e(identity.sign(t1)),
    }
    return msg, t1, eph


def node_auth(identity: Identity, t1: bytes, controller_id: str) -> tuple[dict, bytes, X25519PrivateKey]:
    eph = X25519PrivateKey.generate()
    nonce = os.urandom(16)
    eph_pub = eph.public_key().public_bytes(serialization.Encoding.Raw,
                                            serialization.PublicFormat.Raw)
    full = transcript_full(t1, identity.node_id, identity.pub_raw, nonce, eph_pub)
    msg = {
        "type": "CLIENT_AUTH",
        "node_id": identity.node_id,
        "node_pubkey": b64e(identity.pub_raw),
        "client_nonce": b64e(nonce),
        "eph_pub": b64e(eph_pub),
        "sig": b64e(identity.sign(full)),
    }
    return msg, full, eph


def finish_key(my_eph: X25519PrivateKey, peer_eph_raw: bytes, full: bytes) -> bytes:
    shared = my_eph.exchange(X25519PublicKey.from_public_bytes(peer_eph_raw))
    return derive_key(shared, full)
