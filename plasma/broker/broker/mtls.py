"""broker.mtls — mutual TLS with SPKI pinning, on stdlib ssl.

The handshake is not hand-rolled: Python's ssl does the TLS work. Our only
job is to answer one question — does the live peer hold the private key for the
fingerprint we pinned? We answer it by hashing the SubjectPublicKeyInfo (SPKI)
of the peer's certificate and comparing to the pinned value.

The pin is over SPKI DER bytes, so it is algorithm-agnostic: the same code pins
an Ed25519 identity on a host whose TLS stack supports it, and an ECDSA P-256
identity where the stack does not (e.g. LibreSSL 2.8.3). Key/cert generation
uses the openssl CLI (already a dependency via crypto.py).

Fail closed: any missing peer certificate, unreadable SPKI or openssl failure
raises HandshakeError, never returns a fingerprint.
"""
from __future__ import annotations

import base64
import os
import socket
import ssl
import subprocess
import tempfile

from .canon import sha256_hex

OPENSSL = os.environ.get("BROKER_OPENSSL", "openssl")


class HandshakeError(Exception):
    pass


def _run(argv: list) -> bytes:
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=20)
    except (OSError, subprocess.SubprocessError) as exc:
        raise HandshakeError(f"openssl_invocation_failed: {type(exc).__name__}")
    if proc.returncode != 0:
        raise HandshakeError((proc.stderr or b"").decode("utf-8", "replace").strip()[:200] or "openssl_failed")
    return proc.stdout


def generate_identity(cert_path: str, key_path: str, common_name: str, algo: str = "ec") -> None:
    """Self-signed transport identity. `algo` is 'ec' (P-256, portable) or
    'ed25519' (only where the TLS stack can load it)."""
    if os.path.exists(key_path):
        raise HandshakeError("key_exists")
    directory = os.path.dirname(os.path.abspath(key_path))
    if directory:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    if algo == "ed25519":
        _run([OPENSSL, "genpkey", "-algorithm", "ED25519", "-out", key_path])
    else:
        _run([OPENSSL, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", key_path])
    os.chmod(key_path, 0o600)
    # CA:TRUE lets this self-signed cert be a trust anchor for the other side.
    _run([OPENSSL, "req", "-x509", "-new", "-key", key_path, "-out", cert_path, "-days", "825",
          "-subj", f"/CN={common_name}", "-addext", "basicConstraints=critical,CA:TRUE"])


def _spki_hex(spki_pem: bytes) -> str:
    body = b"".join(line for line in spki_pem.splitlines() if not line.startswith(b"-----"))
    try:
        return base64.b64decode(body).hex()
    except (ValueError, TypeError):
        raise HandshakeError("malformed_spki")


def spki_hex_from_key(key_path: str) -> str:
    return _spki_hex(_run([OPENSSL, "pkey", "-in", key_path, "-pubout"]))


def spki_hex_from_cert(cert_path: str) -> str:
    return _spki_hex(_run([OPENSSL, "x509", "-in", cert_path, "-pubkey", "-noout"]))


def spki_hex_from_cert_der(cert_der: bytes) -> str:
    fd, path = tempfile.mkstemp(prefix="broker-cert-")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(cert_der)
        return _spki_hex(_run([OPENSSL, "x509", "-inform", "DER", "-in", path, "-pubkey", "-noout"]))
    finally:
        os.unlink(path)


def _fingerprint(spki_hex: str) -> str:
    return sha256_hex(bytes.fromhex(spki_hex))


def fingerprint_from_key(key_path: str) -> str:
    return _fingerprint(spki_hex_from_key(key_path))


def fingerprint_from_cert(cert_path: str) -> str:
    return _fingerprint(spki_hex_from_cert(cert_path))


def fingerprint_from_cert_der(cert_der: bytes) -> str:
    return _fingerprint(spki_hex_from_cert_der(cert_der))


def server_context(cert_path: str, key_path: str, client_ca: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(client_ca)
    return ctx


def client_context(cert_path: str, key_path: str, server_ca: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_cert_chain(cert_path, key_path)
    ctx.load_verify_locations(server_ca)
    return ctx


def initiator_context(cert_path: str, key_path: str) -> ssl.SSLContext:
    """Client that presents its cert but trusts by SPKI pin, not by a CA.

    CERT_NONE still exposes the server certificate via getpeercert(), so no
    trust anchor is required: the fingerprint comparison is the trust decision.
    The cert is loaded so the peer (which requests one) sees our identity.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(cert_path, key_path)
    return ctx


def peer_fingerprint(tls_sock: ssl.SSLSocket) -> str:
    der = tls_sock.getpeercert(binary_form=True)
    if not der:
        raise HandshakeError("no_peer_certificate")
    return fingerprint_from_cert_der(der)


def connect(context: ssl.SSLContext, address: str, port: int, server_name: str, timeout: float = 5.0) -> ssl.SSLSocket:
    raw = socket.create_connection((address, int(port)), timeout=timeout)
    return context.wrap_socket(raw, server_hostname=server_name)
