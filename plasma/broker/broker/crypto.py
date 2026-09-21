"""broker.crypto — Ed25519 signatures via the system OpenSSL.

Separation of duties: the gate stores PUBLIC keys only. Callers keep their
private keys outside BROKER_HOME, so compromising the gate's trust store cannot
mint caller authority; the executor keeps only the gate's public key, so it
cannot mint execution tokens.

Fail closed: every OpenSSL failure raises CryptoError, which callers translate
into a deny. There is no code path where a crypto error becomes an allow.
"""
from __future__ import annotations

import base64
import os
import subprocess
import tempfile
import textwrap

OPENSSL = os.environ.get("BROKER_OPENSSL", "openssl")
_SPKI_ED25519_PREFIX = bytes.fromhex("302a300506032b6570032100")


class CryptoError(Exception):
    pass


def _run(argv: list, stdin: bytes | None = None) -> bytes:
    try:
        proc = subprocess.run(argv, input=stdin, capture_output=True, timeout=15)
    except (OSError, subprocess.SubprocessError) as exc:
        raise CryptoError(f"openssl_invocation_failed: {type(exc).__name__}")
    if proc.returncode != 0:
        raise CryptoError((proc.stderr or b"").decode("utf-8", "replace").strip()[:200] or "openssl_failed")
    return proc.stdout


def generate_private(path: str) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    if os.path.exists(path):
        raise CryptoError("key_exists")
    _run([OPENSSL, "genpkey", "-algorithm", "ED25519", "-out", path])
    os.chmod(path, 0o600)


def public_hex(private_path: str) -> str:
    der = _run([OPENSSL, "pkey", "-in", private_path, "-pubout", "-outform", "DER"])
    if len(der) < 32:
        raise CryptoError("public_key_export_failed")
    return der[-32:].hex()


def fingerprint_hex(public_hex_str: str) -> str:
    """Stable target identity: SHA-256 over the raw public key bytes."""
    import hashlib

    return hashlib.sha256(bytes.fromhex(public_hex_str)).hexdigest()


def _public_pem(public_hex_str: str) -> str:
    der = _SPKI_ED25519_PREFIX + bytes.fromhex(public_hex_str)
    body = "\n".join(textwrap.wrap(base64.b64encode(der).decode("ascii"), 64))
    return f"-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n"


def _temp(data: bytes) -> str:
    fd, path = tempfile.mkstemp(prefix="broker-crypto-")
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    return path


def sign_hex(private_path: str, message: bytes) -> str:
    msg = _temp(message)
    try:
        return _run([OPENSSL, "pkeyutl", "-sign", "-inkey", private_path, "-rawin", "-in", msg]).hex()
    finally:
        os.unlink(msg)


def verify_hex(public_hex_str: str, message: bytes, signature_hex: str) -> bool:
    try:
        bytes.fromhex(public_hex_str)
        bytes.fromhex(signature_hex)
    except (ValueError, TypeError):
        return False
    pub = _temp(_public_pem(public_hex_str).encode("ascii"))
    msg = _temp(message)
    sig = _temp(bytes.fromhex(signature_hex))
    try:
        try:
            proc = subprocess.run(
                [OPENSSL, "pkeyutl", "-verify", "-pubin", "-inkey", pub, "-rawin", "-in", msg, "-sigfile", sig],
                capture_output=True, timeout=15,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise CryptoError(f"openssl_invocation_failed: {type(exc).__name__}")
        return proc.returncode == 0
    finally:
        for path in (pub, msg, sig):
            os.unlink(path)
