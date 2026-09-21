#!/usr/bin/env python3
"""Generate an Ed25519 caller identity for the remote authorization gate.

Each guest VM that talks to the gate gets its own keypair. The PRIVATE key
stays on that guest and is used to sign requests; the gate only ever holds the
PUBLIC key and its SHA-256 fingerprint (the "keyhash"), which is the caller's
cryptographic identity. No secret is ever transmitted to or stored by the gate.

Usage:
    ./venv69/bin/python3 authz_keygen.py <caller-name> [--out DIR]

Prints the public key, the fingerprint, and a policy snippet to paste into
authz_policy.yml. The private key is written to <caller-name>.ed25519.key
(0600) when --out is given, otherwise printed once to stdout for you to store.
"""
from __future__ import annotations

import argparse
import base64
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from authz_gate import pubkey_fingerprint


def generate() -> tuple[bytes, bytes]:
    priv = Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv_raw, pub_raw


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Generate an Ed25519 gate caller identity")
    ap.add_argument("caller", help="caller/guest name, e.g. responder-vm-01")
    ap.add_argument("--out", help="directory to write the private key into (0600)")
    args = ap.parse_args(argv)

    priv_raw, pub_raw = generate()
    pub_b64 = base64.b64encode(pub_raw).decode()
    priv_b64 = base64.b64encode(priv_raw).decode()
    fp = pubkey_fingerprint(pub_raw)

    print(f"# caller:      {args.caller}")
    print(f"# fingerprint: {fp}")
    print(f"# pubkey_b64:  {pub_b64}")
    print()
    print("# --- paste into authz_policy.yml under `callers:` ---")
    print(f"  {args.caller}:")
    print("    alg: ed25519")
    print(f"    key_sha256: {fp}")
    print(f"    pubkey_b64: {pub_b64}")
    print("    grants:")
    print("      - action: <action>")
    print("        targets: [\"host:<other-live-machine>\"]")
    print()

    if args.out:
        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        key_path = out_dir / f"{args.caller}.ed25519.key"
        # Write with 0600 from the start so the secret is never world-readable.
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(priv_b64 + "\n")
        print(f"# private key (0600) written to: {key_path}", file=sys.stderr)
        print("# keep it on the guest; never commit it or send it to the gate.", file=sys.stderr)
    else:
        print("# PRIVATE KEY (store securely on the guest, shown once):", file=sys.stderr)
        print(f"# {priv_b64}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
