"""broker.canon — canonical encoding and digests.

Every signed/authorized artifact is canonicalised here first. Canonical means:
sorted keys, no insignificant whitespace, ASCII. Two logically-equal requests
produce one digest, so a signature can never be replayed under a different
byte encoding (authorization confusion).
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

GENESIS = "0" * 64


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(obj: Any) -> str:
    return sha256_hex(canonical(obj))
