"""broker.paths — resolved filesystem locations, single source of truth.

Imported by cli, actions and possession so they agree on where authority state and key
material live without importing each other (which would be a cycle).
"""
from __future__ import annotations

import os
from pathlib import Path

HOME = Path(os.environ.get("BROKER_HOME", str(Path.home() / "data" / "broker")))
DB = HOME / "broker.db"
POLICY = HOME / "policy.json"
KEYS = HOME / "trusted_keys.json"
CHECKPOINT = HOME / "checkpoint.json"

KEYDIR = Path(os.environ.get("BROKER_KEYDIR", str(Path.home() / ".broker-keys")))
ROTATOR_KEY = KEYDIR / "rotator.pem"
GATE_KEY = KEYDIR / "gate.pem"
GATE_TLS_CERT = KEYDIR / "gate-tls.crt"
GATE_TLS_KEY = KEYDIR / "gate-tls.key"

WITNESS = os.environ.get("BROKER_WITNESS_URL", "")
