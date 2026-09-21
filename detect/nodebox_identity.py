#!/usr/bin/env python3
"""nodebox first-boot node identity.

The image ships WITHOUT an identity. On first boot the node generates a key and
derives node_id from it. Consequences:

    same image          != same node
    same node_id + key  == same trusted node identity

Cloning the disk after enrollment therefore copies the KEY (a trust clone). The
controller detects that: a node_id presenting from a different `machine_binding`
or a different per-boot `boot_id` than its enrolled record is flagged. The fix
for a legitimate clone is to wipe identity on first boot (regenerate), which
yields a new key, a new node_id, and a fresh enrollment.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

import nodebox_crypto as nc


def machine_binding() -> str:
    """A stable per-VM identifier. Prefers the guest machine-id (present in any
    minimal Linux rootfs); falls back to host/arch/MAC without any subprocess."""
    for p in (
        os.environ.get("NODEBOX_MACHINE_ID_PATH", ""),
        os.path.expanduser("~/.nodebox-machine-id"),
        "/etc/machine-id",
        "/var/lib/dbus/machine-id",
    ):
        try:
            v = Path(p).read_text().strip()
            if v:
                return "machine-id:" + v
        except OSError:
            pass
    # Self-provision a stable per-device binding where the OS has no machine-id
    # (e.g. Android/Termux). Written once, 0600, never shared across devices.
    try:
        mp = Path(os.path.expanduser("~/.nodebox-machine-id"))
        v = uuid.uuid4().hex
        mp.write_text(v)
        os.chmod(mp, 0o600)
        return "machine-id:" + v
    except OSError:
        pass
    return "fallback:" + hashlib.sha256(
        f"{platform.node()}|{platform.machine()}|{uuid.getnode():x}".encode()
    ).hexdigest()[:32]


def boot_id() -> str:
    """Random per boot, never persisted. Two live sessions for one node_id with
    different boot_ids means the identity was cloned onto a second instance."""
    return uuid.uuid4().hex


@dataclass
class Enrolled:
    node_id: str
    pubkey_b64: str
    machine_binding: str
    created_at: float
    enrolled: bool = False


class IdentityStore:
    def __init__(self, state_dir: Path):
        self.dir = Path(state_dir)
        self.key_path = self.dir / "identity.key"
        self.rec_path = self.dir / "identity.json"

    def exists(self) -> bool:
        return self.key_path.exists() and self.rec_path.exists()

    def load_or_create(self) -> tuple[nc.Identity, Enrolled, bool]:
        """Returns (identity, record, first_boot)."""
        if self.exists():
            ident = nc.Identity.load(self.key_path)
            rec = Enrolled(**json.loads(self.rec_path.read_text()))
            if nc.node_id_for(ident.pub_raw) != rec.node_id:
                raise ValueError("identity key does not match stored node_id")
            return ident, rec, False
        return self._create()

    def regenerate(self) -> tuple[nc.Identity, Enrolled, bool]:
        """Wipe and re-create -- the correct first boot for a cloned disk."""
        for p in (self.key_path, self.rec_path):
            if p.exists():
                p.unlink()
        return self._create()

    def _create(self) -> tuple[nc.Identity, Enrolled, bool]:
        self.dir.mkdir(parents=True, exist_ok=True)
        ident = nc.Identity.generate()
        rec = Enrolled(
            node_id=ident.node_id,
            pubkey_b64=nc.b64e(ident.pub_raw),
            machine_binding=machine_binding(),
            created_at=time.time(),
            enrolled=False,
        )
        ident.save(self.key_path)
        self.rec_path.write_text(json.dumps(asdict(rec), indent=2))
        os.chmod(self.rec_path, 0o600)
        return ident, rec, True

    def mark_enrolled(self) -> None:
        if not self.rec_path.exists():
            return
        rec = json.loads(self.rec_path.read_text())
        rec["enrolled"] = True
        self.rec_path.write_text(json.dumps(rec, indent=2))
