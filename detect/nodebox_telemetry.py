#!/usr/bin/env python3
"""nodebox telemetry: normalized event envelope + JSONL sink.

Every node emits the SAME envelope schema, so the controller can run one set of
Sigma rules across a heterogeneous fleet while keeping per-device identity and
provenance. pySigma is deliberately NOT on the node -- nodes emit, the host
collector normalizes and evaluates.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

SCHEMA = "nodebox.event/v1"


def envelope(node_id: str, device_type: str, event_type: str,
             data: dict, provenance: dict | None = None) -> dict:
    return {
        "schema": SCHEMA,
        "node_id": node_id,
        "device_type": device_type,
        "ts": int(time.time()),
        "event_type": event_type,
        "data": data,
        "provenance": provenance or {},
    }


def flatten(env: dict) -> dict:
    """Dot-flatten for Sigma: {data:{capability:x}} -> {"data.capability": x}.
    Also promotes provenance fields the rules key on."""
    out: dict = {}
    for k in ("schema", "node_id", "device_type", "ts", "event_type"):
        out[k] = env.get(k)
    for section in ("data", "provenance"):
        for k, v in (env.get(section) or {}).items():
            out[f"{section}.{k}"] = v
    return out


class TelemetrySink:
    """Append-only JSONL of raw envelopes (host side)."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, env: dict) -> None:
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(env, separators=(",", ":")) + "\n")

    def read(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return out
