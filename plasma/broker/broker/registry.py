"""broker.registry — the fixed capability registry.

A request never carries a command. It names a capability; the registry maps
that name to a fixed Python entry point and a closed, bounded parameter set.
Unknown capability, unknown parameter, or out-of-range value is refused before
anything executes. Nothing here builds a shell string.
"""
from __future__ import annotations

from typing import Any

CAPABILITIES: dict[str, dict[str, Any]] = {
    "ping": {
        "desc": "ICMP reachability, one echo",
        "params": {},
        "ttl_s": 30,
        "read_only": True,
    },
    "neigh": {
        "desc": "ARP/neighbour-table lookup for the target address",
        "params": {},
        "ttl_s": 60,
        "read_only": True,
    },
    "tcp_probe": {
        "desc": "TCP connect probe to an allow-listed port",
        "params": {"port": {"type": "int", "allow": [80, 443, 8022, 5353, 62078]}},
        "ttl_s": 30,
        "read_only": True,
    },
    "inventory": {
        "desc": "ping + neighbour summary for one target",
        "params": {},
        "ttl_s": 60,
        "read_only": True,
    },
}


class RegistryError(Exception):
    pass


def get(action: str) -> dict[str, Any]:
    spec = CAPABILITIES.get(action)
    if spec is None:
        raise RegistryError(f"unknown capability {action!r}")
    return spec


def validate_params(action: str, params: dict[str, Any] | None) -> dict[str, Any]:
    spec = get(action)
    params = dict(params or {})
    allowed = spec["params"]
    extra = set(params) - set(allowed)
    if extra:
        raise RegistryError(f"unexpected params for {action!r}: {sorted(extra)}")
    out: dict[str, Any] = {}
    for name, rule in allowed.items():
        if name not in params:
            if rule.get("required", True):
                raise RegistryError(f"missing param {name!r} for {action!r}")
            continue
        value = params[name]
        if rule["type"] == "int":
            try:
                ivalue = int(value)
            except (TypeError, ValueError):
                raise RegistryError(f"param {name!r} must be an int")
            if "allow" in rule and ivalue not in rule["allow"]:
                raise RegistryError(f"param {name!r}={ivalue} not in allow-list {rule['allow']}")
            if "min" in rule and ivalue < rule["min"]:
                raise RegistryError(f"param {name!r} below minimum")
            if "max" in rule and ivalue > rule["max"]:
                raise RegistryError(f"param {name!r} above maximum")
            out[name] = ivalue
        else:
            raise RegistryError(f"unsupported param type for {name!r}")
    return out
