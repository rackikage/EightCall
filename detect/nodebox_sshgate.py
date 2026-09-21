#!/usr/bin/env python3
"""nodebox_sshgate — authorization gate whose ALLOW is SSH acceptance.

Model:
    my side (operator)            other side (gate host / cluster)
    holds the private key   ──▶   sshd accepts ONLY that key, and ONLY for the
                                  forwards/commands the policy declares

There is no separate "auth API": the gate IS the SSH acceptance decision. A
principal is a key fingerprint; a grant is (action, target, constraints). The
gate answers allow/deny for a request, and renders the sshd side that enforces
it:

  * `render_authorized_keys()` -> authorized_keys lines with restrictive
    options (restrict, from=, permitopen=, command=, no-pty, ...)
  * `render_sshd_match()`      -> sshd_config Match blocks (AllowUsers,
    PermitOpen, AllowTcpForwarding local, ForceCommand)

Deny by default. Nothing is authorized because a key merely exists; it is
authorized because a grant in the policy covers (action, target, constraint).
"""
from __future__ import annotations

import base64
import fnmatch
import hashlib
import ipaddress
import json
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except Exception:  # noqa: BLE001
    yaml = None


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str
    decision_id: str
    principal: str | None = None
    grant: dict | None = None


def fingerprint_of(pubkey_line: str) -> str:
    """OpenSSH-style SHA256 fingerprint of an ssh public key line."""
    blob = base64.b64decode(pubkey_line.strip().split()[1])
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def load_policy(path: str | Path) -> dict:
    text = Path(path).read_text()
    if str(path).endswith((".yml", ".yaml")) and yaml is not None:
        return yaml.safe_load(text)
    return json.loads(text)


def _now(now: datetime | None) -> datetime:
    return now or datetime.now(timezone.utc)


def _within(window: dict, now: datetime) -> bool:
    nb = window.get("not_before")
    na = window.get("not_after")
    if nb and now < datetime.fromisoformat(nb.replace("Z", "+00:00")):
        return False
    return not (na and now > datetime.fromisoformat(na.replace("Z", "+00:00")))


def _target_match(pattern: str, target: str) -> bool:
    return fnmatch.fnmatchcase(target, pattern) if "*" in pattern else pattern == target


def _source_ok(cidrs: list[str] | None, source_ip: str | None) -> bool:
    if not cidrs:
        return True
    if not source_ip:
        return False
    ip = ipaddress.ip_address(source_ip)
    return any(ip in ipaddress.ip_network(c, strict=False) for c in cidrs)


def _forward_allowed(grant: dict, forward: str | None, listen: str | None) -> tuple[bool, str]:
    if forward:
        allowed = grant.get("permitopen") or []
        return (forward in allowed, f"permitopen {forward} " + ("ok" if forward in allowed else "not granted"))
    if listen:
        allowed = grant.get("permitlisten") or []
        return (listen in allowed, f"permitlisten {listen} " + ("ok" if listen in allowed else "not granted"))
    return True, "no forwarding requested"


def authorize(policy: dict, fingerprint: str, action: str, target: str, *,
              forward: str | None = None, listen: str | None = None,
              port: int | None = None, as_root: bool = False,
              source_ip: str | None = None, now: datetime | None = None) -> Decision:
    """Deny-by-default decision. This IS the SSH acceptance decision.

    No random shells: a shell/task requires an EXPLICIT port that is in the
    host's sshd_ports allowlist, and a root shell requires a grant that sets
    allow_root: true. Anything else is denied."""
    did = uuid.uuid4().hex
    when = _now(now)
    hosts = policy.get("hosts", {}) or {}
    gate_ports = (policy.get("gate", {}) or {}).get("sshd_ports") or [22]
    if policy.get("schema") != "nodebox.sshgate/v1":
        return Decision(False, "unknown policy schema", did)
    for principal in policy.get("principals", []):
        fp = principal.get("fingerprint")
        if not fp or fp != fingerprint:
            continue
        name = principal.get("name", "?")
        for grant in principal.get("grants", []):
            if grant.get("action") != action:
                continue
            if not any(_target_match(t, target) for t in grant.get("targets", [])):
                continue
            if not _within(grant, when):
                return Decision(False, f"grant outside validity window for {name}", did, name, grant)
            if not _source_ok(grant.get("source_cidrs"), source_ip):
                return Decision(False, f"source {source_ip} not in grant source_cidrs", did, name, grant)
            ok, why = _forward_allowed(grant, forward, listen)
            if not ok:
                return Decision(False, why, did, name, grant)
            # no random shells: explicit port, allowlisted, root gated
            if action in ("shell", "task"):
                if port is None:
                    return Decision(False, f"{action} requires an explicit --port", did, name, grant)
                allowed = hosts.get(target, {}).get("sshd_ports") or gate_ports
                if port not in allowed:
                    return Decision(False, f"port {port} not in sshd_ports {allowed} for {target}",
                                    did, name, grant)
                if grant.get("port") and grant["port"] != port:
                    return Decision(False, f"grant is bound to port {grant['port']}, not {port}",
                                    did, name, grant)
                if as_root and not grant.get("allow_root", False):
                    return Decision(False, "root shell not granted (allow_root is not true)",
                                    did, name, grant)
                why = f"port {port} ok" + (", root granted" if as_root else ", non-root")
            return Decision(True, f"grant matched for {name}: {why}", did, name, grant)
        return Decision(False, f"no grant for action={action} target={target}", did, name)
    return Decision(False, "unknown principal (key not enrolled)", did)


def render_authorized_keys(policy: dict, principal_name: str) -> list[str]:
    """One authorized_keys line per grant, with restrictive options."""
    out = []
    for principal in policy.get("principals", []):
        if principal.get("name") != principal_name:
            continue
        key = principal.get("key")
        if not key:
            continue
        for grant in principal.get("grants", []):
            opts = ["restrict"]
            if grant.get("source_cidrs"):
                opts.append(f'from="{",".join(grant["source_cidrs"])}"')
            action = grant.get("action")
            if action == "forward":
                opts.append("port-forwarding")
                for po in grant.get("permitopen", []):
                    opts.append(f'permitopen="{po}"')
                for pl in grant.get("permitlisten", []):
                    opts.append(f'permitlisten="{pl}"')
                opts.append("no-pty")
            elif action == "task":
                opts.append(f'command="{grant["forcecommand"]}"')
            elif action == "shell":
                opts.append("pty")
            out.append(",".join(opts) + " " + key)
    return out


def validate_policy(policy: dict) -> list[str]:
    """Static checks that catch policy mistakes before they reach sshd."""
    issues: list[str] = []
    hosts = policy.get("hosts", {}) or {}
    seen: set[str] = set()
    for principal in policy.get("principals", []):
        name = principal.get("name", "?")
        fp = principal.get("fingerprint")
        if fp in seen:
            issues.append(f"{name}: duplicate fingerprint {fp}")
        seen.add(fp)
        if principal.get("key") and fp and fingerprint_of(principal["key"]) != fp:
            issues.append(f"{name}: key material does not match declared fingerprint")
        by_user: dict[str, set[str]] = {}
        for grant in principal.get("grants", []):
            user = grant.get("sshd_user") or principal.get("sshd_user")
            by_user.setdefault(user, set()).add(grant.get("action"))
            # auth gate applies ONLY to hosts where sshd is enabled
            for target in grant.get("targets", []):
                if target in hosts and not hosts[target].get("sshd"):
                    issues.append(f"{name}: target {target} does not run sshd "
                                  f"({hosts[target].get('note', 'not enrolled')})")
            if grant.get("action") == "task" and not grant.get("forcecommand"):
                issues.append(f"{name}: task grant without forcecommand")
            if grant.get("action") == "forward" and not grant.get("permitopen"):
                issues.append(f"{name}: forward grant without permitopen")
            if grant.get("action") == "forward" and "*" in " ".join(grant.get("permitopen", [])):
                issues.append(f"{name}: wildcard permitopen is not allowed")
            # no random shells: explicit allowlisted port; root must be explicit
            if grant.get("action") in ("shell", "task"):
                targets = grant.get("targets", [])
                if not grant.get("port"):
                    issues.append(f"{name}: {grant.get('action')} grant without an explicit port "
                                  f"(no random shells)")
                for target in targets:
                    allowed = hosts.get(target, {}).get("sshd_ports") \
                        or (policy.get("gate", {}) or {}).get("sshd_ports") or [22]
                    if grant.get("port") and grant["port"] not in allowed:
                        issues.append(f"{name}: port {grant['port']} not in sshd_ports {allowed} for {target}")
                if grant.get("allow_root"):
                    issues.append(f"{name}: grant allows ROOT shell on {targets} (sensitive; "
                                  f"prefer sudo on the target over root login)")
        for user, actions in by_user.items():
            if len(actions) > 1:
                issues.append(f"{name}: sshd_user {user} mixes actions {sorted(actions)} "
                              f"(split users: e.g. gw-fwd / gw-task / gw-shell)")
    return issues


def render_sshd_match(policy: dict) -> str:
    """sshd_config Match blocks enforcing the same policy server-side.

    Grouped by sshd_user; a user that mixes action classes is flagged (use
    per-key authorized_keys options, or split users)."""
    by_user: dict[str, dict] = {}
    for principal in policy.get("principals", []):
        for grant in principal.get("grants", []):
            user = grant.get("sshd_user") or principal.get("sshd_user")
            if not user:
                continue
            agg = by_user.setdefault(user, {"po": [], "fc": None, "shell": False, "actions": set()})
            action = grant.get("action")
            agg["actions"].add(action)
            if action == "forward":
                agg["po"] += grant.get("permitopen", [])
            elif action == "task":
                agg["fc"] = grant.get("forcecommand")
            elif action == "shell":
                agg["shell"] = True

    lines: list[str] = []
    for user, agg in by_user.items():
        lines.append(f"Match User {user}")
        lines.append("    PubkeyAuthentication yes")
        lines.append("    PasswordAuthentication no")
        lines.append("    KbdInteractiveAuthentication no")
        if len(agg["actions"]) > 1:
            lines.append(f"    # CONFLICT: actions {sorted(agg['actions'])} share user {user}; "
                         f"split into gw-fwd / gw-task / gw-shell")
        if agg["po"]:
            lines.append("    AllowTcpForwarding local")
            lines.append("    PermitOpen " + " ".join(dict.fromkeys(agg["po"])))
        else:
            lines.append("    AllowTcpForwarding no")
        if agg["fc"]:
            lines.append(f"    ForceCommand {agg['fc']}")
        if not agg["shell"]:
            lines.append("    PermitTTY no")
        lines.append("    X11Forwarding no")
        lines.append("    AllowAgentForwarding no")
        lines.append("")
    return "\n".join(lines)


def envelope(policy: dict, decision: Decision, request: dict) -> dict:
    return {"schema": "nodebox.event/v1", "node_id": "sshgate", "device_type": "gate",
            "ts": int(time.time()), "event_type": "nodebox.sshgate",
            "data": {"allow": decision.allow, "reason": decision.reason,
                     "decision_id": decision.decision_id, "request": request},
            "provenance": {"gate": policy.get("gate", {}).get("id", "?"),
                           "principal": decision.principal}}
