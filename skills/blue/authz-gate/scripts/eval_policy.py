#!/usr/bin/env python3
"""Default-deny authorization policy evaluator.

Reference implementation of the authz-gate model. It evaluates a *structured*
command request against a default-deny policy and returns a decision. It never
executes anything -- execution belongs to a separate, fixed handler.

    Permit = Authenticated & Authorized & WithinScope
           & PolicyAllowed & ApprovedIfRequired & Auditable

Any term that is false OR unknown resolves to DENY. Failing closed is the point.
Unknown policy shapes, unknown operators, and evaluation errors all deny.

Stdlib only. Run `python eval_policy.py` for the built-in self-tests.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


class PolicyError(Exception):
    """Raised when a policy cannot be loaded or is structurally invalid."""


@dataclass(frozen=True)
class Decision:
    permit: bool
    reason: str
    request_id: str
    actor: str
    action: str
    policy_version: int
    timestamp: float

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_policy(path: str | Path) -> dict[str, Any]:
    """Load a policy and refuse anything that is not default-deny."""
    data = json.loads(Path(path).read_text())
    if data.get("default_decision") != "deny":
        raise PolicyError("policy must set default_decision: deny")
    if not isinstance(data.get("actions"), dict):
        raise PolicyError("policy must define an actions catalog")
    return data


def _param_matches_type(spec: dict[str, Any], value: Any) -> bool:
    kind = spec.get("type")
    if kind == "boolean":
        return isinstance(value, bool)
    if kind == "string":
        return isinstance(value, str)
    if kind == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    return False


def validate_parameters(action_spec: dict[str, Any], params: dict[str, Any]) -> tuple[bool, str]:
    schema = action_spec.get("parameters", {})
    for name, spec in schema.items():
        if spec.get("required") and name not in params:
            return False, f"missing required parameter: {name}"
        if name in params and not _param_matches_type(spec, params[name]):
            return False, f"parameter '{name}' has invalid type"
    for name in params:
        if name not in schema:
            return False, f"unknown parameter: {name}"
    return True, "parameters valid"


def _resolve_role(policy: dict[str, Any], roles: list[str], action: str) -> tuple[str | None, dict[str, Any] | None]:
    for role_name in roles:
        role = policy.get("roles", {}).get(role_name)
        if role and action in role.get("allow", []):
            return role_name, role
    return None, None


def _approval_ok(approval: dict[str, Any] | None, actor: str) -> bool:
    if not approval or not approval.get("valid"):
        return False
    # Separation of duties: an actor may not approve their own request.
    return approval.get("approver") != actor


def _lookup(ctx: dict[str, Any], dotted: str) -> Any:
    cur: Any = ctx
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _matches(rule: dict[str, Any], ctx: dict[str, Any]) -> bool:
    for cond in rule.get("all", []):
        actual = _lookup(ctx, cond["field"])
        op = cond["op"]
        expected = cond["value"]
        if op == "eq":
            ok = actual == expected
        elif op == "neq":
            ok = actual != expected
        elif op == "in":
            ok = actual in expected
        elif op == "not_in":
            ok = actual not in expected
        else:
            raise PolicyError(f"unknown denial operator: {op}")
        if not ok:
            return False
    return True


def evaluate(
    policy: dict[str, Any],
    request: dict[str, Any],
    identity: dict[str, Any] | None,
    approval: dict[str, Any] | None = None,
    *,
    now: float | None = None,
) -> Decision:
    """Evaluate a request. Returns a Decision; never raises on bad input."""
    now = time.time() if now is None else now
    request_id = str(request.get("request_id", "unknown"))
    actor = str((identity or {}).get("id", "anonymous"))
    action = str(request.get("action", ""))
    version = int(policy.get("version", 0))

    def deny(reason: str) -> Decision:
        return Decision(False, reason, request_id, actor, action, version, now)

    try:
        # 1. Authenticated
        if not identity or not identity.get("authenticated"):
            return deny("identity is missing or not authenticated")
        if float(identity.get("session_expires_at", 0)) <= now:
            return deny("session is expired")

        # 2. PolicyAllowed -- action must be in the catalog
        action_spec = policy.get("actions", {}).get(action)
        if action_spec is None:
            return deny("action not in allowlisted_actions")

        # 3. Authorized -- a role must grant the action
        role_name, role = _resolve_role(policy, list(identity.get("roles", [])), action)
        if role is None:
            return deny("role is not authorized for this action")

        # 4. WithinScope -- resource type and environment
        resource = request.get("resource", {}) or {}
        if resource.get("type") not in action_spec.get("resource_types", []):
            return deny("resource type is not permitted for this action")
        environment = request.get("environment")
        allowed_envs = (role.get("constraints") or {}).get("environments")
        if allowed_envs is not None and environment not in allowed_envs:
            return deny("environment is outside the role's scope")

        # 5. Parameter schema
        ok, msg = validate_parameters(action_spec, request.get("parameters", {}) or {})
        if not ok:
            return deny(msg)

        # 6. ApprovedIfRequired
        requires = (role.get("constraints") or {}).get("requires_approval", [])
        if action in requires and not _approval_ok(approval, actor):
            return deny("action requires a valid, independent approval")

        # 7. Explicit denial rules
        ctx = {
            "environment": environment,
            "resource": resource,
            "actor": identity,
            "approval": {"valid": bool(approval and approval.get("valid"))},
        }
        for rule in policy.get("denials", []):
            if _matches(rule, ctx):
                return deny(rule.get("reason", "denied by policy"))

        # 8. Auditable -- caller must persist this Decision (see audit_log.py)
        return Decision(True, "permitted", request_id, actor, action, version, now)
    except PolicyError as exc:
        return deny(f"policy evaluation error: {exc}")


# --------------------------------------------------------------------------- #
# Self-tests
# --------------------------------------------------------------------------- #

def _self_test() -> int:
    policy = {
        "version": 1,
        "default_decision": "deny",
        "roles": {
            "operator": {
                "allow": ["service.read", "service.restart"],
                "constraints": {"environments": ["development", "staging"]},
            },
            "production_operator": {
                "allow": ["service.read", "service.restart"],
                "constraints": {"environments": ["production"], "requires_approval": ["service.restart"]},
            },
        },
        "actions": {
            "service.restart": {
                "resource_types": ["service"],
                "parameters": {"graceful": {"type": "boolean", "required": True}},
                "execution": {"handler": "restart_service", "shell_access": False, "network_egress": "deny"},
            }
        },
        "denials": [
            {
                "all": [
                    {"field": "environment", "op": "eq", "value": "production"},
                    {"field": "approval.valid", "op": "eq", "value": False},
                ],
                "reason": "Production restart requires a valid human approval.",
            }
        ],
    }

    def req(**over):
        base = {
            "request_id": "req_01",
            "action": "service.restart",
            "resource": {"type": "service", "id": "api-worker"},
            "environment": "staging",
            "parameters": {"graceful": True},
        }
        base.update(over)
        return base

    identity = {"id": "user_123", "roles": ["operator"], "authenticated": True, "session_expires_at": time.time() + 60}

    cases = [
        ("staging restart by operator is permitted", req(), identity, None, True),
        ("unauthenticated is denied", req(), {"id": "x", "roles": ["operator"], "authenticated": False}, None, False),
        ("unknown action is denied", req(action="db.drop"), identity, None, False),
        ("out-of-scope environment is denied", req(environment="production"), identity, None, False),
        ("unknown parameter is denied", req(parameters={"graceful": True, "extra": "x"}), identity, None, False),
        ("wrong parameter type is denied", req(parameters={"graceful": "yes"}), identity, None, False),
        (
            "production restart without approval is denied",
            req(environment="production"),
            {"id": "prod", "roles": ["production_operator"], "authenticated": True, "session_expires_at": time.time() + 60},
            None,
            False,
        ),
        (
            "production restart with independent approval is permitted",
            req(environment="production"),
            {"id": "prod", "roles": ["production_operator"], "authenticated": True, "session_expires_at": time.time() + 60},
            {"valid": True, "approver": "user_999"},
            True,
        ),
        (
            "self-approval is denied",
            req(environment="production"),
            {"id": "prod", "roles": ["production_operator"], "authenticated": True, "session_expires_at": time.time() + 60},
            {"valid": True, "approver": "prod"},
            False,
        ),
    ]

    failures = 0
    for name, request, ident, appr, expected in cases:
        got = evaluate(policy, request, ident, appr).permit
        status = "ok" if got == expected else "FAIL"
        if got != expected:
            failures += 1
        print(f"[{status}] {name}: expected={expected} got={got}")
    print(f"\n{len(cases) - failures}/{len(cases)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_self_test())
