# Policy Schema — Default-Deny Authorization Model

Authorization is a declarative, versioned policy document. The only safe default is `deny`; every grant is explicit and as narrow as possible.

## Model

A policy binds four things:

- **Roles** → the set of actions a role may perform, with constraints.
- **Actions** → the allowlisted command catalog, each with a resource type, a parameter schema, and an execution contract.
- **Constraints** → environment, resource scope, change window, and approval requirements.
- **Denials** → explicit conditions that force a `DENY` with a stable reason, evaluated after grants.

## Worked example

```yaml
version: 1

default_decision: deny

roles:
  viewer:
    allow:
      - audit.read
      - status.read

  operator:
    allow:
      - service.read
      - service.restart
    constraints:
      environments:
        - development
        - staging

  production_operator:
    allow:
      - service.read
      - service.restart
    constraints:
      environments:
        - production
      requires_approval:
        - service.restart

actions:
  service.restart:
    resource_types:
      - service
    parameters:
      graceful:
        type: boolean
        required: true
    execution:
      handler: restart_service
      shell_access: false
      timeout_seconds: 60
      network_egress: deny

denials:
  - condition: "resource.environment == 'production' && !approval.valid"
    reason: "Production restart requires a valid human approval."
  - condition: "actor.role not in allowed_roles"
    reason: "Role is not authorized for this action."
  - condition: "action not in allowlisted_actions"
    reason: "Action is not available through the command gateway."
```

## Properties to preserve

- **`default_decision: deny`** is mandatory. A policy that defaults to allow is not a gate.
- **Least privilege in the grants.** Roles name the smallest action set that lets a person do their job; scope them by environment whenever the action is destructive or production-touching.
- **Approval is a constraint, not a convention.** `requires_approval` is enforced by the gate, and approval records are audited. No actor may approve their own request (separation of duties).
- **Actions carry their own execution contract.** `shell_access: false` and `network_egress: deny` are the defaults; deviations are explicit and reviewed.
- **Denials are explicit and explained.** A stable `reason` string lets operators understand the block and lets detection correlate denial patterns.
- **Parameter schemas are strict.** Unknown parameters are rejected; types are enforced; ranges and enumerations are declared.

## Evaluation order

1. Resolve the actor's roles from the identity system (not the request).
2. Check the action exists in the catalog (`action not in allowlisted_actions` → deny).
3. Check a role grants the action (`actor.role not in allowed_roles` → deny).
4. Check constraints: environment, resource scope, change window.
5. Validate parameters against the action schema.
6. Evaluate `denials` conditions.
7. If `requires_approval`, require a valid, independent approval.
8. Permit; hand off to the fixed handler; audit.

Any condition that cannot be evaluated (missing policy, unknown resource, unavailable approval service) resolves to `DENY`.

## Versioning and governance

- Policies are versioned; the version is recorded in every audit event.
- Policy changes are themselves privileged actions: they require review/approval and are audited.
- Periodic access reviews reconcile roles against current job needs and remove stale grants.
