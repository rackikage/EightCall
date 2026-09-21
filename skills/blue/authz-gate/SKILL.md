---
name: authz-gate
description: Design and implement defensive authorization gates and controlled command-execution layers. Use this skill whenever the user is building or reviewing a system that must permit actions only when they are explicitly authorized — command gateways, allowlisted command catalogs, default-deny policy engines, RBAC/ABAC, scoped service identities, least privilege, human-in-the-loop or two-person approval, tamper-evident audit logging, sandboxed execution, secrets management, AI-agent or tool permissioning, or preventing command injection and prompt injection in automation — even if they never say "authorization," "policy," or "gate." Also use when threat-modeling over-privileged services, self-approval, credential leakage in logs/prompts, or egress-based data loss. This skill hardens access controls; it never helps bypass, disable, weaken, or work around them.
---

# Authz-Gate — Defensive Authorization and Command Control

This skill designs systems that **permit an action only when it is explicitly, verifiably authorized**, and deny otherwise. The central posture is simple: a system should never "work around" authorization — it should make legitimate authorization precise, minimal, reviewable, and fully auditable.

## Security posture

Hold this line in everything you design or review:

- Never bypass, disable, weaken, or work around permissions, authentication, authorization, sandboxing, rate limits, or audit controls.
- Never execute unreviewed scripts or code from untrusted inputs.
- Never send source code, credentials, logs, user data, or command output to external/third-party AI services without explicit written approval and a data-classification check.
- Do not integrate "foreign" AI agents into any execution, parsing, or approval path unless they are explicitly allowlisted, contractually approved, and isolated.
- Treat all external inputs as untrusted: validate, normalize, constrain, and log them before use.
- Do not use offensive-security frameworks, exploit modules, payload generators, credential-harvesting tools, scanners configured for exploitation, or automation intended to evade controls.
- **Reduce capability by default:** every component gets the minimum permissions, network access, filesystem access, secrets, and runtime privileges it needs.
- **Separate planning, authorization, execution, and audit.** No component may approve its own privileged action.
- Require an explicit policy check before every privileged command.
- Prefer allowlists over blocklists.
- **Fail closed:** deny when identity, scope, policy, approval, or audit requirements are missing or ambiguous.
- Require human approval for high-impact actions: permission changes, secret access, production changes, destructive commands, external communications, and data exports.
- Record immutable audit events for authentication, authorization decisions, command requests, approvals, execution results, and policy denials.
- Never expose secrets in prompts, logs, terminal output, error messages, or model context.

## The permit equation

A request is permitted only if **all** terms hold:

```
Permit = Authenticated
       ∧ Authorized
       ∧ WithinScope
       ∧ PolicyAllowed
       ∧ ApprovedIfRequired
       ∧ Auditable
```

If any term is false **or unknown**, the result is `DENY`. "Unknown" is not a soft state to be resolved by guessing — it is a denial, because failing open is how authorization systems are defeated.

## Control layers

| Layer | Defensive requirement |
|---|---|
| Identity | Strong authentication; short-lived sessions/tokens; MFA for privileged users |
| Authorization | RBAC plus scoped permissions; ABAC where context (environment, time, data class) matters |
| Commands | Typed command catalog with explicit allowlisted operations and parameters |
| Execution | Separate low-privilege worker; no shell interpolation; no arbitrary command execution |
| Secrets | Vault-backed, short-lived credentials; least privilege; rotation |
| Approvals | Two-person or human-in-the-loop approval for sensitive operations |
| Audit | Append-only records with request IDs, actor, policy decision, timestamp, result |
| Isolation | Sandboxed execution with restricted filesystem, egress, CPU, memory, and time |
| Observability | Alert on repeated denials, privilege-escalation attempts, anomalous access, and policy edits |

## Structured commands, not shell strings

Never accept a raw shell string such as `run("some command from a user")`. Accept a **typed request** instead, so that every field can be validated against policy:

```json
{
  "request_id": "req_01",
  "actor": { "id": "user_123", "roles": ["operator"] },
  "action": "service.restart",
  "resource": { "type": "service", "id": "api-worker" },
  "environment": "staging",
  "parameters": { "graceful": true },
  "reason": "Deploy completed; restart is required to load the new release."
}
```

See `references/command-schema.md` for the full schema and the enforcement order.

## Enforcement order

Every privileged request passes through the same gate, in order:

1. Verify identity and session validity.
2. Verify the action is in the command allowlist.
3. Verify the actor's role permits that action on that resource.
4. Verify the environment and change window are permitted.
5. Validate parameters against a strict schema.
6. Decide whether human approval is required.
7. Execute through a **fixed handler**, never via arbitrary shell input.
8. Store a complete audit record.

Steps 1–6 are decisions; step 7 is the only place side effects occur; step 8 must happen whether the outcome is permit or deny.

## Policy

Authorization is expressed as a default-deny policy document. Start from `references/policy-schema.md` for the role/action/constraint model and the denial-condition pattern. The non-negotiable properties of any policy you write:

- `default_decision: deny`.
- Roles grant the *minimum* set of actions, scoped by environment/resource where possible.
- Sensitive actions carry `requires_approval`.
- Execution handlers declare `shell_access: false` and `network_egress: deny` unless explicitly justified.
- Denials are explained with a stable reason string, so operators understand *why* they were blocked.

## Threats and mitigations

Before finalizing a design, work through the threat list in `references/threats.md`: privilege escalation via over-broad roles, command injection via raw shell execution, prompt injection and unsafe automation in AI-assisted systems, credential leakage in logs/prompts/CI, approval spoofing and self-approval, audit-log tampering and missing attribution, egress-based data leakage, and supply-chain risk from scripts/packages/plugins/agents. For each, the mitigation follows the posture above — least privilege, fail-closed, separation of duties, and immutable audit.

## Auditability and governance

- **Append-only, tamper-evident** logs (hash-chained or WORM) for every decision and execution.
- Every record carries a request ID, actor, action, resource, policy version, decision, and result.
- Policy is **versioned**; changes are themselves audited and require approval.
- Retention, periodic access reviews, and alerting on denials/escalation attempts are part of the design, not an afterthought.
- Incident response can reconstruct exactly what was requested, who approved it, what policy applied, and what executed.

## Evaluation

A gate is only as good as what it can prove. Measure:

- Denied unauthorized requests (should be high, and explained).
- Time-to-detect policy violations.
- Privilege footprint per component (target: minimum viable).
- Approval latency for sensitive actions.
- Audit completeness (every request has a decision and a record).
- Blast-radius reduction (what a single compromised component can reach).

## Limitations

Be honest about the tradeoffs: operational friction from approvals, the ongoing cost of policy maintenance, false denials that erode trust, and the hard dependency on secure identity infrastructure. A gate cannot compensate for a weak identity layer.

## Bundled scripts

Two runnable, stdlib-only references. Both have self-tests (`python <script>`); run them rather than rewriting the logic each time.

- `scripts/eval_policy.py` — a default-deny policy evaluator. Takes a structured request + identity + optional approval and returns a `Decision` (`permit`, `reason`, …). Implements the permit equation and enforcement order, fails closed on unknown operators/shapes/errors, and refuses any policy that is not `default_decision: deny`. Use it to demonstrate or test a policy design.
- `scripts/audit_log.py` — an append-only, hash-chained audit log. Each record commits to the previous record's hash, so tampering or deletion is detectable via `verify()`. Use it to show what "tamper-evident" means concretely; in production, ship records to off-host WORM storage.
- `scripts/example_policy.json` — the worked policy from `references/policy-schema.md` in the JSON form the evaluator consumes.

## Reference files

- `references/command-schema.md` — the structured command request schema and the eight-step enforcement order.
- `references/policy-schema.md` — the default-deny policy model (roles, actions, constraints, denials) with a worked example.
- `references/threats.md` — the defensive threat/mitigation chapter: privilege escalation, injection, prompt injection, credential leakage, approval spoofing, audit tampering, egress leakage, supply chain.
- `references/s5-outline.md` — a reusable thesis/report outline for a least-privilege authorization architecture ("S5" is a placeholder codename; substitute the real system name).

## Workflow

1. Identify what is being gated: the actions, resources, environments, and actors involved.
2. Define the command catalog as typed actions with strict parameter schemas.
3. Write the default-deny policy (roles → actions → constraints → approvals → denials), then verify it against the evaluator in `scripts/eval_policy.py`.
4. Specify the enforcement order and the fixed execution handlers.
5. Threat-model against `references/threats.md` and close the gaps with least privilege, fail-closed defaults, and separation of duties.
6. Specify the audit record shape (see `scripts/audit_log.py`) and the governance process around policy changes.
7. State the evaluation metrics and the residual limitations.
