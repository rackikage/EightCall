# CLAUDE.md — detect continuation

Purple-team toolkit built around one loop:
**emulate a technique → hunt the telemetry → prove the detection → gate the response.**

## Current state (2026-09-18)

Existing: `authz_gate.py` (pt1 HMAC local / pt2 Ed25519 remote), `redact.py`,
`livetail.py`, Sigma rules (`ios_shell_abuse`, `sshd_abuse`, `c2_relay_beacon`,
`icmp_exfil`), pySigma tooling (`pysigma_shells.py`, `validate_rules.py`).

New this session — **nodebox**, an attributable fleet-control plane:

| Module | Role |
|---|---|
| `nodebox_layers.py` | trust stack: hardware → host kernel → hypervisor → guest kernel → guest userspace → process; honest `attestation_scope()` |
| `nodebox_crypto.py` | Ed25519 identity, controller-auth-first handshake, X25519+AES-GCM, replay counters |
| `nodebox_protocol.py` | CONNECT→AUTHENTICATE→ATTEST→SYNC→OBSERVE→APPLY state machine |
| `nodebox_identity.py` | first-boot keygen; `same image != same node`; clone detection inputs |
| `nodebox_telemetry.py` | normalized event envelope + dot-flatten for Sigma |
| `nodebox_agent.py` | node agent in the microVM; typed capabilities; no shell/exec |
| `nodebox_controller.py` | enrollment, authenticated sessions, typed dispatch, clone detection; **`apply()` optionally routes through `authz_gate` (signed allow required)** |
| `nodebox_collector.py` | host-side normalizer (dot-flatten **+ ECS**) + pySigma (pySigma stays OFF-node) |
| `nodebox_broker.py` | hardened OpenSSH admin plane; refuses arbitrary `--command`/unknown hosts |
| `nodebox_cli.py` | `stack / keygen / enroll / controller / node / collect / ssh` |
| `nodebox_demo.py` | end-to-end loopback network demo |
| `rules/nodebox_*.yml` | unknown-controller, unauthorized-capability, cloned-identity, mutation-without-supervisor |
| `supervisor/` | systemd service+timer, launchd plist (attributable, not hidden) |
| `vm/` | Firecracker config (1 vCPU/128 MB) + minimal rootfs build |
| `toolbox_http.py` | read-only view server (gate/fleet/detections/tail). GET-only by invariant. Now runs as an internal **loopback sidecar** behind toolbox-rs, not as the front door. `toolbox_ui.*` are its superseded standalone assets, kept on disk. |
| `toolbox_registry.json` | **policy file**: the single declarative registry of every capability the panel can invoke. Adding a command is one row + a restart — no Rust rebuild, no TypeScript edit. |
| `toolbox-rs/` | Rust (axum) front door: boot-lints the registry, then dispatches it through three generic runners (`read_view` proxy / `exec` / `service`). No per-capability code. |
| `toolbox-frontend/` | Vite + TS layer that renders itself from `/api/registry`: controls from `args`, routing from `runner`, presentation from `output.kind`. AMOLED theme. |
| `toolbox_ssh_exec.py` | JSON wrapper over `nodebox_broker.ssh_session` so an argv never round-trips through a joined string. |

## Run

```bash
cd detect
../bin/python3 nodebox_demo.py                 # controller + 3 nodes + collector + gate; 5 alert-hits
../bin/python3 -m pytest test_nodebox.py -q    # 24 tests
../bin/python3 nodebox_cli.py stack            # trust stack + attestation scope
../bin/python3 nodebox_cli.py ssh task --inventory inventory.json --node gateway --task collect-health --dry-run
../bin/python3 nodebox_collector.py nodebox_telemetry.jsonl rules --ecs ecs.ndjson  # eval + ECS export
../bin/python3 toolbox_http.py --port 9091     # view sidecar (internal; not the front door)
./toolbox-rs/target/debug/toolbox-rs \
    --detect-dir . --python ../bin/python3 \
    --static-dir toolbox-frontend/dist        # panel on 127.0.0.1:8080
```

The router (`b628`, `192.168.8.1`) has no sshd; `--node router` is refused by the
broker on purpose (`sshd: false` in `inventory.json` -> use its HTTP API). SSH
tasks target the sshd-enabled `gateway`.

## Invariants — do not violate

- No arbitrary shell/exec/subprocess/eval anywhere in nodebox.
- Typed capabilities only: `PING INFO STATUS DISCONNECT SYNC_CONFIG FETCH_LOGS CAPTURE_TELEMETRY RESTART_SERVICE UPDATE_RULESET`.
- Node authenticates the **controller first**; unknown controller is refused **before** session creation.
- Unique identity per node, generated on first boot; cloning a disk must yield a new key + node_id.
- pySigma never runs on a node — nodes emit, the host collector evaluates.
- **Attribution, not camouflage**: record launcher/unit, inventory revision, node_id, pinned host-key alias, capability, outcome.
- `RESTART_SERVICE` is owned by the service manager (agent exits 75); never `exec`/`kill`.
- SSH admin plane is separate from the agent; `ControlPersist=5m`, per-user control socket, no agent forwarding.
- **The toolbox boundary moved deliberately (2026-09-18).** It was "a view: do not add a route
  that acts". It now acts, because the operator asked for start/stop and command dispatch. The
  boundary that replaced it is stronger than a prohibition, and must hold:
  - `toolbox_http.py` (the sidecar) is still **GET-only and never calls `authorize()`**. All four
    read views keep that property; nothing mutating was added to it.
  - Every argv element is a registry literal, the server's own `--python` path, a server-generated
    token, or a member of an option set the server enumerated from an operator-controlled file
    (`inventory.json`, `log_allowlist.yml`). **A caller supplies an index into a set, never a string.**
  - That is structural, not aspirational: a registry token mixing text with a placeholder fails to
    *deserialize*, the boot lint refuses any argv placeholder whose kind is not `enum`/`server`, and
    `Bound::as_single()` exists only for single-valued bindings, so one arg cannot become two argv
    elements. The lint runs before the listener binds.
  - `effects: [contacts_host]` **requires** a signed allow through `authz_gate`; it fails closed when
    `DETECT_AUTHZ_KEY_TOOLBOX` is unset (the default), so reaching a real host is opt-in.
  - Do not add a `string`/free-text arg kind, and do not add a registry row for anything in the
    excluded set (see `test_toolbox_registry.py::EXCLUDED`): keygen, enroll, controller/node serve,
    authz_http, or anything that rebinds the toolbox itself.
- `toolbox_registry.json` is a **policy file, not configuration**: its literals are argv elements, so
  whoever can edit it can run repo scripts with fixed arguments. Review it like `authz_policy.yml`.

## Open threads

1. ~~Wire `nodebox ssh task` against the owned router~~ **DONE (reconciled):** the
   router has no sshd, so `inventory.json` marks it `sshd:false` and the broker
   refuses SSH to it (use the HTTP API). SSH `collect-health` targets the
   sshd-enabled `gateway`; the documented CLI + supervisor unit now work.
2. ~~Route `Controller.apply` through `authz_gate.py`~~ **DONE:** `Controller`
   takes an optional gate; `apply()` builds a signed request and dispatches only
   on allow, attaching the audited `decision_id`. See `nodebox_authz_policy.yml`.
3. ~~Add an ECS-normalizer stage to `nodebox_collector.py`~~ **DONE:** `to_ecs()`
   + `nodebox collect --ecs OUT`. Original envelope preserved under `nodebox`.
4. Run `vm/build-rootfs.sh` on a Linux host with KVM (Firecracker needs Linux; not macOS).
5. c2-signal timing project (`~/Desktop/c2-signal-lab`): add ground-truth plan-vs-reconstructed timing diff.
6. Paused LAN audit (`~/Desktop/HomeLAN-API-Map`): API map + vulns for `192.168.8.0/24`.
7. Live host exposure to review: kind/py-box nginx on `*:80`, limactl DNS on `*:53` (both all-interfaces).
8. Wire a live HiLink HTTP client for the router's `collect-health` (the SSH path
   is intentionally closed for b628); feed its output through the same redactor.
9. Wire `Controller.apply`'s gate to the *remote* Ed25519 flow (`authz_http` /
   `authz_client`) for cross-host controllers, not just the in-process HMAC gate.

## Test baseline

`pytest -q` → **147 collected** (one command; `conftest.py` aliases the `tmp`
fixture so the dual-mode `test_redact`/`test_livetail` collect):
`test_nodebox.py` 30 · `test_toolbox.py` 22 · `test_authz_gate.py` 21 ·
`test_sshgate.py` 17 · `test_redact.py` 18 · `test_toolbox_registry.py` 13 ·
`test_livetail.py` 10 · `test_authz_remote.py` 9 · `test_toolbox_ssh_exec.py` 7.
Plus `cd toolbox-rs && cargo test` → **17 passed** (token/lint/argv safety).
FIXED (2026-09-20): `test_nodebox.py::test_cloned_identity_is_flagged` and
`::test_node_local_denial_when_policy_grants_but_node_does_not` previously
asserted after a fixed `time.sleep()` / a single dispatch and flaked under load;
both now poll for the expected event/outcome (same readiness pattern as commit
79a06c6).
`validate_rules.py` PASS · `check_coverage.py` PASS · `ruff check .` clean ·
`nodebox_demo.py` → 4 rules fire (5 alert-hits, incl. the gate deny).
