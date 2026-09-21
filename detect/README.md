# detect — shell-abuse hunt & detection validation

A purple-team toolkit built around one loop: **emulate a technique → hunt it in
telemetry → prove the detection → gate the response.** Two halves plus a
control boundary.

- 🎯 **Hunt** — Sigma detections + pySigma validation that find shell, tunnel,
  and exfil abuse.
- 🧪 **Validation (the "emulation" side)** — a *contained telemetry generator* that
  reproduces the **telemetry** of those techniques so the hunt can be proven.
  It generates signatures (benign fixture commands aimed at `test.invalid`,
  synthetic OSLog lines, crafted pcaps) — it does **not** execute a working
  payload, open a real shell, or hijack a host.
- 🚦 **Gate** — a deny-by-default authorization boundary that must approve
  before any responder/executor acts on a hit.
- 👁 **Observe** — a read-only, allowlisted live-log tail (`tail -v -F`) that
  redacts before anything persists.

> Scope: authorized engineering on systems you own. The validator
> emulates *telemetry*, not intrusions; the gate only ever says allow/deny.

## Concept / tooling structure

```
   validate/ (emulate)         hunt/ (detect)              gate (respond)
 ┌──────────────────┐      ┌───────────────────┐      ┌────────────────────┐
 │ fixture commands │─────▶│ Sigma rules       │─────▶│ authorize(request) │
 │ oslog_emitter    │ tel- │ validate_rules    │ hit  │ deny by default    │
 │ gen_icmp_pcaps   │ emetry│ pysigma_shells   │      │ signed·scoped·audit│
 └──────────────────┘      └───────────────────┘      └────────────────────┘
     signatures, not            fires on the              nothing runs until
     working payloads           emulated telemetry        a signed allow
```

## Hunt — detections

| Rule | Technique | ATT&CK |
|------|-----------|--------|
| `rules/ios_shell_abuse.yml` | reverse/pipe shells (`curl\|bash`, `nc -e`, `/dev/tcp`, `wget\|sh`, `base64 -d\|bash`) | T1059.004 |
| `rules/sshd_abuse.yml` | OpenSSH tunneling/forwarding pivots, root login, auth bursts | T1572 · T1021.004 |
| `rules/c2_relay_beacon.yml` | beaconing C2 through a redirector/relay tier (regular callback + fronting/relay hop) | T1071 · T1090 · T1573 |
| `rules/icmp_exfil.yml` | ICMP payload exfiltration | T1048 |

- `validate_rules.py` — minimal Sigma evaluator over the emulated fixtures
- `check_coverage.py` — per-signature coverage vs `schema/shell_api_map.yml`
- `pysigma_shells.py` — re-validate on the **real pySigma** engine + compile to
  Elasticsearch (Lucene / DSL) queries

## Validation — emulation (contained)

Reproduces the *telemetry* each detection expects, so a rule can be proven to
fire without touching a live host:

- `schema/shell_api_map.yml` — the technique signatures + their benign fixture
  commands (targets are `test.invalid`)
- `oslog_emitter.swift` — emits **synthetic** OSLog lines in the collector's
  format (proves the log shape; runs no argv)
- `gen_icmp_pcaps.py` — crafts a benign and an attack **test** pcap
- `gen_c2_beacon_fixtures.py` — emits benign + attack **enriched-flow** fixtures
  (`c2_beacon_*.flowlog`) reproducing the *telemetry* a relay cluster leaves on
  the wire — beacon timing, SNI≠Host fronting, relay-tier hops; no relay is run
- `collected_events.log`, `live_capture.log` — captured emulation telemetry

See `docs/telemetry-chain.md` for the relay-cluster topology mapped hop-by-hop
to the telemetry it emits and the rule that catches it (defence-side only).

## Gate — response authorization

The single deterministic boundary between a detection hit and any executor.

- `authz_gate.py` — `authorize(request) -> {allow, reason, decision_id}`;
  validates caller identity, target scope, action, expiry, nonce/replay;
  hash-chained, tamper-evident audit. Authority comes only from
  `authz_policy.yml` — never inferred from packet/log/model content.
- **pt1** local (HMAC) · **pt2** remote (Ed25519, pinned by public-key
  fingerprint) over HTTP: `authz_http.py`, client `authz_client.py`, keygen
  `authz_keygen.py`. Tests: `test_authz_gate.py` (21) + `test_authz_remote.py` (9).

## Observe — read-only live logs

`livetail.py` is the bounded observation path. Callers name allowlisted
**labels** from `log_allowlist.yml` — never a path — and the only process ever
spawned is `tail` with a fixed argv vector (no shell). Historical reads use
`tail -v -n N`; live follows use `tail -v -n N -F` (`-F` follows the *name*
across log rotation/recreation, where plain `-f` goes silent; `-v` labels each
source when several files are followed). Follows are bounded by time, line,
and byte budgets plus a rate limit, and every line is redacted by `redact.py`
before it can persist: records and the evidence log carry masked text and
salted-hash findings only. Tests: `test_livetail.py` (10), including refusal
of non-allowlisted labels before any process is spawned.

## Redact — safe evidence capture

The stage between a detection hit and the secured backend: it turns a matched
secret into a finding that is **safe to persist** — masked preview + salted hash
+ location — and **never writes the raw value**. This is the "redacted matches +
metadata" the scope calls for.

- `redact.py` — `capture_hit(rule, event) -> [Finding]` + `EvidenceLog.emit`.
  Detects cloud / token / key / JWT / PHI (SSN, Luhn-checked PAN) secrets in
  text **or binary**, masks the value, and appends a hash-chained JSONL evidence
  log — the same tamper-evident chain as the authz audit (`redact.py verify
  <log>`). The salted-HMAC hash (`DETECT_REDACT_SALT`) correlates a secret
  across runs/machines without ever storing it; with no salt set, a random
  per-run salt is used (safe default: no correlation).
- Tests: `test_redact.py` (18) with fixture `planted_secrets.jsonl` — planted
  **fake** secrets come out masked, never raw. Output `findings.jsonl` is
  gitignored runtime state (its records hash real secrets when run for real).

## Fleet control — nodebox (attributable control plane)

`nodebox_*` is an attributable fleet-control plane for synthetic fleet
nodes — **attribution, not camouflage**: no shell/exec anywhere, only typed
capabilities, and every action recorded with its authorization path. See
`CLAUDE.md` for the full module map. Two boundaries gate every dispatch:

- the node's inventory `allowed_capabilities`, and
- the **response gate** — `Controller.apply()` routes through `authz_gate.py`,
  so nothing is dispatched without a signed allow (`nodebox_authz_policy.yml`;
  `RESTART_SERVICE` is deny-by-default). The audited `decision_id` rides on the
  result, and a gate denial is caught by `rules/nodebox_unauthorized_capability.yml`.

The host-side collector normalizes telemetry two ways: dot-flatten for the Sigma
evaluator, and **ECS** (`nodebox collect --ecs OUT`) for shipping to an Elastic
backend (the original envelope is preserved under the `nodebox` key). The SSH
admin plane (`nodebox ssh task`) is bounded and attributable; a node marked
`sshd:false` in `inventory.json` (the router `b628`) is refused — its health is
collected via the read-only HTTP API, not SSH.

```bash
./venv69/bin/python3 nodebox_demo.py                        # end-to-end loopback demo (gate + collector)
./venv69/bin/python3 -m pytest test_nodebox.py -q           # 24 tests
./venv69/bin/python3 nodebox_cli.py ssh task --inventory inventory.json \
    --node gateway --task collect-health --dry-run          # hardened, attributable SSH argv
```

## Toolbox — registry-driven control panel

One core, one registry, three runners. Everything the panel can do is a row in
`toolbox_registry.json`; **adding a command is adding one row and restarting** —
no Rust rebuild, no TypeScript edit.

```bash
../bin/python3 toolbox_http.py --port 9091 &        # view sidecar (internal)
./toolbox-rs/target/debug/toolbox-rs \
    --detect-dir . --python ../bin/python3 \
    --static-dir toolbox-frontend/dist              # http://127.0.0.1:8080
```

| Runner | What it does |
|---|---|
| `read_view` | reverse-proxied to `toolbox_http.py`. Gate logic, hash-chain verification and the Sigma evaluator are **not** reimplemented in Rust — one implementation, in the language it already lives in. |
| `exec` | one-shot subprocess, fixed argv, bounded by `timeout_ms`. |
| `service` | long-lived child with a bounded ring log and start / stop / status. |

### Why a data-driven dispatcher is still safe

A generic runner that executes registry-declared argv is a bigger blast radius
than hand-written handlers, so the registry **is** the security boundary and is
treated as a policy file (same class as `authz_policy.yml`). Four structural
properties, not conventions:

- **Substring interpolation is unrepresentable.** A registry token is either a
  literal with no braces or exactly `"{name}"`. `"--node={node}"` fails to
  *deserialize*, so no lint rule has to catch it.
- **A caller supplies an index into a set, never a string.** The boot lint
  refuses any argv placeholder whose arg kind is not `enum` or `server`, so
  every argv element is a registry literal, the server's own `--python` path, a
  server-generated token, or a member of an option set the server enumerated
  from an operator-controlled file (`inventory.json`, `log_allowlist.yml`).
  Membership is re-resolved server-side per request, so a stale browser list can
  never widen what is accepted.
- **One arg cannot become two argv elements.** `Bound::as_single()` exists only
  for single-valued bindings; anything else is a type error.
- **The lint runs before the listener binds.** A malformed policy file exits
  non-zero naming the rule, and the port never opens.

Plus: no shell anywhere (`Command::new(argv[0]).args(&argv[1..])`), mutating
rows are POST-only, `effects: [contacts_host]` requires a signed allow through
`authz_gate` and **fails closed** when no gate key is configured (the default),
server-generated paths cannot be overridden by a caller, and a timer may never
auto-fire a mutating row.

Dangerous capabilities are excluded on purpose — key generation, `enroll`
(it authors `inventory.json`, the trust root every other dropdown reads),
long-running controller/node services, and `authz_http` (the only service that
can mint an allow). `test_toolbox_registry.py` fails if one reappears.

## Where it runs

Validation and hunt run in a self-contained environment — a Colima Linux VM
running Docker, a `kind` Kubernetes cluster, and a hardened, forwarding-
restricted tor-gateway relay — used only to produce adversary-like telemetry.
Environment definitions live outside this repo; detect ships the validator, the hunt, and
the gate.

## Quick start

```bash
python3 -m venv venv69 && ./venv69/bin/pip install -r requirements.txt
./venv69/bin/python3 gen_icmp_pcaps.py                         # validator: make test pcaps
./venv69/bin/python3 gen_c2_beacon_fixtures.py                 # validator: make beacon flow fixtures
./venv69/bin/python3 validate_rules.py                         # hunt: rules vs emulation
./venv69/bin/python3 pysigma_shells.py rules/c2_relay_beacon.yml   # hunt: real pySigma + compile
./venv69/bin/python3 test_redact.py                            # redact: 18 tests (masked, never raw)
./venv69/bin/python3 test_authz_gate.py                        # gate: 21 tests
./venv69/bin/python3 test_authz_remote.py                      # gate: 9 tests
./venv69/bin/python3 test_livetail.py                          # observe: 10 tests
./venv69/bin/python3 livetail.py labels                        # observe: approved sources
./venv69/bin/python3 livetail.py snapshot fixture-live         # observe: bounded read
./venv69/bin/python3 test_toolbox.py                           # toolbox: 22 tests
./venv69/bin/python3 test_toolbox_registry.py                  # toolbox: registry contract, 13 tests
(cd toolbox-rs && cargo test)                                  # toolbox: argv/lint safety, 17 tests
```

See `RUNBOOK.md` for the full pipeline and the gate contract.
