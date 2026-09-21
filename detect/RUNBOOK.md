# detect detection pipeline — runbook

Sigma-style detection rules (ICMP exfil, iOS shell abuse, sshd abuse, C2
relay/beacon) validated against locally generated fixtures / the real pySigma
engine. Covers the detection pipeline only — not device provisioning or live
telemetry collection. `rules/sshd_abuse.yml` traces OpenSSH tunneling/forwarding
pivots (T1572), root logins, and auth bursts — the counterpart to the
tor-gateway relay; validate it with `pysigma_shells.py rules/sshd_abuse.yml`.
`rules/c2_relay_beacon.yml` traces a beaconing implant reaching C2 through a
redirector/relay tier (T1071/T1090/T1573) from the wire vantage — regular
callback timing combined with domain fronting (SNI≠Host) or a relay-tier hop.
`docs/telemetry-chain.md` maps that relay-cluster shape hop-by-hop to the
telemetry it emits and the rule that catches it (defence-side only — no relay,
redirector, or C2 channel is built or operated by this repo).

## Setup

```
python3 -m venv venv69
./venv69/bin/pip install -r requirements.txt
```

## Run

```
./venv69/bin/python3 gen_icmp_pcaps.py      # regenerate ICMP fixtures
./venv69/bin/python3 gen_c2_beacon_fixtures.py   # regenerate C2 beacon flow fixtures
./venv69/bin/python3 validate_rules.py      # validate all rules against fixtures
./venv69/bin/python3 check_coverage.py      # per-signature coverage vs schema/shell_api_map.yml
./venv69/bin/python3 pysigma_shells.py      # re-check the shell rule on the REAL pySigma engine
./venv69/bin/python3 pysigma_shells.py rules/sshd_abuse.yml   # same, for the sshd-abuse rule
./venv69/bin/python3 pysigma_shells.py rules/c2_relay_beacon.yml   # same, for the C2 relay/beacon rule
./venv69/bin/python3 test_redact.py         # redaction-capture suite (18 cases; masked, never raw)
./venv69/bin/python3 test_authz_gate.py     # local gate test suite (pt1, 21 cases)
./venv69/bin/python3 test_authz_remote.py   # remote gate: Ed25519 + HTTP (pt2, 9 cases)
./venv69/bin/python3 test_livetail.py       # live-log observation suite (10 cases)
./venv69/bin/python3 authz_gate.py verify authz_audit.jsonl   # check audit hash chain
./venv69/bin/python3 redact.py verify findings.jsonl          # check findings hash chain (same construction)
```

## Authorization gate

`authz_gate.py` is the single deterministic boundary between parsed detection
output (`evaluate()` hits) and any executor — the coming osascript / XPC
response runners. Nothing acts on a host without clearing it first:

```python
from authz_gate import AuthzGate
gate = AuthzGate.from_policy_file("authz_policy.yml")
decision = gate.authorize(request)          # -> Decision(allow, reason, decision_id)
if not decision.allow:
    abort(decision.reason)                  # deny by default
# executor may now run, quoting decision.decision_id
```

or fail-closed: `decision_id = gate.require(request)` (raises on deny).

Authority lives only in `authz_policy.yml` (operator-controlled grants).
The gate decides from the request's structural fields — caller, action,
target, params, nonce, issued_at — matched against those grants. It **never**
reads packet bytes, log lines, or model output to grant access, and rejects
any request that carries an unexpected field (so a caller cannot smuggle its
own verdict). Each request is HMAC-signed by the caller's policy key; identity
is proven, not claimed. Every call appends one record to the hash-chained
`authz_audit.jsonl`, and the returned `decision_id` is that record's chain
hash. `authz_nonces.log` is the replay store; both are append-only.

Request shape (all fields required except `params`/`evidence_ref`):

```json
{"caller":"responder-osascript","action":"run_osascript",
 "target":"host:test-sim-01","params":{"script":"notify_soc"},
 "nonce":"<unique-per-caller>","issued_at":"<ISO-8601 UTC>",
 "evidence_ref":"ios_shell_abuse:seq3","sig":"<HMAC-SHA256 hex>"}
```

`evidence_ref` is opaque traceability for the audit trail only — it is not
part of the decision. Set `DETECT_AUTHZ_KEY_RESPONDER` (per `key_env` in the
policy) to the caller's key before running a real runner.

### Remote gate (pt2): Ed25519 identity + HTTP hosting

For live-machine-to-live-machine audits, each guest VM is a caller identified
by its **Ed25519 public-key fingerprint (the "keyhash")**. The gate holds only
each guest's public key + fingerprint — never a secret — so it is safe to host
where remote guests reach it. The fingerprint is the cryptographic identity;
it is recorded on every audit record (`caller_fingerprint`).

Provision a guest identity (private key stays on the guest):

```
./venv69/bin/python3 authz_keygen.py responder-vm-01 --out keys/
# prints fingerprint + a policy block to paste into authz_policy.yml
```

Host the gate over HTTP (localhost by default):

```
./venv69/bin/python3 authz_http.py --policy authz_policy.yml --host 127.0.0.1 --port 8787
#   POST /authorize  -> 200 {allow, reason, decision_id} | 403 on deny
#   GET  /healthz    -> 200
```

The HTTP layer adds **no** trust of its own: the Ed25519 signature is the
authentication and deny-by-default is the rule, so an exposed endpoint still
cannot yield an allow to anyone without a pinned private key. Bind to the LAN
(e.g. via the FLEET gateway) only deliberately, and terminate TLS in front.

Runner side (on the guest), fail-closed:

```python
from authz_client import build_request, submit, RemoteDenied
req = build_request(caller="responder-vm-01", action="quarantine_process",
                    target="host:test-sim-09", private_key_b64=GUEST_KEY,
                    evidence_ref="ios_shell_abuse:seq3")
try:
    decision = submit("http://<gate-ip>:8787", req)   # raises RemoteDenied on deny/unreachable
except RemoteDenied as e:
    abort(e.reason)
# execute, quoting decision["decision_id"]
```

pt1 HMAC callers and pt2 Ed25519 callers coexist in one policy (per-caller
`alg:`); the decision core, audit chain, and replay store are shared.

`oslog_emitter` (built from `oslog_emitter.swift`) emits the iOS shell-abuse
fixtures into the unified log; `collected_events.log` / `live_capture.log`
are `log show` exports of that output, consumed by the two scripts above.
Rebuild the emitter (verified reproducible from the tracked source):

```
swiftc -O -o oslog_emitter oslog_emitter.swift
```

## Live-log observation (read-only)

`livetail.py` is the bounded observation path for approved logs. Callers pass
**labels**, never paths: the label → path mapping lives in the operator
allowlist `log_allowlist.yml`, and an unlisted label is refused before any
process exists. The only child process is `tail` with a fixed argv vector
(shell=False — no shell, no concatenation):

```
./venv69/bin/python3 livetail.py labels                              # approved sources
./venv69/bin/python3 livetail.py snapshot fixture-live               # tail -v -n 200 (bounded)
./venv69/bin/python3 livetail.py follow fixture-live --seconds 30 \  # tail -v -n 100 -F
    --evidence findings.jsonl
```

`-F` (capital) follows the file by NAME and retries across rotation/recreation
— plain `-f` follows the inode and goes silent after a rotate. `-v` prints an
`==> path <==` header per source so multi-file output stays attributed.
Follows stop at the first of `--seconds` / `--max-lines` / byte budget and are
rate-paced; snapshots are one-shot with an OS timeout. Every line is redacted
by `redact.py` before it can persist (`redact_text` for the record text,
`capture_hit` for findings) — raw line bytes are never written anywhere; with
`--evidence`, only masked findings land in the hash-chained log. Add real
deployment logs to `log_allowlist.yml` to observe them.

## Redaction-capture (findings)

`redact.py` is the stage between a detection hit and the secured backend it
exports to — the "export only redacted matches + metadata; never harvest,
display, or transmit usable credentials" piece. On a hit a runner calls:

```python
from redact import EvidenceLog, capture_and_emit
log = EvidenceLog("findings.jsonl")
capture_and_emit(log, rule, event,
                 evidence_ref="ios_shell_abuse:seq3",
                 decision_id=decision.decision_id)   # ties to the gate decision
```

`capture_hit(rule, event)` scans the event's string **and bytes** fields for
secrets (cloud keys, source-control/package tokens, private keys, JWTs,
bearer/basic-auth, and PHI: US SSN and Luhn-checked PAN) and returns `Finding`s.
Each finding carries a **masked preview** (`<type>:********(N)` — no characters
of the value by default; `reveal_last` exposes at most the last N), a **salted
HMAC-SHA256** of the secret, its field/offset/length, severity, and the
`evidence_ref` / `decision_id`. No field holds the raw secret, so the emitted
record cannot contain it — `test_redact.py` asserts the planted secret is absent
from the written bytes.

Correlation without storage: set `DETECT_REDACT_SALT` to a stable per-deployment
value and the same secret hashes identically across runs/machines (dedupe, or
"this key seen on N guests"). With no salt set a random per-run salt is used —
safe by default, no cross-run correlation; `salt_id` records which regime a hash
came from.

The findings log uses the SAME hash-chained construction as the authz audit
(`canonical_bytes`, `prev_hash -> record_hash`), so `redact.py verify
findings.jsonl` (or `verify_audit_chain`) validates it. `findings.jsonl` is
append-only, **gitignored** runtime state — its records hash real secrets when
run for real; keep it where callers can't rewrite it, as with the audit trail.
The gate's own audit still records only an opaque `evidence_ref`, never contents:
this findings log is the separate, redacted evidence trail, and the gate never
reads it (authority is still never inferred from content).

## Toolbox (registry-driven control panel)

```bash
cd detect
../bin/python3 toolbox_http.py --port 9091 &          # view sidecar, internal only
./toolbox-rs/target/debug/toolbox-rs \
    --detect-dir . --python ../bin/python3 \
    --static-dir toolbox-frontend/dist                # http://127.0.0.1:8080
```

Boot prints what the lint admitted, then binds:

```
registry ok: 15 capabilities (14 enabled, 6 mutating, 1 gated) (digest f8ca1b12494b4a17)
toolbox-rs listening on http://127.0.0.1:8080
```

Everything is reachable as plain JSON:

```bash
curl -s 127.0.0.1:8080/api/registry                    # the policy file + its digest
curl -s 127.0.0.1:8080/api/read/view.detections        # a read view
curl -s '127.0.0.1:8080/api/read/view.gate?limit=5'
curl -s 127.0.0.1:8080/api/options/nodebox.ssh.task.preview/node   # a dropdown's option set
curl -s '127.0.0.1:8080/api/options/nodebox.ssh.task.preview/task?dep=gateway'
curl -s -X POST 127.0.0.1:8080/api/run/nodebox.stack -d '{}'
curl -s 127.0.0.1:8080/api/service/validate.demo/status
```

### Adding a command

Add one object to `toolbox_registry.json` and restart the server. No rebuild:

```json
{ "id": "hunt.validate_rules", "label": "Validate Sigma rules against fixtures",
  "group": "hunt", "summary": "...", "mutating": false, "runner": "exec",
  "timeout_ms": 60000, "argv": ["{python}", "validate_rules.py"], "args": [],
  "output": {"kind": "pass-fail"},
  "dashboard": {"panel": "detections", "order": 3} }
```

It appears in the UI, gets its own controls and renderer, and runs.

### What it refuses, and why that is the design

```bash
# a value outside the server-enumerated option set -> 400, before any spawn
curl -s -X POST 127.0.0.1:8080/api/run/nodebox.ssh.task.preview \
  -d '{"args":{"node":"; rm -rf /","task":"collect-health"}}'
#   "; rm -rf /" is not a member of the option set for "node"

# the sshd-less router is not in the set at all (the broker would refuse it too)
curl -s -X POST 127.0.0.1:8080/api/run/nodebox.ssh.task.preview \
  -d '{"args":{"node":"b628","task":"collect-health"}}'          # 400

# a server-generated path cannot be overridden into a write target
curl -s -X POST 127.0.0.1:8080/api/run/nodebox.collect.ecs \
  -d '{"confirm":"yes","args":{"ecs_out":"/tmp/pwn.ndjson"}}'    # 400

curl -s 127.0.0.1:8080/api/read/nodebox.ssh.task.preview         # 405: mutating, POST-only
curl -s -X POST 127.0.0.1:8080/api/run/validate.gen.c2_fixtures -d '{}'   # 428: confirm required
curl -s -X POST 127.0.0.1:8080/api/run/nodebox.apply -d '{}'     # 410: enabled:false, with the reason
```

Reaching a real host is deliberately hard: `nodebox.ssh.task.execute` needs a
type-the-id confirmation, a **single-use** preview token from
`nodebox.ssh.task.preview` (reuse is refused), and a signed allow from
`authz_gate`. With `DETECT_AUTHZ_KEY_TOOLBOX` unset — the default — it fails
closed:

```
gate denied: DETECT_AUTHZ_KEY_TOOLBOX is not set, so this capability cannot
obtain a signed allow. Register a caller in authz_policy.yml to enable it.
```

Note that `nodebox.ssh.task.preview` is marked `mutating: true` even though it
contacts nothing: `ssh_session()` calls `_emit()` *before* the dry-run return, so
building an argv appends one `nodebox.ssh_session` envelope to the telemetry
stream. A byte is written, so it is not a read. That is attribution working as
designed, not a bug — but it means repeatedly clicking preview grows the stream.

## Known limitations

- `validate_rules.py` is a minimal hand-rolled Sigma evaluator (field,
  `contains`, `contains|all`, `re`, `gte`, `lte`, `and`/`or`/parens only) —
  passing here does not mean a rule is valid against a real Sigma engine.
  Re-check with `pysigma_shells.py`, which loads a rule into **pySigma 1.5**,
  runs the core validators, and compiles it to an Elasticsearch (Lucene + DSL)
  query. `rules/ios_shell_abuse.yml` passes there (33 validators, 0 issues,
  compiles); `rules/c2_relay_beacon.yml` also passes (0 issues, compiles to
  Lucene + DSL). `rules/icmp_exfil.yml` parses and compiles there too, with
  one advisory validator issue (`FieldnameLogsourceIssue`: its `pcap` product
  and payload fields are outside the known field taxonomy) — but compiling to
  a log query proves nothing for a payload-matching network rule. Its real
  proof is `validate_rules.py` over the pcap fixtures; it needs a
  payload-bearing packet source (raw pcap or a Zeek plugin exporting ICMP
  payload bytes) and will not fire against a stock Zeek `conn.log`.
- `rules/c2_relay_beacon.yml` consumes **analytic** fields, not raw capture:
  `beacon.interval_s` / `beacon.jitter_pct` (from a RITA-style beacon scorer),
  `tls.front` = aligned|mismatch (computed from TLS SNI vs HTTP Host), and
  `dst.relay_tier` (hop count through untrusted redirectors). A stock Zeek
  `conn.log` without that enrichment carries none of them and will not fire —
  the rule's `logsource.definition` says so, which is why pySigma reports no
  field-taxonomy issue. Fixtures (`c2_beacon_*.flowlog`) supply these fields
  directly; wiring a live enricher is out of scope here.
- `rules/icmp_exfil.yml` needs a payload-bearing packet source (raw pcap or
  a Zeek plugin exporting ICMP payload bytes). It will not fire against a
  stock Zeek `conn.log`.
- `rules/ios_shell_abuse.yml` signature coverage has gaps: it does not match
  `wget ... | bash`, `base64 -d ... | sh`, or `/dev/udp/...` variants (only
  `| sh`, `| bash`, and `/dev/tcp/` respectively are covered).
- `oslog_emitter` is a macOS CLI tool using `OSLog`/`Logger` — it proves the
  log format, not iOS collection. On iOS the same logging call must run
  inside an app, MDM/EDR collector, or supervised-device test harness; stock
  iOS exposes no system-wide exec/argv stream to third-party code.
- No real iOS device has been attached/tested against this pipeline.
- `authz_gate.py` is pt1: the gate itself. The **nodebox controller** now
  consumes it — `Controller.apply()` builds a signed request and dispatches only
  on an allow (see `nodebox_authz_policy.yml`) — but the osascript / XPC response
  runners are still to be built and must likewise call `authorize()` (or
  `require()`) before acting. The nonce and audit stores are append-only
  local files guarded by an in-process lock; they are correct for a single
  gate process. Multiple concurrent gate processes sharing one store would
  need file locking (not yet implemented), and the append-only hash chain is
  tamper-*evident*, not tamper-proof — verify it (`authz_gate.py verify`) and
  keep the log where callers can't rewrite it.
- pt2 (`authz_http.py`, Ed25519) hosts the gate but ships **no TLS** — bind
  127.0.0.1 and terminate TLS in a reverse proxy / the FLEET gateway before
  any off-host exposure. The single-process nonce/audit caveat above still
  applies (one gate process per store). Still no executor: the runners that
  will consume `decision_id` (osascript / XPC, and any "vacuum" collector over
  the containers-layer sshd guests) are not built yet, and the containers
  layer (Colima/Docker) is currently stopped — bring it up before a live
  multi-guest run.
- `redact.py` secret detection is pattern-based and best-effort. The pattern set
  (`_PATTERNS`) covers common cloud / token / key / JWT / basic-auth / PHI
  shapes, gated by entropy (the generic `key=value` matcher) and Luhn (PAN) to
  cut false positives — but a novel or shapeless secret can be missed, and an
  odd high-entropy string can over-match. It reduces exposure of the secrets it
  *detects*; it is not a guarantee that every secret in a stream was found. Tune
  `_PATTERNS` for the target. The masking + salted-hash guarantee (never emit a
  raw value) holds regardless of which patterns match.
- No live REMOTE telemetry is wired in yet. Local observation exists:
  `livetail.py` tails allowlisted local files read-only and redacts before
  persistence. Feeding real remote-guest logs (e.g. over the router /
  port-forward path) into the same redactor is the remaining integration
  step — the redaction guarantee is identical, but the remote collector that
  streams them is not built here.
- `livetail.py` bounds, by design: a line longer than 8 KiB is truncated
  before scanning (a secret split across the boundary is missed, never
  leaked); detection scans at most the first 1 MiB of any field
  (`redact.MAX_SCAN_CHARS`); the allowlist is a local file, so path authority
  is whoever controls it; `tail -v` framing differs slightly between BSD and
  GNU (BSD emits a leading blank line) — the parser handles both, and the
  line budget counts framing lines as well as content.
