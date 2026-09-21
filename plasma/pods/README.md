# fleet/pods — disposable controller-side script runners

A small bash implementation of the A/B/C architecture you laid out. iPhones
and iPads are **targets** (probed from outside); pods are **disposable
controller-side script runners** that invoke a defined action against a
target.

```text
A = watcher.sh       long-running; every W seconds scans targets and emits
                     a trigger to state/triggers.tsv when liveness changes.

        ▼

B = rotator.sh       long-running; pulls triggers, picks an eligible
                     target, and invokes:

        ▼

C = pod.sh <t> <a>   one-shot; resolves alias→ip and runs:
                       actions/<a>.sh <alias> <ip>
                     each invocation gets its own CHAIN_ID / EXEC_ID and
                     writes one line to pods.log + one JSON record to
                     runs.jsonl.
```

iPhones do **not** run pods. Stock iOS has no generic shell surface — pods
operate over the network (ICMP, TCP probes, mDNS, ARP). Arbitrary on-device
execution requires an agent app you ship yourself, a paired lockdown
client, or a jailbroken environment; the pod abstraction does not assume
any of those.

## Layout

```
fleet/pods/
├── README.md
├── CLUSTER_LAW.md        # the identity/authorization spec the gate enforces
├── pods.conf             # all tunables; sourced by every script
├── targets.conf          # alias=ip, one per line (LOCATION, not identity)
├── cluster.conf          # pod_name/device_id/status/capabilities (ENROLLMENT)
├── pod.sh                # C: one-shot action runner
├── watcher.sh            # A: long-running liveness scanner
├── rotator.sh            # B: long-running dispatch loop
├── lib_eligibility.sh    # shared by B and the tests (eligible, in_cooldown, pick_eligible)
├── lib_safety_gate.sh    # read-only: is_enrolled, capability_granted, gate_check
├── cluster.sh            # the ONLY writer to cluster.conf (enroll/disable/enable/rename/validate/list)
├── killswitch.sh               # hard stop for both daemons
├── install.sh            # copies this tree to $PODS_HOME
├── actions/
│   ├── health.sh         # ICMP ping
│   ├── probe.sh          # TCP-port sweep ($PROBE_PORTS)
│   └── inventory.sh      # reverse DNS + ARP neighbor MAC
└── test/
    └── test_pods.sh      # bash-portable smoke tests (no deps)
```

## Install

```sh
cd fleet/pods
./install.sh                       # -> ~/pods (or $PODS_HOME)
```

The installer copies scripts, the conf, an example `targets.conf`, and
creates the empty `state/`, `pids/`, `locks/` directories. It refuses to
overwrite without `--force`.

## Edit `targets.conf`

```sh
# alias=ip per line. Comments start with #.
iphone01=192.168.8.120
iphone02=192.168.8.121
ipad01=192.168.8.122
```

Aliases let a target keep a stable identity even if its IP changes.

## Enroll a pod (CLUSTER LAW v1 safety gate)

`targets.conf` gives an alias an IP — it does **not** authorize dispatch.
Before `pod.sh` will run a real (alias-resolved) action, that alias must be
an **enrolled, enabled pod** with the requested action explicitly granted.
This is enforced by `lib_safety_gate.sh`'s `gate_check()`, called from
`pod.sh` itself, deny-by-default. See `CLUSTER_LAW.md` for the full spec:
one target = one pod, pod name is editable metadata (not identity), a
target never becomes a pod automatically, and discovery never equals
enrollment.

```sh
~/pods/cluster.sh enroll --pod iphone01 --device-id <id-you-assert> \
    --caps health,probe,inventory
~/pods/cluster.sh validate       # lint the whole ledger
~/pods/cluster.sh list           # show current enrollment
```

`<id-you-assert>` is an opaque identifier **you** choose and record — stock
iOS exposes no queryable stable device ID over the LAN (see the notes in
`targets.conf`), so nothing in this repo invents one for you; that would be
exactly the auto-enrollment the law forbids. Re-running `enroll` for the
same pod+device_id just updates its capability grant (no `--force` needed).
Reassigning an *existing* pod name to a *different* device_id needs
`--force` — a loud, logged, deliberate override, never silent.

```sh
~/pods/cluster.sh disable --pod iphone01          # revoke dispatch, keep the record
~/pods/cluster.sh enable  --pod iphone01          # restore it
~/pods/cluster.sh rename  --old iphone01 --new pod-iphone01   # device_id unchanged
```

A capability named literally `root-exec` gates any action shipped with a
same-named `actions/<action>.root` sentinel file — required *in addition
to* the action's own capability, never instead of it. A literal-IP target
(no enrolled pod behind it) can never hold that grant, so a root-requiring
action is refused unconditionally on that path. No shipped action
currently requires it.

Every gate decision (allow/deny) and every `cluster.sh` mutation is
audited to `cluster.log`, one terse `key=value` line each — separate from
`pods.log`/`runs.jsonl`.

## Run

```sh
~/pods/watcher.sh start            # forks, writes pids/watcher.pid
~/pods/rotator.sh start            # forks, writes pids/rotator.pid

tail -F ~/pods/pods.log | grep --line-buffered 'chain='
```

`watcher.sh` runs forever, scanning targets every `$WATCH_INTERVAL_SECONDS`
(default 60) and appending a row to `state/triggers.tsv` whenever an
alias flips between UP and DOWN.

`rotator.sh` runs forever, polling `state/triggers.tsv` every
`$ROTATE_INTERVAL_SECONDS` (default 2). For each unseen trigger it picks
an eligible target — UP per `state.tsv` AND not currently in
`$COOLDOWN_SECONDS` — and runs `pod.sh <alias> <action>`.

A single pod invocation looks like:

```
2026-09-18T12:00:00Z chain=ACB-... exec=E0001f2a hop=0 target=iphone01 ip=192.168.8.120 stage=C event=start action=health status=ok
2026-09-18T12:00:00Z chain=ACB-... exec=E0001f2a hop=0 target=iphone01 ip=192.168.8.120 stage=C event=finish action=health status=ok duration_s=0
```

`runs.jsonl` carries the same record in structured JSON for downstream
tools.

## Hard stop — `killswitch.sh`

```sh
~/pods/killswitch.sh              # stop both daemons, keep state
~/pods/killswitch.sh --purge      # also remove pids/ and locks/
```

It touches `$PODS_STOP`, lets each daemon exit at its next loop boundary,
escalates to SIGTERM after `$FIRE_GRACE_SECONDS`, and removes the pid
files. It does **not** touch unrelated processes, the system shell, SSH,
or your `pods.log` / `runs.jsonl` audit trail.

## Actions

Every action is `actions/<name>.sh` with the same contract:

```sh
actions/<name>.sh <alias> <ip>
# stdout: a short label that lands in the runs.jsonl record
# stderr: free-form (rare; for diagnostics)
# exit:   0 = success, non-zero = fail
```

The shipped actions:

| Action      | What it does                                                     |
|-------------|------------------------------------------------------------------|
| `health`    | ICMP ping (`ping -c N -W s`). Exits 0 if reachable.              |
| `probe`     | TCP-connect to each port in `$PROBE_PORTS`. Exits 0 if any open.  |
| `inventory` | Reverse DNS + ARP neighbor MAC. Always exits 0 (best-effort).    |

Add your own:

```sh
cat > ~/pods/actions/agent.sh <<'EOF'
#!/usr/bin/env bash
set -eu
ALIAS="$1"; IP="$2"
# invoke YOUR app/agent over the network; do NOT assume on-device shell
EOF
chmod +x ~/pods/actions/agent.sh
```

Any non-executable, missing, or out-of-tree action is refused by `pod.sh`
**before** it is invoked — `pod.sh` logs `event=reject reason=unknown-action`
and exits 3. For an alias-resolved target, the action must also be granted
to that pod in `cluster.conf` (see "Enroll a pod" above) — an ungranted or
unenrolled dispatch is refused with `reason=gate_denied` and exits 5. A
future action can require root-exec by shipping `actions/<name>.root`
(empty sentinel file) alongside it — no changes to `pod.sh` are needed for
that; it is picked up automatically by the existing gate.

## State files

| File                              | Owner | Format                       | Notes                            |
|-----------------------------------|-------|------------------------------|----------------------------------|
| `state/state.tsv`                 | A     | `alias\tip\tstatus\tat`      | atomic rewrite per scan          |
| `state/triggers.tsv`              | A     | `alias\tevent\tat`           | append-only; B reads it          |
| `state/processed.tsv`             | B     | one trigger key per line     | dedupe ledger — never truncate   |
| `state/last_dispatch.tsv`         | B     | `alias\tat`                  | for the cooldown check           |
| `pods.log`                        | A/B/C | space-separated `key=value`   | one event per line               |
| `runs.jsonl`                      | C     | one JSON object per line     | structured per-pod record        |
| `cluster.conf`                    | operator (via `cluster.sh`) | `pod_name\tdevice_id\tstatus\tcapabilities` | enrollment ledger; C only reads it |
| `cluster.log`                     | gate / `cluster.sh` | space-separated `key=value` | one line per gate decision + per enroll/disable/enable/rename |

All files are plain text under `$PODS_HOME` (default `~/pods`). No DB.

## Tests

```sh
./test/test_pods.sh           # bash-portable, no deps
./test/test_pods.sh -v        # verbose: print each assertion's data
```

What it covers:

* `bash -n` on every shipped script
* `pod.sh` against loopback succeeds
* `pod.sh` rejects unknown aliases (exit 2) and unknown actions (exit 3)
* `pod.sh` accepts a literal IPv4 address
* `runs.jsonl` is written per invocation
* log line is well-formed key=value
* the safety gate: unenrolled/disabled alias denied (exit 5), ungranted
  capability denied, granted capability allowed, literal-IP dispatch stays
  ungated for ordinary actions
* `cluster.sh`: one-target-one-pod enforcement, identity reassignment
  requires `--force`, rename preserves device_id, disable/enable
  round-trips, `validate` catches a hand-corrupted ledger
* root-exec: an action's own capability alone is not enough; a literal-IP
  target can never hold the `root-exec` grant
* A's eligibility: UP target eligible, DOWN target refused
* B's cooldown: recent dispatch refuses re-dispatch
* `killswitch.sh` actually stops both daemons

The test runner builds a throwaway `$PODS_HOME` under `$TMPDIR` and never
touches your real `~/pods`.

## Tunables

Edit `pods.conf`. Override on the command line with `KEY=val ./pod.sh ...`.

| Key                         | Default       | Meaning                                   |
|-----------------------------|---------------|-------------------------------------------|
| `WATCH_INTERVAL_SECONDS`    | 60            | A's scan cadence                          |
| `PING_TIMEOUT_SECONDS`      | 2             | ping `-W`                                 |
| `PROBE_PORTS`               | 80,443,5353,8080,8443,62078 | CSV; B's probe sweep          |
| `ROTATE_INTERVAL_SECONDS`   | 2             | B's poll cadence                          |
| `COOLDOWN_SECONDS`          | 120           | don't re-dispatch the same target         |
| `FIRE_GRACE_SECONDS`        | 10            | SIGTERM grace before SIGKILL              |
| `CHAIN_PREFIX`              | ACB           | first component of `chain=...`            |
| `ACTION_DEFAULT`            | health        | default action when none specified        |

## What this is not

* Not a network scanner. `probe.sh` only checks the configured port list.
* Not a host exploit tool. iPhones are interrogated over stock protocols,
  not attacked.
* Not an agent platform. Anything that needs to *run on* an iPhone needs
  a separate on-device component you ship yourself; pods talk to it.
* Not anonymous. The log carries `chain=`, `exec=`, your target aliases,
  your IPs, and your actions. Tail it like a tool, not a diary.
