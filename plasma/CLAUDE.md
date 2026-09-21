# fleet — Claude handoff

`fleet/` is a Tor-hidden-service NestJS deployment (`gateway/` + `node/`,
unchanged in this phase) with a separate bash implementation of the
user's A/C/B architecture at `pods/`. The pods tree is the active
surface; the others are not being modified.

**This file is edited by more than one session.** `fleet/pods/` has had
concurrent work land from at least two sessions in the same sitting
(the safety gate below, and a separate `state-receiver`/`recon/` effort — see
"Concurrent work" below). Re-run `git log --oneline -10` and `git status`
before trusting anything in this file's Status section — it goes stale
fast. The previous version of this file was itself already one generation
behind HEAD when this rewrite happened.

## Status (re-verify before trusting)

- `pods/test/test_pods.sh`: **45 pass / 0 fail**, bash 3.2-portable, run 3x
  for stability. Covers pod.sh's existing contract, the safety gate below,
  A's eligibility, B's cooldown, and `killswitch.sh`.
- B628 UPnP IGD: confirmed unusable (only `WANPPPConnection:1`; miniupnpc
  needs `WANIPConnection:1`). UPnP dispatch (`expose`/`unexpose`,
  `ROTATE_EXPOSE`, `broker.jsonl`) was removed from the working set — don't
  reintroduce it without a router that actually has the right IGD service.
  `test/router_diag.sh` (read-only LAN diagnostic) still probes for UPnP
  for *discovery* purposes; that's fine, only *dispatch* was removed.

## Safety gate — CLUSTER LAW v1 (new this session)

`fleet/pods` now has a deny-by-default authorization boundary between a
dispatch request (alias + action) and actually running an `actions/*.sh`
script. The full spec is `pods/CLUSTER_LAW.md` — read it before touching
`pod.sh`, `cluster.sh`, or `lib_safety_gate.sh`. Short version:

- `targets.conf` (alias→ip) is **location**, not **identity**. Being in
  it gives a target an IP; it does not authorize dispatch.
- `cluster.conf` (new) is the **enrollment ledger**:
  `pod_name<TAB>device_id<TAB>status<TAB>capabilities`. A `device_id` is
  an operator-asserted opaque string — nothing in this repo can derive a
  stable ID for a stock iOS target on its own, so nothing auto-populates
  this file. Ships empty on purpose.
- `cluster.sh` is the **only** sanctioned writer (`enroll` / `disable` /
  `enable` / `rename` / `validate` / `list`). It enforces one-target-one-
  pod (a `device_id` can't be enrolled under two pod names), refuses
  reassigning an existing pod name to a different `device_id` unless
  `--force` is passed explicitly, and `rename` moves only the label.
- `lib_safety_gate.sh` is **read-only** (`is_enrolled`, `capability_granted`,
  `requires_root`, `gate_check`). `pod.sh` sources it and calls
  `gate_check "$ALIAS" "$ACTION"` before dispatching any alias-resolved
  target — deny-by-default: no cluster.conf row, a disabled row, or a
  capability not in the row's CSV list all refuse, exit 5, logged to both
  `pods.log` (`reason=gate_denied`) and the new `cluster.log` (terse
  `key=value` per decision).
- **Literal-IP dispatch is intentionally NOT gated** for an ordinary
  action (there is no pod identity to check against — this is
  unchanged, pre-existing behavior, matches the old test #4). It **is**
  refused unconditionally for a root-requiring action (see below), since
  no pod exists there to hold that grant.
- **root-exec**: an action opts into requiring root by shipping a
  same-named `actions/<action>.root` sentinel (empty file) next to its
  `.sh`. The gate then additionally requires the literal capability
  `root-exec` in the pod's grant list — on top of, never instead of, the
  action's own capability. No shipped action requires this today; it
  exists so a future privileged action (`admin-shell`, a NAT-map path
  that needs elevated access, etc.) can opt in with **zero changes to
  `pod.sh`** — just a `.root` file and a capability grant.
- Nothing on the automatic A→B→C path calls `cluster.sh` or writes to
  `cluster.conf`. Enrollment is a deliberate, explicit, operator-driven
  act — "discovery never equals enrollment," and `test/router_diag.sh`'s
  own header already states it modifies no state.

**Files added:** `pods/CLUSTER_LAW.md`, `pods/cluster.conf` (empty
template), `pods/cluster.sh`, `pods/lib_safety_gate.sh`.
**Files edited (minimal, additive — see git diff, not a rewrite):**
`pods/pod.sh` (one new gate-check block + a sourced library, zero changes
to any existing branch/exit-code/log-line), `pods/pods.conf`
(`CLUSTER_CONF`/`CLUSTER_LOG` defaults), `pods/install.sh` (installs the
two new scripts; **never overwrites an existing `cluster.conf`, even with
`--force`** — that would silently un-enroll every pod), `pods/README.md`,
`pods/test/test_pods.sh` (+19 gate assertions, all pre-existing assertions
still pass unchanged).

**Before enrolling anything for real**, decide what `device_id` values to
use for `iphone01`/`iphone02`/`ipad01`/the router — this is an operator
decision, not something to automate. See `pods/README.md`'s "Enroll a pod"
section for the exact commands.

## Concurrent work (state-receiver / scans) — not this session's, don't touch blind

While the safety gate above was being built, a **separate, concurrent
session** added (now committed — see `git log`, commits around
`0fc2890`/`0ae5c00`):

- `pods/state-receiver.sh` / `pods/state_receiver.py` — an inbound-only endpoint
  (currently a bare-socket line protocol, not HTTP+JSON — it was reworked
  mid-flight; re-read it before assuming its shape) for owned nodes to
  dial back and report state. **As of this writing it only receives and
  logs — it does not call `pod.sh` or dispatch anything.** If a future
  version starts dispatching work based on an inbound report, that
  dispatch **must** go through the same `gate_check()` as A/B do — don't
  let a second entry point bypass CLUSTER LAW.
- `pods/recon/` — nmap scan output (`.nmap`/`.gnmap`/`.xml`) for
  `iphone01`/`iphone02`/`ipad01`. Read-only artifacts from a
  reconnaissance step; not wired into anything else yet.

Two install.sh/test_pods.sh edits landed from *both* sessions in the same
window and needed re-merging by hand (a real collision, not hypothetical
— check `git log` timestamps if you need the detail). If you're a fresh
session picking this up: **diff against `git show HEAD~3:pods/install.sh`
or similar before assuming any single commit's message describes
everything that commit's diff contains** — commits here have had more in
them than their subject line during concurrent-editing windows.

## Open threads

1. **Populate `cluster.conf` for real.** Ships empty by design (see
   above) — an operator must run `cluster.sh enroll` for each real pod
   before the rotator can dispatch to it. Until then, an enrolled-but-
   never-populated cluster means every alias-based dispatch is correctly
   denied (fail-closed, not a bug).
2. **Wire state-receiver's future dispatch path (if/when it gets one)
   through the gate.** See "Concurrent work" above.
3. **Pick the NAT path** for the router, now framed as a `nat-map`
   capability rather than UPnP. Four options, in order of preference:
   authenticated web UI (credentials via env, never on disk); SSH/Telnet
   on the LAN (host key pinned); vendor recovery/serial console
   (human-in-the-loop, out of scope for the pod layer); reverse SSH
   tunnel from a different owned LAN node (controller runs the SSH
   *server*, pinned host key). When built, `actions/nat-map.sh` should
   ship a `.root` sentinel if it needs elevated access, and get its
   capability wired through `cluster.conf` like any other action — no
   `pod.sh` changes needed.
4. **Targets are unreachable from this host** (last checked: all three
   enrolled iPhones/iPads silent on ICMP from 192.168.8.113). Bring one
   online, or use a loopback-only dry run (`targets.conf:
   loopback=127.0.0.1`, `cluster.sh enroll --pod loopback ...`) to
   exercise the full pipeline without LAN targets.

## Refusals (explicit, do not negotiate)

- **No credentials in the repo.** Any router admin password or similar
  belongs in an env var from the operator's shell, never on disk.
- **No unauthenticated listener on the controller.** If something tunnels
  in, the owned LAN node is the SSH *client*, the controller runs the
  SSH *server* with a pinned host key. Never the other way round.
- **No stealth / backdoor / auth bypass on the router or any target.**
  Every capability is enrolled and explicit — CLUSTER LAW v1's "auto-
  enroll scan forbidden" and "discovery never equals enrollment" apply to
  every future addition, not just the safety gate itself.
- **No copying a `device_id` or a private key out of `cluster.conf` (or
  anywhere else).** `pods.log`/`runs.jsonl` never carry a `device_id`
  field — only `pod_name`/`alias`/`ip`.
- **No rewrite of working components.** `watcher.sh`, `rotator.sh`,
  `lib_eligibility.sh`, and `actions/{health,probe,inventory}.sh` remain
  untouched. `pod.sh`/`pods.conf`/`install.sh`/`test_pods.sh` received
  small, additive, fully-tested edits to wire in the safety gate — not a
  rewrite (see the git diff for each; every pre-existing test still
  passes unchanged). Future dispatch-path additions (`nat-map.sh`,
  `route-inspect.sh`, `admin-shell.sh`) need **zero further edits to
  `pod.sh`** — just a capability grant in `cluster.conf` and, if
  privileged, a `.root` sentinel.

## Architectural invariants to preserve

- **Stable device identities.** CLUSTER LAW v1: one target = one pod;
  `device_id` is fixed at enrollment, `pod_name` is editable metadata,
  IP/port/radio move freely. Rotation moves placement; it does not move
  identity.
- **Transactional handoff.** New C is healthy before old C is retired.
  Failed replacement does not retire the previous exposure. (No current
  action is stateful/retiring — `health`/`probe`/`inventory` are
  non-destructive reads — so nothing today can violate this; a future
  rotating action must preserve the ordering explicitly.)
- **One event per line, terse key=value.** `CHAIN_ID` groups a rotation,
  `EXEC_ID` identifies one execution, `HOP` counts successful placements.
  Gate decisions and cluster mutations go to `cluster.log`, kept separate
  from `pods.log`/`runs.jsonl`.
- **Privileged work is its own capability.** `root-exec` is explicit
  (a `.root` sentinel + an explicit grant), never implicit in being C.
- **`killswitch.sh` is the hard stop.** Never touches unrelated processes,
  unrelated SSH/system services, unrelated logs, or `state-receiver` (which
  is deliberately outside `killswitch.sh`'s scope — stop it explicitly).
- **Deny-by-default, audited.** An empty or missing capability list
  grants nothing. Every gate decision is logged, allow or deny.

## Test conventions

- **bash 3.2 portable.** macOS ships bash 3.2.57; `declare -A`,
  `${var,,}`, `case ;&` fallthrough, `mapfile`, GNU `timeout`,
  GNU `gtimeout` are all unavailable. Do not use them.
- **awk is BWK awk (one-true-awk), not gawk.** No `arr[i][j]` nested
  arrays — use a `SUBSEP`-keyed single-dimension array instead
  (`cluster.sh`'s `validate` command is the reference example).
- **Daemon tests use the background + sleep + `kill -TERM` pattern**
  (`kill -TERM "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null ||
  true`). Do not reintroduce GNU `timeout`.
- **Tests build a throwaway `PODS_HOME` under `$TMPDIR`** (never touch
  the real `~/pods/`). New scripts that need mirroring into that
  throwaway tree get a `cp`/`install` line in `test_pods.sh`'s setup
  block, matching the existing `lib_eligibility.sh`/`pod.sh` pattern.
- **Deterministic test actions over real ones for gate assertions.**
  `probe.sh`'s exit code depends on real TCP/port state and is not a
  reliable success signal in a sandbox; the gate tests use a synthetic
  always-`exit 0` action (`okaction.sh`, created inline in the test's
  throwaway tree) instead.
