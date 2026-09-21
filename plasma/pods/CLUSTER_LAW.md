# CLUSTER LAW v1

The governing identity/authorization spec for `fleet/pods`. This is not
guidance — it is enforced in code (see "Where this is enforced" below).
The law text itself is reproduced verbatim, unedited, as given by the
operator; anything below the divider is commentary, not part of the law.

---

```text
CLUSTER LAW v1

1. ONE TARGET = ONE POD
   Each enrolled target has exactly one logical pod identity.

   iphone01 -> pod-iphone01
   iphone02 -> pod-iphone02
   ipad01   -> pod-ipad01
```

The pod name is just the target-facing identity. You can rename it later
without changing the underlying device identity.

```text
device identity != pod name
pod name        != IP address
pod name        != current port
```

The fixed rules are:

```text
TARGET
  has one stable DEVICE_ID

POD
  belongs to exactly one TARGET

POD NAME
  is editable metadata

IP / PORT / RADIO
  may change freely

A
  watches all enrolled pods

C
  executes for one pod/target only

B
  rotates execution between pods

ROOT
  requires explicit root-exec authorization

UNKNOWN TARGET
  never becomes a pod automatically

DISCOVERY
  never equals enrollment

ROTATION
  never destroys old C until new C is healthy
```

So your cluster can be:

```text
cluster=ios-fleet

pod-iphone01 -> iphone01
pod-iphone02 -> iphone02
pod-ipad01   -> ipad01
pod-router   -> router
```

If you edit the cluster:

```text
rename pod        -> allowed
move pod group    -> allowed
change IP         -> allowed
change port       -> allowed
change transport  -> allowed
disable pod       -> allowed

copy DEVICE_ID    -> forbidden
copy private key  -> forbidden
auto-enroll scan  -> forbidden
```

And the execution law stays:

```text
A watches cluster
    ↓
C runs on one target pod
    ↓
B rotates to next eligible pod
    ↓
C runs there
```

That gives you editable cluster structure without making names,
addresses, ports, or radios part of identity.

---

## Where this is enforced

| Law | Enforced by |
|---|---|
| TARGET has one stable DEVICE_ID | `cluster.conf` — one row, `device_id` column, populated only via `cluster.sh enroll`. |
| POD belongs to exactly one TARGET (one target = one pod) | `cluster.sh enroll` refuses a `device_id` already enrolled under a different `pod_name` — see `_find_pod_by_device_id` in `lib_safety_gate.sh`. `cluster.sh validate` re-checks this statically over the whole file. |
| POD NAME is editable metadata | `cluster.sh rename --old NAME --new NAME2` moves the label, keeps `device_id` fixed. Reassigning an EXISTING pod name to a *different* `device_id` is refused unless `--force` is passed explicitly (a loud, logged, deliberate override — never silent). |
| IP / PORT / RADIO may change freely | `targets.conf` (`pod_name=ip`) is edited independently of `cluster.conf`; neither file's key touches the other's identity column. |
| UNKNOWN TARGET never becomes a pod automatically | `pod.sh`'s gate (`gate_check`, via `lib_safety_gate.sh`) denies dispatch to any alias with no `enabled` row in `cluster.conf` — being merely present in `targets.conf` is not enrollment. |
| DISCOVERY never equals enrollment | `test/router_diag.sh` is read-only and writes nothing to `cluster.conf`; nothing in `watcher.sh` (A) or `rotator.sh` (B) ever calls `cluster.sh` or writes to the ledger. The only path onto the ledger is an operator explicitly running `cluster.sh enroll`. |
| ROOT requires explicit root-exec authorization | An action opts into requiring root by shipping a `actions/<action>.root` sentinel file. `gate_check` then additionally requires the literal capability `root-exec` in the pod's grant list — on top of, never instead of, the action's own capability. A literal-IP dispatch (no pod identity) is refused unconditionally for any such action. |
| ROTATION never destroys old C until new C is healthy | Structural: `rotator.sh` calls `pod.sh` synchronously and only proceeds after it returns; there is no "retire" step in the current action set (`health`/`probe`/`inventory` are non-destructive reads) for this to violate. Any future stateful/rotating action must preserve this ordering explicitly (see `fleet/CLAUDE.md`'s open threads). |
| copy DEVICE_ID / copy private key forbidden | No script anywhere in `pods/` reads a private key (none exist for these stock-iOS targets today) or echoes a `device_id` outside `cluster.conf`/`cluster.log`. `pods.log`/`runs.jsonl` (the world-readable-by-convention operational logs) never carry a `device_id` field — only `pod_name`, `alias`, and `ip`. |
| auto-enroll scan forbidden | `test/router_diag.sh`'s own header states it "does not modify any state." No script fans discovery output (ARP tables, mDNS/Bonjour browsing, SSDP results) into `cluster.conf` or into a call to `cluster.sh enroll`. |

## Files

- `cluster.conf` — the enrollment ledger. Tab-separated:
  `pod_name<TAB>device_id<TAB>status<TAB>capabilities(csv)`. Hand-editing
  bypasses the uniqueness/reassignment checks; run `cluster.sh validate`
  immediately after if you do.
- `cluster.log` — one terse `key=value` line per gate decision (allow/deny)
  and per `cluster.sh` mutation (enroll/disable/enable/rename), audited
  separately from `pods.log`.
- `lib_safety_gate.sh` — read-only. `is_enrolled`, `capability_granted`,
  `requires_root`, `gate_check`. Sourced by `pod.sh`; never mutates
  `cluster.conf`.
- `cluster.sh` — the only sanctioned writer. `enroll` / `disable` /
  `enable` / `rename` / `validate` / `list`.
