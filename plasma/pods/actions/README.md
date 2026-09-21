# plasma/pods/actions — the typed actions a pod may run

Each script is one enumerated capability a pod invokes against a target
(`$1 = alias`, `$2 = ip`). Nothing else runs: `pod.sh` dispatches only these
files, gated by `lib_safety_gate.sh`. All are read-only or best-effort probes
of hosts you own — no exploitation, no payloads.

- `health.sh` — single ICMP reachability + latency.
- `inventory.sh` — reverse DNS + ARP MAC + optional banner read (best-effort,
  always exits 0; that non-strict exit is the contract, not an oversight).
- `probe.sh` — TCP connect probe of the enumerated `PROBE_PORTS` only.

## Safety

Only test electronics you own. Authorized systems only. Loopback-bound by
default (`127.0.0.1`/`::1`); these actions dial owned targets and open no
listeners. No evasion — every run is recorded. No arbitrary execution: only
the typed actions in this folder, dispatched through the safety gate. No
secrets in git.
