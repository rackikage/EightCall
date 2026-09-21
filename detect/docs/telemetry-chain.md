# Telemetry chain — a relay cluster, seen from the defence

This document maps the C2 **relay/redirector cluster** the way a hunter sees it:
each hop as a *source of telemetry*, and the detect rule or field that catches
it. It describes the adversary infrastructure's **observable shape** so the
detections can be aimed at it — it is not a build or operator guide.

> **What this is not.** No redirector configuration, no C2 profile, no fronting
> setup, no payload. Standing up or operating a relay is out of scope for this
> repo, which ships only the hunt (`rules/`) and the gate (`authz_*`). Every
> address here is documentation-only (RFC 5737 / RFC 1918 / RFC 2606).

## The shape being detected — a 3×2 redirector cluster ("X6")

Adversaries rarely point an implant straight at the C2 brain. They interpose a
**redirector tier**: a fan of cheap, disposable hops that relay operator traffic
inward and break the link between the beacon and the real controller (resilience
+ attribution-breaking, ATT&CK **T1090**). A common shape is two tiers of three
redirectors — six relays, `3 × 2` — so any single seizure loses one hop, not the
channel.

The point of this doc: **that topology is not invisible.** Fronting, tiering,
and automated beaconing each leave a wire signature, and none of them need a
host agent or a kernel vantage to see — they are all readable at the router.

```
  implant (10.0.0.9)
      │  regular low-jitter beacon  ── beacon.interval_s / beacon.jitter_pct
      ▼
  ┌───────── tier 1 (edge redirectors) ─────────┐   dst.relay_tier = 1
  │  R1a          R1b          R1c               │   TLS SNI ≠ HTTP Host
  │ 203.0.113.7  203.0.113.8  203.0.113.9        │   ── tls.front = mismatch
  └───────┬──────────┬────────────┬──────────────┘   (domain fronting, T1090.004)
          ▼          ▼            ▼
  ┌───────── tier 2 (long-haul relays) ──────────┐   dst.relay_tier = 2
  │  R2a          R2b          R2c               │   shared TLS fingerprint / JA3
  │ 203.0.113.12 203.0.113.13 203.0.113.14       │   reused across the fan
  └───────────────────┬──────────────────────────┘
                      ▼
                 C2 controller  ── never contacted by the implant directly;
                                    the wire only ever sees a relay hop
```

## Hop → telemetry → detection

| Where | What the adversary does | Wire-observable signature | Caught by |
|-------|-------------------------|---------------------------|-----------|
| implant → tier 1 | automated check-in on a timer | regular interval, low jitter | `c2_relay_beacon.yml` · `beacon_regular` (`beacon.jitter_pct\|lte:15` + `beacon.interval_s\|gte:1`) |
| implant → tier 1 | domain fronting: real dest hidden behind an allowed SNI | `tls.sni` ≠ HTTP `Host` | `c2_relay_beacon.yml` · `fronting_mismatch` (`tls.front: mismatch`) |
| tier 1 → tier 2 | traffic egresses through untrusted redirector hops | hop count through non-sanctioned relays | `c2_relay_beacon.yml` · `relay_egress` (`dst.relay_tier\|gte:1`) |
| any hop | shell/tunnel pivot riding SSH between relays | sshd `direct-tcpip` / `forwarded-tcpip`, remote-forward bind | `sshd_abuse.yml` · `forwarding_channel` / `remote_forward_listen` (T1572) |
| any hop | low-and-slow data siphon over an alt protocol | oversized / base64 ICMP echo payload | `icmp_exfil.yml` (T1048.003) |

The decisive rule for the cluster is **`c2_relay_beacon.yml`**: it does **not**
fire on regularity alone (a legitimate update poller beacons too), only on
regularity **combined with** a relay or fronting indicator — the shape that
distinguishes a redirector-fronted channel from a direct, aligned poll. See its
`falsepositives:` for what that deliberately excludes.

## Where in the stack each signal is readable (the XNU split)

The earlier design question — *how much do we need on the device?* — resolves to
a vantage split. The kernel is **XNU** (Mach core + BSD/Unix layer + Apple
drivers/frameworks); most of the relay chain is visible **before** you ever need
a kernel vantage.

```
  wire @ router            BSD exec via EndpointSecurity      Mach / XPC
  (available now)          (host stage, entitled/supervised)  (deferred)
 ┌────────────────────┐   ┌───────────────────────────────┐  ┌────────────────┐
 │ beacon timing      │   │ ES_EVENT_TYPE_NOTIFY_EXEC     │  │ task ports,    │
 │ SNI≠Host fronting  │──▶│ full argv: the `| bash` the   │─▶│ port rights,   │
 │ relay-tier hops    │   │ wire cannot see               │  │ XPC messaging  │
 │ ICMP exfil         │   │ (ios_shell_abuse.yml consumes │  │ (gate's own    │
 │                    │   │  this argv stream)            │  │  boundary)     │
 └────────────────────┘   └───────────────────────────────┘  └────────────────┘
  no agent, no kernel       needs an entitled EndpointSecurity  not required for
  → the whole network       client (macOS / supervised iOS);    the network chain;
  chain of the cluster      stock third-party iOS has no         this is the
                            system-wide exec/argv stream         "land in kernel"
                                                                 stage, left for later
```

- **Wire / router — available now, no kernel.** The full network chain of the
  cluster (beacon → fronting → relay hops → exfil) is readable from mirrored
  traffic or an enriched proxy log. This is where `c2_relay_beacon.yml`,
  `icmp_exfil.yml`, and the network side of `sshd_abuse.yml` operate — the
  vantage that needs only a router, matching the "no kernel yet" design.
- **BSD exec via EndpointSecurity — the host stage.** The one thing the wire
  cannot show is the executed `curl … | bash` / argv. That comes from the BSD
  layer's `posix_spawn`/`execve` surfaced through **EndpointSecurity**
  (`ES_EVENT_TYPE_NOTIFY_EXEC`), which is exactly what `ios_shell_abuse.yml`
  consumes. It requires an entitled ES client (macOS, or a supervised device),
  which is why stock third-party iOS cannot produce those command lines — the
  rule's own `logsource` note says as much.
- **Mach / XPC — deferred.** Task ports, port rights, and XPC messaging are the
  deepest, least accessible vantage. XPC is also where the **authorization gate**
  sits (`authz_gate.py` guards that boundary). Observing it is not needed for the
  network chain and is left for later — the "land in kernel" stage.

## What runs today

Everything in the two tables above is exercised by the repo's fixtures — no
relay, redirector, or C2 channel is created:

```bash
./venv69/bin/python3 gen_c2_beacon_fixtures.py               # emit benign + attack flow fixtures
./venv69/bin/python3 validate_rules.py                       # prove the rule fires on attack, not benign
./venv69/bin/python3 pysigma_shells.py rules/c2_relay_beacon.yml   # real pySigma: validate + compile
```

The fixtures reproduce the *telemetry* a cluster emits (`c2_beacon_attack.flowlog`
/ `c2_beacon_benign.flowlog`); the rule proves the detection; the gate decides
any response. Emulate the signal → hunt it → gate the answer — no working relay
in the repo.
