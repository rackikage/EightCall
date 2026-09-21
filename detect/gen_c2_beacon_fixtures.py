#!/usr/bin/env python3
"""Emit enriched-flow fixtures for the C2 relay/beacon rule (T1071/T1090/T1573).

Outputs newline-delimited flow records (key=value, one flow per line) in the
shape a beacon analyzer would export — Zeek conn/ssl/http joined with a
RITA-style beacon scorer, or a forward-proxy log enricher. These are the
DEFENSIVE counterpart to a redirector cluster: they reproduce the *telemetry*
such a cluster emits at the wire so `rules/c2_relay_beacon.yml` can be proven
to fire, without standing up any relay, redirector, or C2 channel.

Outputs:
  - c2_beacon_attack.flowlog  - two flows that should ALERT
      a1: fronted beacon through a 2-hop relay tier (SNI != Host)
      a2: regular beacon egressing a 1-hop relay tier (SNI == Host)
  - c2_beacon_benign.flowlog  - two flows that should NOT alert
      b1: bursty human CDN traffic (high jitter), direct, aligned
      b2: fixed-interval legit poller, DIRECT egress, aligned  <-- the key
          true-negative: regular timing alone must not alert

Addressing is documentation-only: implant 10.0.0.9 (RFC1918), relays in
203.0.113.0/24 (TEST-NET-3, RFC5737), .example names (RFC2606) — zero
real-world routing, and nothing here dials out.
"""
from __future__ import annotations

# fields: analytic enrichment a flow/beacon scorer must populate.
# tls.front is aligned|mismatch (computed from SNI vs Host); dst.relay_tier is
# the hop count through UNTRUSTED redirectors (0 = direct egress).
FIELDS = (
    "flow.id", "ts", "src", "dst", "dst.relay_tier",
    "network.protocol", "tls.sni", "tls.host", "tls.front",
    "beacon.interval_s", "beacon.jitter_pct", "bytes_out", "bytes_in", "note",
)

ATTACK = [
    {
        "flow.id": "a1", "ts": "2026-09-18T00:00:00Z",
        "src": "10.0.0.9", "dst": "203.0.113.7", "dst.relay_tier": 2,
        "network.protocol": "tls",
        "tls.sni": "cdn.frontable.example", "tls.host": "login-portal.example",
        "tls.front": "mismatch",
        "beacon.interval_s": 60, "beacon.jitter_pct": 7,
        "bytes_out": 812, "bytes_in": 126,
        "note": "fronted beacon via 2-hop relay: SNI!=Host + regular callback",
    },
    {
        "flow.id": "a2", "ts": "2026-09-18T00:00:45Z",
        "src": "10.0.0.9", "dst": "203.0.113.12", "dst.relay_tier": 1,
        "network.protocol": "tls",
        "tls.sni": "api.telemetry.example", "tls.host": "api.telemetry.example",
        "tls.front": "aligned",
        "beacon.interval_s": 45, "beacon.jitter_pct": 10,
        "bytes_out": 640, "bytes_in": 96,
        "note": "regular beacon egressing a 1-hop relay tier (no fronting)",
    },
]

BENIGN = [
    {
        "flow.id": "b1", "ts": "2026-09-18T00:01:00Z",
        "src": "10.0.0.9", "dst": "198.51.100.30", "dst.relay_tier": 0,
        "network.protocol": "tls",
        "tls.sni": "cdn.example", "tls.host": "cdn.example",
        "tls.front": "aligned",
        "beacon.interval_s": 4, "beacon.jitter_pct": 68,
        "bytes_out": 1503, "bytes_in": 482113,
        "note": "bursty human CDN download: high jitter, direct, aligned",
    },
    {
        "flow.id": "b2", "ts": "2026-09-18T00:02:00Z",
        "src": "10.0.0.9", "dst": "198.51.100.44", "dst.relay_tier": 0,
        "network.protocol": "tls",
        "tls.sni": "update.example", "tls.host": "update.example",
        "tls.front": "aligned",
        "beacon.interval_s": 64, "beacon.jitter_pct": 3,
        "bytes_out": 220, "bytes_in": 180,
        "note": "fixed-interval legit poller: regular BUT direct + aligned -> no alert",
    },
]


def render(flow: dict) -> str:
    parts = []
    for key in FIELDS:
        val = flow[key]
        parts.append(f'{key}="{val}"' if " " in str(val) else f"{key}={val}")
    return " ".join(parts)


def write(path: str, flows: list[dict]) -> None:
    with open(path, "w") as fh:
        fh.writelines(render(flow) + "\n" for flow in flows)


if __name__ == "__main__":
    write("c2_beacon_attack.flowlog", ATTACK)
    write("c2_beacon_benign.flowlog", BENIGN)
    print(f"[+] wrote c2_beacon_attack.flowlog ({len(ATTACK)} flows -> expect ALERT)")
    print(f"[+] wrote c2_beacon_benign.flowlog ({len(BENIGN)} flows -> expect no alert)")
