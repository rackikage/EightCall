#!/usr/bin/env python3
"""Emit ICMP echo request pcaps for iteration 7 (T1048.003).

Outputs:
  - icmp_exfil_attack.pcap  - one echo request with a 400-byte base64 payload
  - icmp_benign.pcap        - one echo request with a 56-byte ping-shaped payload

Classic pcap (linktype 1 = DLT_EN10MB), single packet per file, .example
addressing to guarantee zero real-world routing.
"""
from __future__ import annotations

import base64
import secrets

from scapy.all import ICMP, IP, Ether, Raw, wrpcap

CLIENT_IP, SERVER_IP = "10.0.0.5", "10.0.0.1"
CMAC, SMAC = "02:00:00:00:00:01", "02:00:00:00:00:02"


def make_icmp_echo(payload: bytes) -> Ether:
    return (
        Ether(src=CMAC, dst=SMAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / ICMP(type=8, code=0, id=0x1234, seq=1)
        / Raw(load=payload)
    )


if __name__ == "__main__":
    exfil_bytes = base64.b64encode(secrets.token_bytes(300))
    wrpcap("icmp_exfil_attack.pcap", [make_icmp_echo(exfil_bytes)], linktype=1)

    benign = bytes(range(56))
    wrpcap("icmp_benign.pcap", [make_icmp_echo(benign)], linktype=1)

    print(f"[+] wrote icmp_exfil_attack.pcap (payload={len(exfil_bytes)} bytes)")
    print(f"[+] wrote icmp_benign.pcap (payload={len(benign)} bytes)")
