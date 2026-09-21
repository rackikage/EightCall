#!/usr/bin/env python3
"""nodebox_scout — where each layer of the VM chain can look OUTSIDE its env.

The trust stack (nodebox_layers) says what a process can ATTEST. This module
says where it can OBSERVE — specifically, where the network path leaves the
sandbox and who can see the real L2 at each hop.

Chain, as captured live on this machine (Colima + kind + pod):

    L0 hardware          Mac (Apple silicon)                no network identity
    L1 host kernel       macOS XNU, en0 192.168.8.113/24     <-- ONLY layer that
                         default gw 192.168.8.1                  sees the real LAN
    L2 hypervisor        Apple Virtualization.framework        gvproxy user-mode NAT
                         VM side gateway 192.168.5.2
    L3 guest kernel      Colima Linux VM
                         eth0 192.168.5.1/24, docker0 172.17.0.1,
                         br-* 172.18-172.23.0.1 (incl. kind bridge 172.20.0.1)
    L4 guest userspace   kind node "py-box-control-plane"
                         eth0 172.20.0.2/16, CNI gw 10.244.0.1 (veth)
    L5 process           pod netns 10.244.0.14/24
                         default via 10.244.0.1, DNS 10.96.0.10 (CoreDNS)

Every hop re-writes the source address (SNAT), so the observable identity
changes at each boundary:

    10.244.0.14  --CNI/kindnet-->  172.20.0.2  --Docker bridge-->  192.168.5.1
      pod                            kind node                      Colima VM
                 --gvproxy NAT-->  192.168.8.113  --en0-->  192.168.8.0/24
                                    host                           LAN

Practical consequences:
  * From L5/L4/L3 you can REACH the LAN (egress is NATed, not blocked) but you
    cannot see L2: no ARP of LAN hosts, no promiscuous capture of LAN traffic.
  * To observe the real segment you need a vantage at L1 (host en0) or a
    mirrored port — exactly the XNU/wire split in docs/telemetry-chain.
  * Identity of the scanner as seen by the target is the HOST IP
    (192.168.8.113), not the pod IP. Any per-source telemetry the target emits
    attributes the scan to the host, not to the cluster.
"""
from __future__ import annotations

import fcntl
import socket
import struct
from pathlib import Path

STACK = [
    {"layer": "HARDWARE", "who": "Apple silicon / Mac", "net": "-",
     "sees_lan_l2": False, "note": "no network vantage"},
    {"layer": "HOST_KERNEL", "who": "macOS XNU", "net": "en0 192.168.8.113/24 (gw 192.168.8.1)",
     "sees_lan_l2": True, "note": "ONLY layer with a real LAN vantage; mirror/tap here"},
    {"layer": "HYPERVISOR", "who": "Apple Virtualization.framework", "net": "gvproxy NAT (vm gw 192.168.5.2)",
     "sees_lan_l2": False, "note": "user-mode NAT; SNAT boundary #2"},
    {"layer": "GUEST_KERNEL", "who": "Colima Linux VM", "net": "eth0 192.168.5.1/24; docker0 172.17.0.1; br-* 172.18-172.23.0.1",
     "sees_lan_l2": False, "note": "Docker bridges live here; SNAT boundary #1"},
    {"layer": "GUEST_USERSPACE", "who": "kind node py-box-control-plane", "net": "eth0 172.20.0.2/16; CNI gw 10.244.0.1",
     "sees_lan_l2": False, "note": "kindnet CNI; pod egress NATed"},
    {"layer": "PROCESS", "who": "pod netns", "net": "10.244.0.14/24; default via 10.244.0.1; DNS 10.96.0.10",
     "sees_lan_l2": False, "note": "reaches LAN only via the NAT chain"},
]

# The observed SNAT rewrite chain (pod -> ... -> LAN)
EGRESS_HOPS = [
    {"from": "10.244.0.14", "boundary": "CNI/kindnet", "to": "172.20.0.2", "layer": "GUEST_USERSPACE"},
    {"from": "172.20.0.2", "boundary": "Docker bridge", "to": "192.168.5.1", "layer": "GUEST_KERNEL"},
    {"from": "192.168.5.1", "boundary": "gvproxy user-mode NAT", "to": "192.168.8.113", "layer": "HYPERVISOR"},
    {"from": "192.168.8.113", "boundary": "en0 (L2)", "to": "192.168.8.0/24", "layer": "HOST_KERNEL"},
]


def _iface_ip(name: str) -> str | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        packed = struct.pack("256s", name.encode()[:15])
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, packed)[20:24])  # SIOCGIFADDR
    except OSError:
        return None
    finally:
        s.close()


def capture_egress() -> dict:
    """Best-effort runtime capture of THIS process's egress identity.

    Linux-first (/proc); degrades gracefully elsewhere. No subprocess.
    """
    out: dict = {"interfaces": {}, "dns": [], "default_route": None}
    for idx, name in socket.if_nameindex():
        ip = _iface_ip(name)
        if ip:
            out["interfaces"][name] = ip
    try:
        for line in Path("/etc/resolv.conf").read_text().splitlines():
            if line.startswith("nameserver"):
                out["dns"].append(line.split()[1])
    except OSError:
        pass
    try:
        for line in Path("/proc/net/route").read_text().splitlines()[1:]:
            f = line.split()
            if f[1] == "00000000":  # default
                gw = socket.inet_ntoa(struct.pack("<L", int(f[2], 16)))
                out["default_route"] = {"dev": f[0], "gw": gw}
    except OSError:
        pass
    return out


def vantage_provenance() -> dict:
    """Provenance block a node/scanner can attach to telemetry."""
    egress = capture_egress()
    in_pod = bool(egress["default_route"] and egress["default_route"]["dev"].startswith("eth0")
                  and any(ip.startswith("10.244.") for ip in egress["interfaces"].values()))
    return {
        "observed_layer": "PROCESS",
        "sees_lan_l2": False,          # a process at L5 cannot see L2
        "identity_as_seen_by_target": egress["interfaces"].get("eth0")
                                        or next(iter(egress["interfaces"].values()), None),
        "likely_sandbox": "kubernetes-pod" if in_pod else "host-or-vm",
        "egress": egress,
        "note": "targets attribute this scanner to the HOST IP after SNAT, not the pod IP",
    }


def describe() -> dict:
    return {"stack": STACK, "egress_hops": EGRESS_HOPS}
