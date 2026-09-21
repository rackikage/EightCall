#!/usr/bin/env python3
"""nodebox trust-stack model.

The nodebox agent runs at the BOTTOM of a layered trust stack:

    hardware
      |
    host kernel
      |
    hypervisor
      |
    guest kernel
      |
    guest userspace
      |
    your process  <-- nodebox agent lives here

A process at that layer can observe and attest to its OWN identity and
immediate userspace facts. It cannot, on its own, attest the layers below it
(guest kernel, hypervisor, host kernel, hardware) -- that requires an EXTERNAL
anchor (measured boot / IMA, an attestation service, a hardware-rooted key).

So the agent's attestation is deliberately HONEST ABOUT ITS SCOPE: it declares
`attestation.depth = PROCESS` and lists the layers it does NOT attest. The
controller refuses to let an L5 attestation stand in for a lower layer. This is
the difference between "looks legitimate" and "is attributable": the provenance
records exactly which layer asserted which fact, and nothing is implied upward.
"""
from __future__ import annotations

import enum
import hashlib
import os
import platform
import pwd
import sys
from dataclasses import dataclass
from pathlib import Path


class Layer(enum.IntEnum):
    HARDWARE = 0
    HOST_KERNEL = 1
    HYPERVISOR = 2
    GUEST_KERNEL = 3
    GUEST_USERSPACE = 4
    PROCESS = 5


STACK = [
    Layer.HARDWARE,
    Layer.HOST_KERNEL,
    Layer.HYPERVISOR,
    Layer.GUEST_KERNEL,
    Layer.GUEST_USERSPACE,
    Layer.PROCESS,
]


@dataclass(frozen=True)
class LayerFact:
    layer: Layer
    name: str
    trust_anchor: str
    observable: str   # yes | partial | no  (from the process)
    attestable: str   # yes | partial | no  (self; external anchor needed for < PROCESS)
    note: str


STACK_FACTS: dict[Layer, LayerFact] = {
    Layer.HARDWARE: LayerFact(
        Layer.HARDWARE, "hardware", "OEM silicon / TPM / Secure Enclave",
        "no", "no", "only via a hardware-rooted key or a signed quote",
    ),
    Layer.HOST_KERNEL: LayerFact(
        Layer.HOST_KERNEL, "host kernel", "host OS vendor",
        "no", "no", "invisible from the guest; host-side attestation only",
    ),
    Layer.HYPERVISOR: LayerFact(
        Layer.HYPERVISOR, "hypervisor", "VMM operator",
        "partial", "no", "guest can see it exists (virtio/timing) but not its integrity",
    ),
    Layer.GUEST_KERNEL: LayerFact(
        Layer.GUEST_KERNEL, "guest kernel", "guest OS + measured boot",
        "partial", "partial", "syscall surface visible; integrity needs IMA/measured boot + verifier",
    ),
    Layer.GUEST_USERSPACE: LayerFact(
        Layer.GUEST_USERSPACE, "guest userspace", "service manager (launchd/systemd)",
        "yes", "partial", "the launching service unit is attributable to the agent",
    ),
    Layer.PROCESS: LayerFact(
        Layer.PROCESS, "your process", "nodebox identity key",
        "yes", "yes", "self: identity key, code digest, capability manifest, argv0",
    ),
}

# external anchors that let the agent's attestation legitimately reach BELOW its
# own layer. Absent any of these, the scope stops at GUEST_USERSPACE (when a
# supervisor launched it) or PROCESS (interactive).
ANCHORS = ("supervisor", "measured_boot", "attestation_service", "host_attestation", "hardware_root")


def supervisor_identity() -> dict:
    """Which approved service manager launched this process, if any.

    Detected from the environment the service manager sets -- no subprocess, no
    process-name sniffing. 'interactive' means a human shell, which is still
    attributable via the initiator user + tty.
    """
    if os.environ.get("XPC_SERVICE_NAME"):
        return {"kind": "launchd", "unit": os.environ["XPC_SERVICE_NAME"]}
    if os.environ.get("INVOCATION_ID") or os.environ.get("JOURNAL_STREAM"):
        return {"kind": "systemd", "unit": os.environ.get("SYSTEMD_UNIT") or os.environ.get("INVOCATION_ID")}
    return {"kind": "interactive", "unit": os.environ.get("TERM") or "tty"}


def code_digest(package_root: Path) -> str:
    """SHA-256 over the nodebox source tree -- the exact code that is running."""
    h = hashlib.sha256()
    for path in sorted(package_root.rglob("*.py")):
        h.update(path.name.encode())
        h.update(path.read_bytes())
    return h.hexdigest()


def process_provenance(package_root: Path | None = None) -> dict:
    """Facts the PROCESS layer can honestly attest about itself."""
    root = package_root or Path(__file__).resolve().parent
    try:
        user = pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        user = str(os.getuid())
    return {
        "layer": "PROCESS",
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "uid": os.getuid(),
        "user": user,
        "argv0": Path(sys.argv[0]).name,
        "cwd": os.getcwd(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "supervisor": supervisor_identity(),
        "code_digest": code_digest(root),
    }


def attestation_scope(anchors: list[str] | None = None) -> dict:
    """What this process's signed attestation actually covers, and what it does not."""
    have = {a for a in (anchors or []) if a in ANCHORS}
    attested = [Layer.PROCESS]
    if "supervisor" in have:
        attested.append(Layer.GUEST_USERSPACE)
    if "measured_boot" in have:
        attested.append(Layer.GUEST_KERNEL)
    if "attestation_service" in have:
        attested.append(Layer.HYPERVISOR)
    if "host_attestation" in have:
        attested.append(Layer.HOST_KERNEL)
    if "hardware_root" in have:
        attested.append(Layer.HARDWARE)

    not_attested = [L for L in STACK if L not in attested]
    # depth = the DEEPEST (lowest) layer attested; attesting toward hardware is
    # stronger, so min by layer value, not max.
    depth = min(attested)
    return {
        "depth": depth.name,
        "depth_level": int(depth),
        "attested": [L.name for L in attested],
        "not_attested": [L.name for L in not_attested],
        "anchors": sorted(have),
    }


def describe_stack() -> list[dict]:
    return [
        {
            "layer": f.layer.name,
            "name": f.name,
            "trust_anchor": f.trust_anchor,
            "observable": f.observable,
            "attestable": f.attestable,
            "note": f.note,
        }
        for f in (STACK_FACTS[L] for L in STACK)
    ]
