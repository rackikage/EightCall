"""broker.grant — the capability object handed to action code.

Actions refuse to run without a Grant, and a Grant can only be constructed
through mint(). This raises the bar from "import the action module and call a
function" to "forge an internal object".

It is defence in depth, not a boundary. Python running in one account is not a
security boundary: code that can read this module can read the seal. The real
enforcement split is the Unix-account separation described in the design notes
(gate / exec / observe must not be the same principal).
"""
from __future__ import annotations

_SEAL = object()


class Grant:
    __slots__ = ("target_id", "action", "fencing", "params", "run_id", "_seal", "_used")

    def __init__(self, seal, target_id, action, fencing, params, run_id):
        if seal is not _SEAL:
            raise PermissionError("execution grants are minted only by the gate")
        self.target_id = target_id
        self.action = action
        self.fencing = int(fencing)
        self.params = dict(params or {})
        self.run_id = run_id
        self._seal = seal
        self._used = False

    def check(self, action):
        if self._seal is not _SEAL:
            raise PermissionError("invalid execution grant")
        if self._used:
            raise PermissionError("execution grant already consumed")
        if self.action != action:
            raise PermissionError("execution grant scope mismatch")

    def consume(self):
        if self._used:
            raise PermissionError("execution grant already consumed")
        self._used = True

    def __reduce__(self):
        raise TypeError("execution grants are not serializable")


def mint(target_id, action, fencing, params, run_id):
    return Grant(_SEAL, target_id, action, fencing, params, run_id)
