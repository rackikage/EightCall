"""broker.failpoints — deterministic crash injection for destructive tests.

Test-only. A no-op unless the process environment sets BROKER_FAILPOINT to the
name of a hook. When it matches, the process is SIGKILLed at that exact point,
which lets the stress suite prove what state a crash leaves behind at each
persistence boundary.

Hard-disabled in service mode: if BROKER_SERVICE=1 the hook is ignored entirely,
so a failpoint can never become a standing self-DoS lever in a real deployment.
"""
from __future__ import annotations

import os
import signal


def hit(name: str) -> None:
    if os.environ.get("BROKER_SERVICE") == "1":
        return
    if os.environ.get("BROKER_FAILPOINT") == name:
        os.kill(os.getpid(), signal.SIGKILL)
