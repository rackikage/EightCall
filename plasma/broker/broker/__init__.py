"""broker — authorized control plane (enforcement-first).

Laws encoded in code, not convention:
  * ONE TARGET = ONE POD          -> UNIQUE(enrollments.target_id)
  * UNKNOWN TARGET NEVER ENROLLS  -> FK + existence check in enroll()
  * DISCOVERY != ENROLLMENT       -> observations never create enrollments
  * active_C(T) <= 1              -> exclusive lease per target
  * stale C is harmless           -> fencing token monotonic, checked at use
  * replay is impossible          -> UNIQUE(req_digest) + single-use tokens
  * identity, not claims          -> Ed25519; the gate holds PUBLIC keys only
  * no token => no action         -> run_authorized() requires a gate-signed token
  * consume == record run         -> claim_run() is one transaction
  * policy cannot roll back       -> signed envelope + monotonic version
  * fail closed, always           -> denials, bad input and bugs never traceback

What is NOT yet enforced in-process: the gate, signer and executor still share
one Unix account (defence in depth, not a boundary). See the hardening notes.
"""

__version__ = "2.0.0"

# --- platform_runtime bootstrap ----------------------------------------------
# broker lives at fleet/broker/broker/; platform_runtime/ is at the repo root.
# The workspace does not `pip install -e .` either package (both are run in
# place), so make the sibling importable regardless of how the CLI is invoked
# (PYTHONPATH from selftest, `python -m broker`, or a `broker` launcher).
import sys as _sys
from pathlib import Path as _Path
_REPO_ROOT = _Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_REPO_ROOT))
del _sys, _Path
