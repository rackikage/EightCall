# plasma/acb — agent / control / broker (mTLS proof-of-possession)

The Python package (`acb/`) and its Termux driver scripts (`bin/pod.sh`,
`bin/rotator.sh`, `bin/watcher.sh`). A target runs `acb agent` — an mTLS
listener that only proves possession of an enrolled key and runs typed,
signed-lease actions. Nothing runs without a signed allow; deny is the default
(`gate.py`, `grant.py`).

## Binding

`acb agent` binds the enrolled target's own address (`--host` defaults to the
target row's address, not the wildcard) behind an mTLS server context gated by
the CA. It is a mutually-authenticated listener on an owned device, not an open
port. Keep target addresses on networks you control; reach them over loopback
forwards where possible.

## Safety

Only test electronics you own. Authorized systems only. Loopback-bound by
default (`127.0.0.1`/`::1`); listeners are mTLS-gated and address-scoped, never
`0.0.0.0`. No evasion — attribution is the design. No arbitrary execution:
typed capabilities only, no signed allow means no action. No secrets in git.
