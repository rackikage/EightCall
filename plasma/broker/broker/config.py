"""broker.config — the broker's typed configuration schema.

Adopts the `platform_runtime` contract (see /platform_runtime/README.md).

Resolution order (high wins):
    CLI flags > env > --config file > user config > system config > defaults

Env map preserves every historical `BROKER_*` name so existing scripts,
selftests, launchers, and CI steps keep working without edits. The only
change is that these values now flow through `resolve_config()` and are
validated *before* any command touches state or binds a listener.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

# Make platform_runtime importable from the broker's PKG_ROOT-based tests too.
_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from platform_runtime import Config
from platform_runtime.errors import ConfigInvalid


@dataclass
class BrokerConfig(Config):
    # State layout — all `0o600`/`0o700` in HOME, per broker.cli._secure_home().
    home: Path = field(default_factory=lambda: Path.home() / "data" / "broker")
    keydir: Path = field(default_factory=lambda: Path.home() / ".broker-keys")
    # Optional witness URL used by verify/checkpoint; empty means "no witness".
    witness_url: str = ""
    # Service mode: hardens a few operator-only paths (see failpoints.py,
    # _secure_home). Present as config so `config show` reflects reality.
    service_mode: bool = False
    # Test-only fault injection; strictly no-op under service_mode.
    failpoint: str = ""

    def __post_init__(self) -> None:
        # Preserve every historical BROKER_* env name — same wire as today.
        self.ENV_MAP = {
            "home": "BROKER_HOME",
            "keydir": "BROKER_KEYDIR",
            "witness_url": "BROKER_WITNESS_URL",
            "service_mode": "BROKER_SERVICE",
            "failpoint": "BROKER_FAILPOINT",
        }

    def validate(self) -> None:
        # `home` must not be a symlink and, if it exists, must be owned by us
        # with `0o700`-ish permissions. This mirrors _secure_home() but lifts
        # the check into config-validation so `broker config validate` catches
        # it BEFORE any command runs.
        home = Path(self.home)
        if home.is_symlink():
            raise ConfigInvalid("HOME_IS_SYMLINK", message=f"{home}: refuse to trust a symlinked state dir",
                                field="home")
        if home.exists():
            import os
            st = home.stat()
            if st.st_uid != os.geteuid():
                raise ConfigInvalid("HOME_NOT_OWNED",
                                    message=f"{home}: uid {st.st_uid} != euid {os.geteuid()}",
                                    field="home")
            if st.st_mode & 0o077:
                raise ConfigInvalid("HOME_PERMS_TOO_OPEN",
                                    message=f"{home}: mode {oct(st.st_mode & 0o777)} allows group/other",
                                    field="home")
        # `service_mode` + `BROKER_HOME` override is refused as an invariant
        # (matches cli._secure_home()). We only enforce here if `home` was
        # explicitly set; otherwise `service_mode=1` alone is fine.
        if self.service_mode:
            prov = self.provenance("home")
            if prov is not None and prov.source.value == "env":
                raise ConfigInvalid("HOME_OVERRIDE_IN_SERVICE",
                                    message="service_mode=1 refuses BROKER_HOME override",
                                    field="home")
