"""broker.runtime — bridge between broker.cli and platform_runtime.

Adds a `_GLOBALS` argparse parent parser (--output, --config, --timeout,
--quiet, --verbose, --log-level, --no-color, --version), builds a
`RunContext`, and provides the two new operational commands (`config`,
`doctor`).

Kept in its own module so cli.py's diff stays small and its own subcommand
handlers see almost the same argparse `args` shape they had before.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import fields
from pathlib import Path

from platform_runtime import (
    RunContext, install_stderr_json, redact,
    ExitCode, PlatformError, ConfigInvalid,
)
from platform_runtime.logging import add_redactor_token

from . import __version__ as _broker_version
from .config import BrokerConfig


COMPONENT = "broker"


def build_global_parser() -> argparse.ArgumentParser:
    """Parent parser holding the flags every subcommand inherits."""
    g = argparse.ArgumentParser(add_help=False)
    g.add_argument("--output", choices=("text", "json", "ndjson"), default="json",
                   help="output format for command results (default: json — matches historical shape)")
    g.add_argument("--config", metavar="PATH", default=None,
                   help="explicit config file (TOML); source #3 in the precedence order")
    g.add_argument("--timeout", type=float, default=None, metavar="SECS",
                   help="abort the command after SECS (exit 3 on hit)")
    g.add_argument("--quiet", action="store_true", help="suppress non-error logs (level=ERROR)")
    g.add_argument("--verbose", action="store_true", help="raise log level to DEBUG")
    g.add_argument("--log-level", default=None, metavar="LEVEL",
                   help="explicit log level (overrides --quiet/--verbose)")
    g.add_argument("--no-color", action="store_true", help="reserved; broker has no color today")
    g.add_argument("--version", action="version",
                   version=f"broker {_broker_version} (platform_runtime contract)")
    return g


def resolve_log_level(args) -> str:
    if args.log_level:
        return args.log_level.upper()
    if getattr(args, "quiet", False):
        return "ERROR"
    if getattr(args, "verbose", False):
        return "DEBUG"
    return "INFO"


def build_context(args) -> tuple[RunContext, BrokerConfig]:
    """Install stderr JSON logging, resolve config, return (ctx, cfg)."""
    from platform_runtime.config import resolve_config
    level = resolve_log_level(args)
    install_stderr_json(COMPONENT, level=level)
    ctx = RunContext(component=COMPONENT, output=getattr(args, "output", "json"))
    if getattr(args, "timeout", None):
        ctx.with_timeout(args.timeout)
    explicit_path = Path(args.config) if getattr(args, "config", None) else None
    cfg = resolve_config(BrokerConfig, component=COMPONENT, explicit_path=explicit_path)
    # Register the witness URL (if any) as a redactor token, so a stray log
    # line naming it can't leak it. Cheap seatbelt.
    if cfg.witness_url:
        add_redactor_token(cfg.witness_url)
    return ctx, cfg


# ------------------------------------------------------------- config subcommand
def cmd_config(args) -> int:
    """Dispatch: broker config {show|validate|explain}."""
    from platform_runtime.config import resolve_config
    explicit_path = Path(args.config) if getattr(args, "config", None) else None
    try:
        cfg = resolve_config(BrokerConfig, component=COMPONENT, explicit_path=explicit_path)
    except ConfigInvalid as exc:
        _print_error(args, exc)
        return int(exc.exit_code)

    action = args.config_action
    if action == "show":
        redacted = not args.no_redact
        data = cfg.as_dict(redacted=redacted)
        _print_result(args, {"ok": True, "config": data})
        return 0
    if action == "validate":
        try:
            cfg.validate()
        except ConfigInvalid as exc:
            _print_error(args, exc)
            return int(exc.exit_code)
        _print_result(args, {"ok": True, "validated": True, "component": COMPONENT})
        return 0
    if action == "explain":
        try:
            info = cfg.explain(args.key)
        except ConfigInvalid as exc:
            _print_error(args, exc)
            return int(exc.exit_code)
        _print_result(args, {"ok": True, **info})
        return 0
    _print_error(args, ConfigInvalid("USAGE", message="broker config <show|validate|explain>"))
    return int(ExitCode.USAGE_OR_CONFIG)


def add_config_subcommand(sub) -> None:
    c = sub.add_parser("config", help="inspect and validate broker configuration")
    csub = c.add_subparsers(dest="config_action", required=True)

    cs = csub.add_parser("show", help="print resolved config with source provenance")
    cs.add_argument("--no-redact", action="store_true", help="show unredacted values (DANGEROUS)")

    csub.add_parser("validate", help="run config validation; exit 2 on failure")

    ce = csub.add_parser("explain", help="print the source and origin for one key")
    ce.add_argument("key", help="config key, e.g. 'home' or 'witness_url'")

    c.set_defaults(fn=cmd_config)


# --------------------------------------------------------------- doctor command
def cmd_doctor(args) -> int:
    """Check preconditions: config validates, keydir exists or is creatable,
    trusted_keys/policy are present or absent (both fine, `init` fixes), db
    permissions are `0o600` if present, umask is `0o077`.
    """
    checks: list[dict] = []

    def add(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": ok, "detail": detail})

    # 1. config resolves + validates
    try:
        explicit_path = Path(args.config) if getattr(args, "config", None) else None
        from platform_runtime.config import resolve_config
        cfg = resolve_config(BrokerConfig, component=COMPONENT, explicit_path=explicit_path)
        add("config validates", True, f"home={cfg.home} keydir={cfg.keydir}")
    except ConfigInvalid as exc:
        add("config validates", False, f"{exc.code}: {exc.message}")
        cfg = None  # keep going so the report is useful

    # Probe paths derived from the RESOLVED config, not from broker.paths'
    # import-time env snapshot — otherwise `--config` / a config file would
    # report one home and check a different one.
    if cfg is not None:
        home_p, keydir_p = Path(cfg.home), Path(cfg.keydir)
    else:
        from .paths import HOME as home_p, KEYDIR as keydir_p  # type: ignore[assignment]
    DB = home_p / "broker.db"
    POLICY = home_p / "policy.json"
    KEYS = home_p / "trusted_keys.json"
    GATE_TLS_CERT = keydir_p / "gate-tls.crt"
    GATE_TLS_KEY = keydir_p / "gate-tls.key"

    # 2. umask is 0o077
    cur = os.umask(0)
    os.umask(cur)
    add("umask is 0o077", cur == 0o077, f"got {oct(cur)}")

    # 3. state dir owned & permissions (only if it exists)
    if cfg is not None and Path(cfg.home).exists():
        st = Path(cfg.home).stat()
        add("state dir owned by us", st.st_uid == os.geteuid(),
            f"uid={st.st_uid} euid={os.geteuid()}")
        add("state dir mode 0700-ish", not (st.st_mode & 0o077),
            f"mode={oct(st.st_mode & 0o777)}")
    else:
        add("state dir owned by us", True, "not yet created (run `broker init`)")
        add("state dir mode 0700-ish", True, "not yet created (run `broker init`)")

    # 4. per-file mode checks
    for label, path in (("db", DB), ("policy", POLICY), ("keys", KEYS)):
        if path.exists():
            m = path.stat().st_mode & 0o777
            add(f"{label} is 0600", m == 0o600, f"path={path} mode={oct(m)}")

    # 5. TLS identity files
    for label, path in (("gate tls cert", GATE_TLS_CERT), ("gate tls key", GATE_TLS_KEY)):
        add(f"{label} present", path.exists(), f"path={path}")

    ok_all = all(c["ok"] for c in checks)
    _print_result(args, {"ok": ok_all, "component": COMPONENT, "checks": checks})
    return 0 if ok_all else int(ExitCode.FAILURE)


def add_doctor_subcommand(sub) -> None:
    d = sub.add_parser("doctor", help="check preconditions and print a diagnosis")
    d.set_defaults(fn=cmd_doctor)


# ----------------------------------------------------------------- print helpers
def _print_result(args, obj) -> None:
    """Emit a *result* on stdout in the caller's requested format."""
    output = getattr(args, "output", "json") or "json"
    obj = redact(obj)
    if output == "ndjson":
        sys.stdout.write(json.dumps(obj, default=str, separators=(",", ":"), sort_keys=True) + "\n")
    elif output == "text":
        # Use the contract's single text renderer — never hand-roll another
        # one here (nested dicts must not leak Python reprs).
        from platform_runtime import render_text
        sys.stdout.write(render_text(obj) + "\n")
    else:
        # json (default): pretty. Matches historical `_out` formatting exactly.
        sys.stdout.write(json.dumps(obj, indent=2, default=str, sort_keys=True) + "\n")
    sys.stdout.flush()


def _print_error(args, exc: PlatformError) -> None:
    """Emit an error envelope on stdout preserving historical `{ok:false, reason,...}` keys."""
    payload = {
        "ok": False,
        # Historical keys: keep them so existing substring assertions still hit.
        "reason": exc.code.lower() if exc.code else "error",
        "detail": exc.message or "",
        # New envelope: adds `error` alongside without disturbing the old keys.
        "error": exc.as_dict(),
    }
    _print_result(args, payload)
