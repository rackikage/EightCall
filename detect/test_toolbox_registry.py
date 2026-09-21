#!/usr/bin/env python3
"""Contract tests for toolbox_registry.json, from the Python side.

The Rust server lints this file at boot and refuses to bind if it fails. These
tests catch the other direction of drift: a registry row that names a script,
flag or file that Python no longer provides. They run in the repo's own pytest
suite, so renaming a CLI subcommand breaks here rather than at the first click.

Runs under pytest, or standalone:
    ../bin/python3 test_toolbox_registry.py
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _resolve_python() -> Path:
    """First bin/python3 walking up from this file that belongs to a real
    virtualenv; fall back to the interpreter running the tests."""
    for base in (HERE, *HERE.parents):
        cand = base / "bin" / "python3"
        if cand.exists() and (base / "pyvenv.cfg").exists():
            return cand
    return Path(sys.executable)


PYTHON = _resolve_python()
REGISTRY = HERE / "toolbox_registry.json"

# Capabilities the design review deliberately kept out of a click-to-run UI.
# If one ever appears in the registry, that is a decision to re-make on purpose,
# not a diff to wave through.
EXCLUDED = {
    "nodebox.keygen",        # mints a controller key, no overwrite guard
    "nodebox.enroll",        # rewrites inventory.json, the trust root
    "nodebox.controller.serve",
    "nodebox.node.run",
    "authz.keygen",          # prints a private key
    "authz.http.serve",      # the only service that can mint an allow
    "toolbox.http.serve",    # would let the panel rebind its own backend
}


def registry() -> dict:
    return json.loads(REGISTRY.read_text())


def caps() -> list[dict]:
    return registry()["capabilities"]


def test_registry_is_valid_json_with_a_schema(tmp_path):
    reg = registry()
    assert reg["schema"].startswith("detect.toolbox.registry/")
    assert reg["version"] >= 1
    assert reg["capabilities"], "registry declares no capabilities"


def test_ids_are_unique(tmp_path):
    ids = [c["id"] for c in caps()]
    assert len(ids) == len(set(ids)), f"duplicate ids: {sorted({i for i in ids if ids.count(i) > 1})}"


def test_every_argv_script_exists(tmp_path):
    """A row naming a script Python does not ship is the most likely drift."""
    for c in caps():
        for tok in c.get("argv", []):
            if tok.endswith(".py"):
                assert (HERE / tok).is_file(), f"{c['id']} names missing script {tok}"
                break


def test_argv_tokens_are_literals_or_whole_placeholders(tmp_path):
    """Mirrors the Rust Token rule: a brace must wrap an entire token, so
    substring interpolation cannot be expressed here either."""
    for c in caps():
        for tok in c.get("argv", []):
            if "{" in tok or "}" in tok:
                assert tok.startswith("{") and tok.endswith("}") and tok.count("{") == 1, (
                    f"{c['id']}: argv token {tok!r} mixes text with a placeholder"
                )


def test_argv_placeholders_name_declared_enum_or_server_args(tmp_path):
    """The closed-set rule: only enum/server kinds may reach an argv element."""
    reg = registry()
    by_id = {c["id"]: c for c in reg["capabilities"]}
    for c in reg["capabilities"]:
        args = c["args"]
        if isinstance(args, dict):  # args: {from: <id>}
            args = by_id[args["from"]]["args"]
        kinds = {a["name"]: a["kind"] for a in args}
        for tok in c.get("argv", []):
            if tok.startswith("{") and tok.endswith("}"):
                name = tok[1:-1]
                if name == "python":
                    continue
                assert name in kinds, f"{c['id']}: argv names undeclared arg {name!r}"
                assert kinds[name] in ("enum", "server"), (
                    f"{c['id']}: arg {name!r} has kind {kinds[name]!r}; only enum/server may "
                    "appear in argv — that is what keeps every element a set member"
                )


def test_mutating_rows_declare_effects(tmp_path):
    for c in caps():
        if c["mutating"]:
            assert c.get("effects"), f"{c['id']} is mutating but declares no effects"


def test_host_contact_requires_the_gate(tmp_path):
    for c in caps():
        if "contacts_host" in c.get("effects", []):
            assert c.get("authz", {}).get("required") is True, (
                f"{c['id']} contacts a host without requiring a signed allow"
            )


def test_excluded_capabilities_stay_out(tmp_path):
    present = {c["id"] for c in caps()}
    leaked = present & EXCLUDED
    assert not leaked, f"capabilities excluded by design are present: {sorted(leaked)}"


def test_no_mutating_row_is_on_an_auto_refresh_timer(tmp_path):
    for c in caps():
        dash = c.get("dashboard") or {}
        if dash.get("refresh_seconds", 0) > 0 and c["mutating"]:
            assert c["runner"] == "service", (
                f"{c['id']} auto-refreshes on a timer and mutates — a timer must never "
                "fire something that writes"
            )


def test_read_views_are_not_mutating_and_have_no_argv(tmp_path):
    for c in caps():
        if c["runner"] == "read_view":
            assert not c["mutating"], f"{c['id']} is a read_view but marked mutating"
            assert "argv" not in c, f"{c['id']} is a read_view but declares argv"
            assert "http" in c, f"{c['id']} is a read_view with no http block"


def test_declared_writes_stay_inside_the_repo(tmp_path):
    for c in caps():
        for w in c.get("writes", []):
            assert not w.startswith("/") and ".." not in w, f"{c['id']} declares write outside repo: {w}"


def test_disabled_rows_explain_themselves(tmp_path):
    for c in caps():
        if c.get("enabled") is False:
            assert (c.get("docs") or {}).get("notes"), (
                f"{c['id']} is disabled with no explanation — a hidden row should say why"
            )


def test_nodebox_cli_still_has_the_subcommands_the_registry_uses(tmp_path):
    """Catches a CLI rename breaking a registry row."""
    out = subprocess.run(
        [str(PYTHON), "nodebox_cli.py", "--help"],
        capture_output=True, text=True, cwd=HERE, timeout=30, check=False,
    )
    helptext = out.stdout + out.stderr
    used = set()
    for c in caps():
        argv = c.get("argv", [])
        if "nodebox_cli.py" in argv:
            i = argv.index("nodebox_cli.py")
            if i + 1 < len(argv) and not argv[i + 1].startswith("{"):
                used.add(argv[i + 1])
    for sub in sorted(used):
        assert sub in helptext, f"registry uses `nodebox {sub}` but the CLI no longer lists it"


def _run_standalone() -> int:
    import tempfile
    import traceback

    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in tests:
        with tempfile.TemporaryDirectory() as td:
            try:
                fn(Path(td))
                print(f"  PASS {fn.__name__}")
            except Exception:  # noqa: BLE001 - test runner reports any failure
                failed += 1
                print(f"  FAIL {fn.__name__}")
                traceback.print_exc()
    print(f"RESULT: {len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run_standalone())
