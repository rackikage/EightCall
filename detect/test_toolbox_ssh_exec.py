#!/usr/bin/env python3
"""Tests for toolbox_ssh_exec.py. Runs under pytest, or standalone:
    ../bin/python3 test_toolbox_ssh_exec.py

The claim under test: this entrypoint adds no authority beyond the broker's
own (a bad node/task is refused, exit 2), and its JSON argv round-trips
losslessly even when an element contains a space — the exact case that made
splitting `nodebox_cli.py ssh task`'s printed output unsafe.
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


def run(*args: str) -> tuple[int, dict]:
    proc = subprocess.run(
        [str(PYTHON), str(HERE / "toolbox_ssh_exec.py"), *args],
        capture_output=True, text=True, timeout=15, cwd=HERE, check=False,
    )
    return proc.returncode, json.loads(proc.stdout)


def test_preview_returns_argv_for_known_task(tmp_path):
    code, out = run("--inventory", "inventory.json", "--node", "gateway", "--task", "collect-health")
    assert code == 0
    assert "error" not in out
    assert out["argv"][0] == "ssh"
    assert "gw@127.0.0.1" in out["argv"]


def test_preview_never_executes(tmp_path):
    """Without --execute, nothing is spawned beyond the broker's own argv build."""
    code, out = run("--inventory", "inventory.json", "--node", "gateway", "--task", "collect-health")
    assert code == 0
    assert "exit_code" not in out and "stdout" not in out


def test_unknown_task_is_refused(tmp_path):
    code, out = run("--inventory", "inventory.json", "--node", "gateway", "--task", "does-not-exist")
    assert code == 2
    assert "error" in out


def test_sshd_less_node_is_refused(tmp_path):
    code, out = run("--inventory", "inventory.json", "--node", "b628", "--task", "collect-health")
    assert code == 2
    assert "error" in out


def test_unknown_node_is_refused(tmp_path):
    code, out = run("--inventory", "inventory.json", "--node", "no-such-node", "--task", "collect-health")
    assert code == 2
    assert "error" in out


def test_execute_against_unreachable_host_reports_failure_not_crash(tmp_path):
    """gateway (127.0.0.1:2222) has no sshd listening in this test environment.
    --execute must still return a clean JSON result: a real connection failure,
    not a Python traceback or a hang past the timeout."""
    code, out = run("--inventory", "inventory.json", "--node", "gateway", "--task", "collect-health", "--execute")
    assert code == 0  # the script ran fine; ssh itself is what failed
    assert out["argv"][0] == "ssh"
    assert out["exit_code"] != 0


def test_argv_round_trips_a_space_losslessly(tmp_path):
    """The whole reason this script exists instead of parsing `ssh task`'s
    printed line: an argv element with an internal space must survive JSON
    intact. inventory.json's own remote_command already has one
    (`/usr/local/lib/nodebox/collect-health`, `--json`) but this pins the
    general property against a synthetic inventory with a harder case."""
    inv = {
        "revision": "test-v1",
        "nodes": {
            "gw": {
                "alias": "gw", "address": "127.0.0.1", "port": 2222, "user": "gw", "sshd": True,
                "host_key_alias": "test-alias",
                "tasks": {"note-task": {"remote_command": ["echo", "two words"], "timeout_seconds": 5}},
            }
        },
    }
    inv_path = tmp_path / "inv.json"
    inv_path.write_text(json.dumps(inv))
    proc = subprocess.run(
        [str(PYTHON), str(HERE / "toolbox_ssh_exec.py"),
         "--inventory", str(inv_path), "--node", "gw", "--task", "note-task"],
        capture_output=True, text=True, timeout=15, cwd=HERE, check=False,
    )
    out = json.loads(proc.stdout)
    assert "two words" in out["argv"]  # one element, space intact — not split into "two" + "words"


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
