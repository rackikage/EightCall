#!/usr/bin/env python3
"""Tests for the read-only live-log observation stage. Runs under pytest, or
standalone: ./venv69/bin/python3 test_livetail.py

The load-bearing guarantees under test:
  * a caller can name only allowlisted LABELS — never a path (denial cases
    prove refusal happens before any process is spawned);
  * raw secret bytes in a tailed line NEVER survive into records or the
    evidence log (redaction before persistence);
  * follows are bounded (time / line budgets) and always tear down `tail`.
"""
from __future__ import annotations

import json
import subprocess
import threading
import time
from pathlib import Path
from unittest import mock

from authz_gate import verify_audit_chain
from livetail import _tail_argv, follow, load_allowlist, snapshot
from redact import EvidenceLog

# Assembled from fragments: the value must look credential-shaped to the
# redactor under test, but no static literal should match a scanner pattern.
SECRET = "AKIA" + "IOSFODNN7" + "EXAMPLE"


def make_logs(tmp: Path) -> tuple[Path, Path, Path]:
    a = tmp / "a.log"
    a.write_text(
        "boot ok\n"
        f"user exported {SECRET} then exited\n"
        "shutdown ok\n"
    )
    b = tmp / "b.log"
    b.write_text("second file first line\nsecond file second line\n")
    allow = tmp / "allow.yml"
    allow.write_text(f"alpha: {a}\nbravo: {b}\n")
    return a, b, allow


# --- source authority: labels only, allowlist enforced ----------------------

def test_unknown_label_refused_before_any_spawn(tmp):
    _, _, allow = make_logs(tmp)
    with mock.patch("subprocess.run") as m_run, mock.patch("subprocess.Popen") as m_pop:
        for call in (
            lambda: snapshot(["etc-passwd"], allowlist_path=allow),
            lambda: follow(["etc-passwd"], allowlist_path=allow, seconds=0.2),
        ):
            try:
                call()
                raise AssertionError("expected ValueError")
            except ValueError as exc:
                assert "not in allowlist" in str(exc)
        assert not m_run.called and not m_pop.called  # no process ever existed


def test_allowlist_rejects_missing_file(tmp):
    bad = tmp / "bad.yml"
    bad.write_text(f"ghost: {tmp / 'nope.log'}\n")
    try:
        load_allowlist(bad)
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert "not an existing file" in str(exc)


def test_allowlist_rejects_non_mapping(tmp):
    bad = tmp / "bad.yml"
    bad.write_text("- just\n- a\n- list\n")
    try:
        load_allowlist(bad)
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert "mapping" in str(exc)


def test_tail_argv_is_fixed_vector_no_shell(tmp):
    argv = _tail_argv([Path("/tmp/x.log")], 50, follow=True)
    assert argv == ["tail", "-v", "-n", "50", "-F", "/tmp/x.log"]
    # caller text lands only inside allowlist resolution, never in argv:
    # the vector contains exactly the resolved path and nothing else.


# --- snapshot: bounded historical read, redaction before persistence --------

def test_snapshot_redacts_and_labels(tmp):
    _, _, allow = make_logs(tmp)
    ev = EvidenceLog(tmp / "findings.jsonl")
    records = snapshot(["alpha"], allowlist_path=allow, evidence=ev)
    blob = json.dumps(records) + (tmp / "findings.jsonl").read_text()
    assert SECRET not in blob                      # raw never persists
    assert len(records) == 3
    assert all(r["source"] == "alpha" for r in records)
    secret_rec = next(r for r in records if r["findings"])
    assert "aws_access_key_id:" in secret_rec["line"]  # masked shape survives
    assert all(r["trace_id"] == records[0]["trace_id"] for r in records)
    assert all(r["ts"].endswith("+00:00") for r in records)  # UTC normalized
    ok, n, _ = verify_audit_chain(tmp / "findings.jsonl")
    assert ok and n == 1


def test_snapshot_line_bound(tmp):
    _, _, allow = make_logs(tmp)
    records = snapshot(["alpha"], allowlist_path=allow, lines=2)
    assert len(records) == 2  # tail -n 2: only the last two lines


def test_snapshot_multi_file_attribution(tmp):
    _, _, allow = make_logs(tmp)
    records = snapshot(["alpha", "bravo"], allowlist_path=allow)
    alpha = [r for r in records if r["source"] == "alpha"]
    bravo = [r for r in records if r["source"] == "bravo"]
    assert len(alpha) == 3 and len(bravo) == 2
    assert all("second file" in r["line"] for r in bravo)


def test_snapshot_passes_timeout(tmp):
    _, _, allow = make_logs(tmp)
    with mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired("tail", 1)) as m:
        records = snapshot(["alpha"], allowlist_path=allow, timeout=1.0)
    assert m.call_args.kwargs["timeout"] == 1.0
    assert records == []  # timeout -> bounded empty result, not a hang


# --- follow: bounded live read, always tears down ---------------------------

def test_follow_redacts_live_and_terminates(tmp):
    a, _, allow = make_logs(tmp)
    ev = EvidenceLog(tmp / "findings.jsonl")
    result: dict = {}

    def run():
        result["records"] = follow(
            ["alpha"], allowlist_path=allow, seconds=2.5, evidence=ev,
        )

    t = threading.Thread(target=run)
    start = time.monotonic()
    t.start()
    time.sleep(0.7)  # let tail -F attach, then simulate rotation-era writes
    with open(a, "a") as fh:
        fh.write(f"live line with {SECRET} appended\n")
    t.join(timeout=15)
    elapsed = time.monotonic() - start

    assert not t.is_alive()                       # tail always torn down
    assert elapsed < 10                           # time budget honored
    records = result["records"]
    blob = json.dumps(records) + (tmp / "findings.jsonl").read_text()
    assert SECRET not in blob
    assert any("live line with" in r["line"] for r in records)
    ok, n, _ = verify_audit_chain(tmp / "findings.jsonl")
    assert ok and n >= 2                          # historic + live secret lines


def test_follow_line_budget_stops_early(tmp):
    a, _, allow = make_logs(tmp)
    with open(a, "a") as fh:
        fh.writelines(f"extra {i}\n" for i in range(50))
    start = time.monotonic()
    records = follow(["alpha"], allowlist_path=allow, seconds=60, max_lines=5)
    assert time.monotonic() - start < 30          # line budget beat time budget
    # the budget counts raw tail output lines, which include the -v framing
    # (BSD tail emits a leading blank + header; GNU emits just the header), so
    # assert the invariant, not a platform-specific exact count
    assert 0 < len(records) <= 5


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
    import sys

    sys.exit(_run_standalone())
