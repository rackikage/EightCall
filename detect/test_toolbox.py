#!/usr/bin/env python3
"""Tests for the read-only HTTP toolbox. Runs under pytest, or standalone:
    ../bin/python3 test_toolbox.py

The claims under test are the safety ones: GET-only, allowlist-only log reads,
no subprocess spawned by a request, no traceback leaked to a client, and a
gate view that reports chain tampering instead of hiding it.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import authz_gate
import livetail
import toolbox_http


def write_chain(path: Path, decisions: list[str]) -> None:
    """Write a valid append-only audit chain the gate would accept."""
    prev = authz_gate.GENESIS_HASH
    with open(path, "w") as fh:
        for seq, decision in enumerate(decisions):
            body = {
                "action": "quarantine_process",
                "caller": "responder-vm-01",
                "decision": decision,
                "prev_hash": prev,
                "reason": "test record",
                "schema": authz_gate.SCHEMA,
                "seq": seq,
                "target": f"host:test-sim-{seq:02d}",
                "ts": "2026-09-18T00:00:00+00:00",
            }
            digest = hashlib.sha256(authz_gate.canonical_bytes(body)).hexdigest()
            fh.write(json.dumps({**body, "record_hash": digest}, sort_keys=True) + "\n")
            prev = digest


def build_allowlist(tmp: Path, text: str = "alpha\nbravo\ncharlie\n") -> tuple[Path, Path]:
    """An operator allowlist in tmp with one real log file beside it."""
    log = tmp / "fixture.log"
    log.write_text(text)
    allowlist = tmp / "allowlist.yml"
    allowlist.write_text("tmp-fixture: fixture.log\n")
    return allowlist, log


def _serve(config: toolbox_http.Config):
    toolbox_http._Handler.config = config
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), toolbox_http._Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    host, port = httpd.server_address
    return httpd, f"http://{host}:{port}"


def _req(base: str, path: str, method: str = "GET"):
    """Returns (status, body_bytes, headers) for any status, including errors."""
    req = urllib.request.Request(base + path, method=method, data=b"" if method != "GET" else None)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers)


# --------------------------------------------------------------------------- #
# views
# --------------------------------------------------------------------------- #

def test_gate_view_reports_window_and_valid_chain(tmp_path):
    audit = tmp_path / "audit.jsonl"
    write_chain(audit, ["allow", "deny", "allow"])
    out = toolbox_http.gate_view(audit)
    assert out["chain"]["ok"] is True
    assert out["chain"]["records"] == 3
    assert out["chain"]["first_bad_seq"] is None
    assert out["window"] == {"returned": 3, "limit": toolbox_http.GATE_LIMIT_DEFAULT, "allow": 2, "deny": 1}
    assert [d["seq"] for d in out["decisions"]] == [0, 1, 2]


def test_gate_view_surfaces_tampering(tmp_path):
    audit = tmp_path / "audit.jsonl"
    write_chain(audit, ["deny", "deny"])
    lines = audit.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["decision"] = "allow"  # rewrite history without fixing the hash
    lines[0] = json.dumps(rec, sort_keys=True)
    audit.write_text("\n".join(lines) + "\n")

    out = toolbox_http.gate_view(audit)
    assert out["chain"]["ok"] is False
    assert out["chain"]["first_bad_seq"] == 0


def test_gate_view_window_is_bounded(tmp_path):
    audit = tmp_path / "audit.jsonl"
    write_chain(audit, ["allow"] * 12)
    assert toolbox_http.gate_view(audit, limit=5)["window"]["returned"] == 5
    assert [d["seq"] for d in toolbox_http.gate_view(audit, limit=3)["decisions"]] == [9, 10, 11]
    # a caller cannot ask for an unbounded page, or a nonsensical one
    assert toolbox_http.gate_view(audit, limit=10_000)["window"]["limit"] == toolbox_http.GATE_LIMIT_MAX
    assert toolbox_http.gate_view(audit, limit=0)["window"]["limit"] == 1


def test_gate_view_tolerates_missing_audit(tmp_path):
    out = toolbox_http.gate_view(tmp_path / "absent.jsonl")
    assert out["chain"] == {"ok": True, "records": 0, "first_bad_seq": None,
                            "note": "tamper-evident, not tamper-proof"}
    assert out["decisions"] == []


def test_detections_pass_against_repo_fixtures(tmp_path):
    out = toolbox_http.detections_view()
    assert out["result"] == "PASS", out["checks"]
    assert all(c["ok"] for c in out["checks"])
    # the benign fixtures must stay quiet — that is the false-positive guard
    quiet = [c for c in out["checks"] if c["expect"] == "none"]
    assert quiet and all(c["hits"] == 0 for c in quiet)


def test_detections_report_uncovered_rules(tmp_path):
    coverage = toolbox_http.detections_view()["coverage"]
    assert coverage["rules"] >= len(coverage["with_fixtures"])
    # honesty check: rules without a proving fixture are named, not omitted
    assert set(coverage["without_fixtures"]).isdisjoint(set(coverage["with_fixtures"]))


def test_detections_spawns_no_subprocess(tmp_path):
    """A request must never cause a process spawn. The evaluator runs in-process."""
    def _forbidden(*_args, **_kwargs):
        raise AssertionError("/detections spawned a subprocess")

    orig_run, orig_popen = subprocess.run, subprocess.Popen
    subprocess.run, subprocess.Popen = _forbidden, _forbidden
    try:
        assert toolbox_http.detections_view()["result"] == "PASS"
    finally:
        subprocess.run, subprocess.Popen = orig_run, orig_popen


def test_fleet_view_reads_inventory(tmp_path):
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps({
        "revision": "test-v1",
        "telemetry_path": "telemetry.jsonl",
        "nodes": {"gateway": {"alias": "gw", "sshd": True, "allowed_capabilities": ["PING"],
                              "tasks": {"collect-health": {"timeout_seconds": 30}}}},
    }))
    (tmp_path / "telemetry.jsonl").write_text(
        json.dumps({"node_id": "gateway", "event_type": "nodebox.ssh_session", "ts": 1789697748}) + "\n"
        + json.dumps({"node_id": "gateway", "event_type": "nodebox.ssh_session", "ts": 1789697750}) + "\n"
        + "{ not json\n"
    )
    out = toolbox_http.fleet_view(inventory)
    assert out["inventory"]["revision"] == "test-v1"
    node = out["inventory"]["nodes"][0]
    assert node["node_id"] == "gateway" and node["tasks"] == ["collect-health"]
    assert out["telemetry"]["by_node"] == {"gateway": 2}
    assert out["telemetry"]["malformed"] == 1
    assert out["telemetry"]["latest_ts"] == 1789697750


def test_fleet_view_tolerates_missing_inventory(tmp_path):
    out = toolbox_http.fleet_view(tmp_path / "absent.json")
    assert out["inventory"]["nodes"] == []
    assert out["telemetry"]["records"] == 0


def test_tail_lists_labels_when_none_requested(tmp_path):
    allowlist, _ = build_allowlist(tmp_path)
    code, payload = toolbox_http.tail_view([], 10, allowlist)
    assert code == 200
    assert payload["labels"] == ["tmp-fixture"]
    assert payload["records"] == []


def test_tail_refuses_unallowlisted_label(tmp_path):
    allowlist, _ = build_allowlist(tmp_path)
    code, payload = toolbox_http.tail_view(["/etc/passwd", "tmp-fixture"], 10, allowlist)
    assert code == 403
    assert payload["unknown"] == ["/etc/passwd"]
    assert payload["approved"] == ["tmp-fixture"]
    assert "records" not in payload  # nothing was read


def test_tail_returns_allowlisted_records(tmp_path):
    allowlist, _ = build_allowlist(tmp_path)
    code, payload = toolbox_http.tail_view(["tmp-fixture"], 10, allowlist)
    assert code == 200
    assert payload["returned"] == 3
    assert any("bravo" in json.dumps(r) for r in payload["records"])


def test_tail_lines_are_capped(tmp_path):
    allowlist, _ = build_allowlist(tmp_path)
    _, payload = toolbox_http.tail_view(["tmp-fixture"], 10_000_000, allowlist)
    assert payload["lines"] == livetail.MAX_LINES


# --------------------------------------------------------------------------- #
# HTTP surface
# --------------------------------------------------------------------------- #

def test_control_panel_and_healthz(tmp_path):
    allowlist, _ = build_allowlist(tmp_path)
    httpd, base = _serve(toolbox_http.Config(allowlist=allowlist))
    try:
        code, body, headers = _req(base, "/")
        assert code == 200
        assert headers["Content-Type"].startswith("text/html")
        assert headers["X-Content-Type-Options"] == "nosniff"
        # the panel loads its own assets and talks only to its own API
        csp = headers["Content-Security-Policy"]
        assert "default-src 'none'" in csp and "connect-src 'self'" in csp
        assert b"detect" in body and b"toolbox.css" in body and b"toolbox.js" in body

        code, body, _ = _req(base, "/?format=json")
        assert code == 200
        assert {r["path"] for r in json.loads(body)["routes"]} == {r for r, _d, _q in toolbox_http.ROUTES}

        code, body, _ = _req(base, "/healthz")
        assert code == 200 and json.loads(body) == {"status": "ok"}
    finally:
        httpd.shutdown()


def test_ui_assets_are_served(tmp_path):
    httpd, base = _serve(toolbox_http.Config())
    try:
        code, css, headers = _req(base, "/toolbox.css")
        assert code == 200 and headers["Content-Type"].startswith("text/css")
        assert b":root" in css

        code, js, headers = _req(base, "/toolbox.js")
        assert code == 200 and headers["Content-Type"].startswith("application/javascript")
        assert b"loadGate" in js
    finally:
        httpd.shutdown()


def test_asset_map_exposes_nothing_else(tmp_path):
    """A caller names one of two fixed keys. Everything else is a 404 — there is
    no path to traverse, so repo source and host files stay unreachable."""
    httpd, base = _serve(toolbox_http.Config())
    try:
        for path in ("/toolbox_http.py", "/authz_policy.yml", "/toolbox.css/../authz_gate.py",
                     "/../../etc/passwd", "/keys/node.key", "/toolbox.css.map"):
            code, body, _ = _req(base, path)
            assert code == 404, f"{path} was served"
            assert b"def " not in body and b"PRIVATE KEY" not in body
    finally:
        httpd.shutdown()


def test_panel_never_writes_observed_text_as_markup(tmp_path):
    """Validation fixtures carry adversary-shaped strings on purpose; the panel must build
    DOM with textContent so an observed log line can never become markup."""
    js = (Path(toolbox_http.__file__).parent / "toolbox_ui.js").read_text()
    # strip comments first: the file *documents* the rule, and the prose must not
    # be what satisfies the test
    code = re.sub(r"/\*.*?\*/", "", js, flags=re.DOTALL)
    code = re.sub(r"^\s*//.*$", "", code, flags=re.MULTILINE)
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
        assert sink not in code, f"panel reaches for {sink}"


def test_panel_falls_back_without_the_ui_file(tmp_path):
    """Stripped to the module alone, the server still serves a usable index."""
    page = toolbox_http.fallback_index_html()
    for route, _desc, _q in toolbox_http.ROUTES:
        assert route.encode() in page


def test_http_routes_serve_views(tmp_path):
    audit = tmp_path / "audit.jsonl"
    write_chain(audit, ["allow", "deny"])
    allowlist, _ = build_allowlist(tmp_path)
    httpd, base = _serve(toolbox_http.Config(audit=audit, allowlist=allowlist))
    try:
        code, body, _ = _req(base, "/gate?limit=1")
        assert code == 200
        payload = json.loads(body)
        assert payload["window"]["returned"] == 1 and payload["chain"]["ok"] is True

        code, body, _ = _req(base, "/detections")
        assert code == 200 and json.loads(body)["result"] == "PASS"

        code, body, _ = _req(base, "/tail?label=tmp-fixture&lines=2")
        assert code == 200 and json.loads(body)["returned"] == 2

        code, body, _ = _req(base, "/tail?label=nope")
        assert code == 403 and json.loads(body)["unknown"] == ["nope"]
    finally:
        httpd.shutdown()


def test_mutating_methods_are_refused(tmp_path):
    httpd, base = _serve(toolbox_http.Config())
    try:
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            code, _body, headers = _req(base, "/gate", method=method)
            assert code == 405, f"{method} was not refused"
            assert headers.get("Allow") == "GET"
    finally:
        httpd.shutdown()


def test_unknown_path_is_404(tmp_path):
    httpd, base = _serve(toolbox_http.Config())
    try:
        code, body, _ = _req(base, "/../../etc/passwd")
        assert code == 404
        assert json.loads(body) == {"error": "not found"}
    finally:
        httpd.shutdown()


def test_internal_error_leaks_no_traceback(tmp_path):
    # A directory where a file belongs makes gate_view raise inside the handler.
    bad = tmp_path / "audit_dir"
    bad.mkdir()
    httpd, base = _serve(toolbox_http.Config(audit=bad))
    try:
        code, body, _ = _req(base, "/gate")
        assert code == 500
        assert json.loads(body) == {"error": "internal error (see server stderr)"}
        assert b"Traceback" not in body and bytes(str(tmp_path), "utf-8") not in body
    finally:
        httpd.shutdown()


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
