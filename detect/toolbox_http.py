#!/usr/bin/env python3
"""Read-only HTTP toolbox over detect — the operator's one page.

This is a *view*, not a control plane. It adds no authority of its own:

  * Every route is a GET. There is no POST/PUT/DELETE handler, so nothing
    reachable here can mutate policy, mint an allow, or act on a host. The
    authorization gate stays the only thing that decides (`authz_gate.py`);
    this server never calls `AuthzGate.authorize()`, it only *reads* the
    audit trail the gate already wrote, and re-verifies its hash chain.
  * `/tail` cannot name a path. Labels resolve through the operator
    allowlist (`log_allowlist.yml`) inside `livetail.py`, which refuses an
    unknown label before `tail` is spawned and redacts what it returns.
  * `/detections` runs the Sigma evaluator **in-process** against repo
    fixtures. No subprocess is spawned from a request and no request input
    reaches the evaluator: the rule/fixture pairs are fixed in _CHECKS.
  * Attribution, not camouflage: the server names itself in `Server:`.

It does disclose host detail (supervisor identity, inventory addresses, log
lines), so bind 127.0.0.1 — the default — and expose it off-host only
deliberately and behind TLS, exactly as `authz_http.py` warns.

Routes:
    GET /            control panel (HTML; ?format=json for the route table)
    GET /toolbox.css
    GET /toolbox.js  the panel's two static assets, served by fixed name only
    GET /gate        recent gate decisions + hash-chain verification
    GET /fleet       nodebox inventory, layer stack, telemetry summary
    GET /detections  Sigma rules vs fixtures, pass/fail + coverage gaps
    GET /tail        bounded, allowlisted, redacted log snapshot
    GET /healthz     liveness

Run:
    ../bin/python3 toolbox_http.py --host 127.0.0.1 --port 8080
"""
from __future__ import annotations

import argparse
import html
import json
import sys
import traceback
from collections import deque
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import livetail
import nodebox_layers
import validate_rules
from authz_gate import verify_audit_chain

_HERE = Path(__file__).resolve().parent

GATE_LIMIT_DEFAULT = 50
GATE_LIMIT_MAX = 500
TAIL_LINES_DEFAULT = 100
TELEMETRY_SCAN_MAX = 5_000  # bound the telemetry summary's memory + time

# The only files this server will ever hand out, keyed by request path. A
# caller names a key, never a path, so there is nothing here to traverse.
_STATIC = {
    "/toolbox.css": ("toolbox_ui.css", "text/css"),
    "/toolbox.js": ("toolbox_ui.js", "application/javascript"),
}

ROUTES = (
    ("/gate", "recent gate decisions + hash-chain verification", f"?limit=N (max {GATE_LIMIT_MAX})"),
    ("/fleet", "nodebox inventory, layer stack, telemetry summary", ""),
    ("/detections", "Sigma rules vs fixtures: pass/fail + coverage gaps", ""),
    ("/tail", "bounded, allowlisted, redacted log snapshot", "?label=<allowlisted>&lines=N"),
    ("/healthz", "liveness", ""),
)


@dataclass(frozen=True)
class Config:
    """Where the toolbox reads from. All paths, no behaviour — a view's inputs."""

    audit: Path = _HERE / "authz_audit.jsonl"
    inventory: Path = _HERE / "inventory.json"
    allowlist: Path = livetail.DEFAULT_ALLOWLIST


@dataclass(frozen=True)
class _Check:
    """One fixed rule-vs-fixture expectation, mirroring validate_rules.__main__."""

    rule: str
    fixture: str
    loader: str  # oslog | pcap | flow
    expect: str  # all | any | none
    min_events: int = 0


_CHECKS = (
    _Check("rules/ios_shell_abuse.yml", "collected_events.log", "oslog", "all", 5),
    _Check("rules/icmp_exfil.yml", "icmp_exfil_attack.pcap", "pcap", "any"),
    _Check("rules/icmp_exfil.yml", "icmp_benign.pcap", "pcap", "none"),
    _Check("rules/c2_relay_beacon.yml", "c2_beacon_attack.flowlog", "flow", "all", 1),
    _Check("rules/c2_relay_beacon.yml", "c2_beacon_benign.flowlog", "flow", "none"),
)

_LOADERS = {
    "oslog": validate_rules.oslog_events,
    "pcap": validate_rules.pcap_events,
    "flow": validate_rules.flow_events,
}


def _guard(fn, *args, **kwargs):
    """Run a sub-view; surface its failure in the payload instead of 500-ing the
    whole page. A broken piece stays visible rather than silently empty."""
    try:
        return fn(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 - a dashboard reports, never hides
        return {"error": f"{type(exc).__name__}: {exc}"}


# --------------------------------------------------------------------------- #
# views (pure functions of on-disk state — unit-testable without a socket)
# --------------------------------------------------------------------------- #

def gate_view(audit_path: str | Path, limit: int = GATE_LIMIT_DEFAULT) -> dict:
    """The gate's own record: the last `limit` decisions, plus a fresh chain verify.

    The chain is recomputed over the *whole* file (that is the integrity claim);
    only the returned window is bounded.
    """
    limit = max(1, min(int(limit), GATE_LIMIT_MAX))
    ok, count, first_bad = verify_audit_chain(audit_path)
    records: list[dict] = []
    path = Path(audit_path)
    if path.exists():
        with open(path) as fh:
            for line in deque(fh, maxlen=limit):  # last N lines, memory-bounded
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except ValueError:
                    records.append({"error": "unparseable record"})
    allow = sum(1 for r in records if r.get("decision") == "allow")
    return {
        "chain": {
            "ok": ok,
            "records": count,
            "first_bad_seq": first_bad,
            "note": "tamper-evident, not tamper-proof",
        },
        "window": {"returned": len(records), "limit": limit, "allow": allow, "deny": len(records) - allow},
        "decisions": records,
    }


def telemetry_summary(path: str | Path) -> dict:
    """Count nodebox events by node and type over a bounded tail of the stream."""
    path = Path(path)
    if not path.exists():
        return {"path": path.name, "records": 0, "by_node": {}, "by_event": {}}
    by_node: dict[str, int] = {}
    by_event: dict[str, int] = {}
    latest: int | None = None
    scanned = 0
    malformed = 0
    with open(path) as fh:
        for line in deque(fh, maxlen=TELEMETRY_SCAN_MAX):
            line = line.strip()
            if not line:
                continue
            scanned += 1
            try:
                rec = json.loads(line)
            except ValueError:
                malformed += 1
                continue
            node = str(rec.get("node_id", "?"))
            event = str(rec.get("event_type", "?"))
            by_node[node] = by_node.get(node, 0) + 1
            by_event[event] = by_event.get(event, 0) + 1
            ts = rec.get("ts")
            if isinstance(ts, int) and (latest is None or ts > latest):
                latest = ts
    return {
        "path": path.name,
        "records": scanned,
        "malformed": malformed,
        "scan_capped_at": TELEMETRY_SCAN_MAX,
        "latest_ts": latest,
        "by_node": dict(sorted(by_node.items())),
        "by_event": dict(sorted(by_event.items())),
    }


def fleet_view(inventory_path: str | Path) -> dict:
    """The attributable fleet: operator inventory, this supervisor's own layer
    stack, and what the collector has actually seen."""
    path = Path(inventory_path)
    inv: dict = {}
    if path.exists():
        inv = json.loads(path.read_text())
    nodes = []
    for node_id, node in sorted((inv.get("nodes") or {}).items()):
        nodes.append({
            "node_id": node_id,
            "alias": node.get("alias"),
            "device_type": node.get("device_type"),
            "address": node.get("address"),
            "port": node.get("port"),
            "sshd": node.get("sshd"),
            "host_key_alias": node.get("host_key_alias"),
            "allowed_capabilities": node.get("allowed_capabilities") or [],
            "tasks": sorted(node.get("tasks") or {}),
            "note": node.get("note"),
        })
    telemetry = inv.get("telemetry_path") or "nodebox_telemetry.jsonl"
    return {
        "inventory": {"path": path.name, "revision": inv.get("revision"), "nodes": nodes},
        "supervisor": _guard(nodebox_layers.supervisor_identity),
        "layers": _guard(nodebox_layers.describe_stack),
        "telemetry": _guard(telemetry_summary, (path.parent / telemetry)),
    }


def detections_view() -> dict:
    """Evaluate every fixed rule/fixture pair in-process and report pass/fail,
    plus which rules ship with no fixture to prove them."""
    results = []
    covered: set[str] = set()
    for check in _CHECKS:
        covered.add(Path(check.rule).stem)
        entry = {
            "rule": Path(check.rule).stem,
            "fixture": check.fixture,
            "expect": check.expect,
        }
        try:
            rule = validate_rules.load_rule(str(_HERE / check.rule))
            events = _LOADERS[check.loader](str(_HERE / check.fixture))
            hits = validate_rules.evaluate(rule, events)
            entry["level"] = rule.get("level")
            entry["events"] = len(events)
            entry["hits"] = len(hits)
            if check.expect == "all":
                entry["ok"] = len(events) >= check.min_events and len(hits) == len(events)
            elif check.expect == "any":
                entry["ok"] = len(hits) > 0
            else:  # none
                entry["ok"] = len(hits) == 0
        except Exception as exc:  # noqa: BLE001 - a failed check is a result, not a crash
            entry["ok"] = False
            entry["error"] = f"{type(exc).__name__}: {exc}"
        results.append(entry)
    all_rules = sorted(p.stem for p in (_HERE / "rules").glob("*.yml"))
    return {
        "result": "PASS" if all(r["ok"] for r in results) else "FAIL",
        "checks": results,
        "coverage": {
            "rules": len(all_rules),
            "with_fixtures": sorted(covered),
            "without_fixtures": [r for r in all_rules if r not in covered],
        },
    }


def tail_view(labels: list[str], lines: int, allowlist_path: str | Path) -> tuple[int, dict]:
    """Allowlisted, redacted, bounded log read. Returns (status, payload).

    A label is the only thing a caller may name; paths come from the operator
    allowlist. No label at all lists what is approved rather than erroring.
    """
    allow = livetail.load_allowlist(allowlist_path)
    if not labels:
        return 200, {
            "labels": sorted(allow),
            "hint": "GET /tail?label=<one of labels>&lines=N",
            "records": [],
        }
    unknown = [lab for lab in labels if lab not in allow]
    if unknown:
        # Refuse before livetail spawns anything; name labels, never paths.
        return 403, {"error": "label(s) not in allowlist", "unknown": unknown, "approved": sorted(allow)}
    lines = max(1, min(int(lines), livetail.MAX_LINES))
    records = livetail.snapshot(labels, allowlist_path=allowlist_path, lines=lines)
    return 200, {"labels": sorted(labels), "lines": lines, "returned": len(records), "records": records}


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #

_STYLE = """
:root { color-scheme: light dark; }
body { font: 14px/1.6 ui-monospace, SFMono-Regular, Menlo, monospace;
       max-width: 46rem; margin: 3rem auto; padding: 0 1rem; }
h1 { font-size: .95rem; letter-spacing: .08em; text-transform: uppercase; opacity: .7; }
ul { list-style: none; padding: 0; }
li { padding: .45rem 0; border-bottom: 1px solid color-mix(in srgb, currentColor 15%, transparent); }
a { font-weight: 600; text-decoration: none; }
a:hover { text-decoration: underline; }
.q { opacity: .55; }
.d { display: block; opacity: .7; font-size: .9em; }
footer { margin-top: 2rem; opacity: .55; font-size: .85em; }
"""


def ui_page() -> bytes:
    """The control panel page. Falls back to the minimal index when the UI file
    is absent, so a stripped-down single-module deployment still works."""
    path = _HERE / "toolbox_ui.html"
    if path.exists():
        return path.read_bytes()
    return fallback_index_html()


def fallback_index_html() -> bytes:
    items = []
    for route, desc, query in ROUTES:
        q = f' <span class="q">{html.escape(query)}</span>' if query else ""
        items.append(
            f'<li><a href="{html.escape(route)}">{html.escape(route)}</a>{q}'
            f'<span class="d">{html.escape(desc)}</span></li>'
        )
    page = (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<title>detect toolbox</title><style>" + _STYLE + "</style></head><body>"
        "<h1>detect toolbox</h1><ul>" + "".join(items) + "</ul>"
        "<footer>Read-only view. GET only — no route here can decide, mutate, or act. "
        "The gate remains the only authority.</footer></body></html>"
    )
    return page.encode("utf-8")


class _Handler(BaseHTTPRequestHandler):
    config: Config = Config()  # set on the handler class before serving
    server_version = "detect-toolbox/1.0"

    def _send(self, code: int, payload: dict, *, content_type: str = "application/json") -> None:
        body = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        self._raw(code, body, content_type)

    def _raw(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        if content_type == "text/html":
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'",
            )
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def _int(qs: dict, name: str, default: int) -> int:
        try:
            return int(qs.get(name, [default])[0])
        except (TypeError, ValueError):
            return default

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        cfg = self.config
        try:
            if parsed.path in ("/", "/index.html"):
                if qs.get("format", [""])[0] == "json":
                    self._send(200, {"routes": [
                        {"path": r, "description": d, "query": q} for r, d, q in ROUTES
                    ]})
                else:
                    self._raw(200, ui_page(), "text/html")
            elif parsed.path in _STATIC:
                name, ctype = _STATIC[parsed.path]
                asset = _HERE / name
                if asset.exists():
                    self._raw(200, asset.read_bytes(), ctype)
                else:
                    self._send(404, {"error": f"asset {name} missing"})
            elif parsed.path == "/healthz":
                self._send(200, {"status": "ok"})
            elif parsed.path == "/gate":
                self._send(200, gate_view(cfg.audit, self._int(qs, "limit", GATE_LIMIT_DEFAULT)))
            elif parsed.path == "/fleet":
                self._send(200, fleet_view(cfg.inventory))
            elif parsed.path == "/detections":
                self._send(200, detections_view())
            elif parsed.path == "/tail":
                labels = [lab for raw in qs.get("label", []) for lab in raw.split(",") if lab]
                code, payload = tail_view(labels, self._int(qs, "lines", TAIL_LINES_DEFAULT), cfg.allowlist)
                self._send(code, payload)
            else:
                self._send(404, {"error": "not found"})
        except Exception:  # noqa: BLE001 - never leak a traceback to the client
            traceback.print_exc(file=sys.stderr)
            self._send(500, {"error": "internal error (see server stderr)"})

    def _read_only(self) -> None:
        self.send_response(405)
        self.send_header("Allow", "GET")
        self.send_header("Content-Length", "0")
        self.end_headers()

    # The toolbox is a view. Spelling these out is the guarantee, not an oversight.
    do_POST = _read_only
    do_PUT = _read_only
    do_DELETE = _read_only
    do_PATCH = _read_only

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write(f"{self.address_string()} - {fmt % args}\n")


def serve(config: Config, host: str, port: int) -> None:
    _Handler.config = config
    httpd = ThreadingHTTPServer((host, port), _Handler)
    print(f"toolbox listening on http://{host}:{port}", file=sys.stderr)
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"WARNING: bound to {host} — reachable off-host. This view discloses host "
              "detail (inventory addresses, supervisor identity, log lines). Ensure TLS "
              "and deliberate exposure only.", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Serve the read-only detect toolbox over HTTP")
    ap.add_argument("--audit", default=str(Config.audit), help="gate audit chain to read")
    ap.add_argument("--inventory", default=str(Config.inventory), help="nodebox inventory to read")
    ap.add_argument("--allowlist", default=str(Config.allowlist), help="livetail operator allowlist")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args(argv)
    config = Config(audit=Path(args.audit), inventory=Path(args.inventory), allowlist=Path(args.allowlist))
    serve(config, args.host, args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
