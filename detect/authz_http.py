#!/usr/bin/env python3
"""HTTP front end for the authorization gate — the remote-hosting layer.

Runners on other guest VMs POST a signed request; the gate decides and returns
{allow, reason, decision_id}. The HTTP layer adds NO trust of its own: the
Ed25519 signature is the authentication and deny-by-default is the rule, so
even an exposed endpoint cannot yield an allow to anyone without a private key
pinned in the policy. Bind 127.0.0.1 by default; expose to the LAN only
deliberately (e.g. via the FLEET gateway) and put TLS in front.

    POST /authorize   body: the request JSON  ->  200 {allow:true,  ...}
                                                   403 {allow:false, ...}
                                                   400 {error: "..."}  (unparseable)
    GET  /healthz     ->  200 {status:"ok"}

Run:
    ./venv69/bin/python3 authz_http.py --policy authz_policy.yml \
        --host 127.0.0.1 --port 8787
"""
from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from authz_gate import AuthzGate

MAX_BODY = 64 * 1024  # a request is small; cap the body to bound memory


class _Handler(BaseHTTPRequestHandler):
    gate: AuthzGate = None  # set on the server class before serving
    server_version = "detect-authz/2.0"

    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send(200, {"status": "ok"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path != "/authorize":
            self._send(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send(400, {"error": "bad Content-Length"})
            return
        if length <= 0 or length > MAX_BODY:
            self._send(400, {"error": "empty or oversized body"})
            return
        raw = self.rfile.read(length)
        try:
            request = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            self._send(400, {"error": "body is not valid JSON"})
            return
        # A non-object request is malformed; hand it to the gate anyway so the
        # denial is audited like any other, rather than silently 400'd.
        decision = self.gate.authorize(request if isinstance(request, dict) else {"_": request})
        code = 200 if decision.allow else 403
        self._send(code, {
            "allow": decision.allow,
            "reason": decision.reason,
            "decision_id": decision.decision_id,
        })

    def log_message(self, fmt: str, *args) -> None:
        # One audited line per decision already lands in the audit trail; keep
        # the HTTP access log quiet and off stdout.
        sys.stderr.write(f"{self.address_string()} - {fmt % args}\n")


def serve(policy: str, host: str, port: int) -> None:
    gate = AuthzGate.from_policy_file(policy)
    _Handler.gate = gate
    httpd = ThreadingHTTPServer((host, port), _Handler)
    print(f"authz gate listening on http://{host}:{port} (policy: {policy})", file=sys.stderr)
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"WARNING: bound to {host} — reachable off-host. Ensure TLS + "
              "deliberate exposure only.", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Serve the authorization gate over HTTP")
    ap.add_argument("--policy", default="authz_policy.yml")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    args = ap.parse_args(argv)
    serve(args.policy, args.host, args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
