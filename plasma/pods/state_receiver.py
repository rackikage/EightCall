#!/usr/bin/env python3
"""
state_receiver.py — line-oriented inbound endpoint for fleet/pods.

Plain TCP. One line per request: a sequence of `key=value` tokens
separated by whitespace. Maximum line length: 512 bytes.

Decoded by the value of `op`:

    op=hello  agent=<a> exec=<e> chain=<c>      agent registers
    op=state  agent=<a> state=<s> [extra...]     agent reports state
    op=work   agent=<a> exec=<e> result=<r>      agent reports work
    op=health                                    health probe

Ack:
    OK\n           on success
    ERR <reason>\n  on parse or dispatch error

No HTTP, no JSON, no regex. Tokens are split on '='; whitespace
separates tokens. The on-disk audit record (pods.log) is JSON, so
downstream tools can still parse it; this is just the wire format.

Wire payload budget: a hello line is ~80 bytes; state and work are
similarly tight. The 512-byte cap rejects anything bigger before any
regex / parse work runs.
"""

import json
import os
import signal
import socketserver
import sys
import time
from datetime import datetime, timezone

PODS_HOME = os.environ.get("PODS_HOME", os.path.expanduser("~/pods"))
PODS_LOG = os.environ.get("PODS_LOG", f"{PODS_HOME}/pods.log")
MAX_LINE = int(os.environ.get("PODS_RECEIVER_MAX_LINE", "512"))

os.makedirs(os.path.dirname(PODS_LOG), exist_ok=True)
LOG = open(PODS_LOG, "a", buffering=1)


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(stage, event, **fields):
    obj = {"ts": now(), "stage": stage, "event": event}
    obj.update(fields)
    LOG.write(json.dumps(obj) + "\n")


def parse(line):
    """Parse `k=v k=v ...` into a dict. No regex; partition + split only.

    Returns (dict, None) on success, (None, reason_str) on failure.
    """
    if not line:
        return None, "empty line"
    if len(line) > MAX_LINE:
        return None, f"line too long (>{MAX_LINE} bytes)"
    out = {}
    for tok in line.split():
        if "=" not in tok:
            return None, f"bad token: {tok!r}"
        k, _, v = tok.partition("=")
        if not k or not v:
            return None, f"empty key/value in {tok!r}"
        # Reject whitespace inside a value (would be ambiguous on parse).
        if any(c.isspace() for c in v):
            return None, f"whitespace in value: {tok!r}"
        out[k] = v
    return out, None


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        line = self.rfile.readline(MAX_LINE + 1).rstrip(b"\r\n").decode("utf-8", "replace")
        peer = self.client_address[0]

        if not line:
            return  # EOF before any data — peer closed the connection.

        msg, err = parse(line)
        if err:
            log("D", "reject", peer=peer, reason=err)
            self.wfile.write(f"ERR {err}\n".encode())
            return

        op = msg.get("op", "")
        log("D", "request", peer=peer, op=op, msg=msg)

        if op == "hello":
            log("D", "agent_hello", peer=peer, **{k: v for k, v in msg.items() if k != "op"})
            self.wfile.write(b"OK\n")
        elif op == "state":
            log("D", "agent_state", peer=peer, **{k: v for k, v in msg.items() if k != "op"})
            self.wfile.write(b"OK\n")
        elif op == "work":
            log("D", "agent_work", peer=peer, **{k: v for k, v in msg.items() if k != "op"})
            self.wfile.write(b"OK\n")
        elif op == "health":
            self.wfile.write(f"OK {int(time.time())}\n".encode())
        else:
            log("D", "reject", peer=peer, reason=f"unknown op: {op}")
            self.wfile.write(f"ERR unknown op: {op}\n".encode())


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    port = int(os.environ.get("PODS_RECEIVER_PORT", "41800"))
    host = os.environ.get("PODS_RECEIVER_HOST", "127.0.0.1")
    pid = os.getpid()
    pidfile = os.environ.get("PODS_RECEIVER_PIDFILE", f"{PODS_HOME}/pids/state-receiver.pid")
    os.makedirs(os.path.dirname(pidfile), exist_ok=True)
    with open(pidfile, "w") as f:
        f.write(str(pid))
    log("D", "started", port=port, host=host, pid=pid, max_line=MAX_LINE)
    server = Server((host, port), Handler)
    signal.signal(signal.SIGTERM, lambda *_: (server.shutdown(), log("D", "stopped", pid=pid)))
    try:
        server.serve_forever()
    finally:
        try:
            os.unlink(pidfile)
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    main()