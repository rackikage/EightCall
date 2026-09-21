#!/usr/bin/env python3
"""Read-only live-log observation stage for the detect pipeline.

The collector half of the redaction pipeline: observe APPROVED log files and
turn what is seen into safe structured records. Design invariants:

  1. READ ONLY. The only process ever spawned is `tail` with a fixed argv
     vector (list form, shell=False — no shell, no concatenation, no
     metacharacter interpretation). This module never writes to, truncates,
     rotates, or follows anything but an allowlisted file.

  2. BOUNDED SOURCES. Callers name ALLOWLIST LABELS, never paths. The
     label -> path mapping lives in an operator-controlled YAML file
     (default: log_allowlist.yml next to this module); a label that is not
     in the allowlist is refused before any process is spawned. There is no
     code path from a caller-supplied string to an arbitrary file.

  3. BOUNDED OUTPUT. Historical reads use `tail -v -n N` (N capped). Live
     follows use `tail -v -n N -F` — -F follows by NAME across rotation/
     recreation (plain -f follows the inode and goes silent after rotate)
     and -v prints an `==> path <==` header so multiple sources stay
     attributed. Follows stop at the first of: time budget, line budget,
     byte budget. Single lines are truncated to MAX_LINE_CHARS. Snapshot
     reads have an OS-level timeout.

  4. REDACTION BEFORE PERSISTENCE. Every line passes through redact.py the
     moment it is read: the returned/persisted record carries only the
     redacted line (redact_text), and any detected secret becomes a Finding
     via capture_hit (masked preview + salted HMAC, never the raw value).
     The raw line exists only transiently in process memory. No intermediate
     raw capture file is ever written; if an EvidenceLog is attached, only
     redacted findings land on disk.

  5. ATTRIBUTION. Every record carries an observation timestamp (UTC,
     ISO-8601), the allowlist label of its source, and a trace_id shared by
     one observation session, so records correlate without raw content.

Rate limiting applies to follows (lines/second, sleeping reader); snapshots
are inherently bounded one-shot reads.

CLI:
    livetail.py labels
    livetail.py snapshot LABEL [LABEL...] [--lines 200] [--evidence f.jsonl]
    livetail.py follow   LABEL [LABEL...] [--seconds 30] [--max-lines 1000]
"""
from __future__ import annotations

import argparse
import json
import queue
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml

from redact import EvidenceLog, capture_hit, redact_text

DEFAULT_ALLOWLIST = Path(__file__).with_name("log_allowlist.yml")
RULE_NAME = "livetail"

MAX_LINES = 1_000            # hard ceiling on -n, whatever the caller asks
MAX_LINE_CHARS = 8_192       # a single observed line never exceeds this
MAX_FOLLOW_CHARS = 4_000_000 # total byte budget of one follow session
DEFAULT_RATE_PER_SEC = 500   # follow reader paces itself to this

_HEADER_PRE, _HEADER_POST = "==> ", " <=="  # tail -v source headers


def load_allowlist(path: str | Path | None = None) -> dict[str, Path]:
    """Load the operator allowlist: {label: log file path}.

    Relative paths resolve against the allowlist file's own directory.
    Every entry must be an existing regular file — a bad allowlist fails
    loud at load time, not at observation time.
    """
    path = Path(path or DEFAULT_ALLOWLIST)
    with open(path) as fh:
        raw = yaml.safe_load(fh)
    if not isinstance(raw, dict) or not raw:
        raise ValueError(f"allowlist {path} must be a non-empty mapping of label: path")
    base = path.parent
    allow: dict[str, Path] = {}
    for label, p in raw.items():
        if not isinstance(label, str) or not isinstance(p, str):
            raise TypeError("allowlist labels and paths must be strings")
        resolved = Path(p) if Path(p).is_absolute() else (base / p).resolve()
        if not resolved.is_file():
            raise ValueError(f"allowlist entry {label!r} -> {resolved} is not an existing file")
        allow[label] = resolved
    return allow


def _resolve_labels(labels: list[str], allow: dict[str, Path]) -> dict[str, Path]:
    """Map requested labels to allowlisted paths, or refuse. This is the only
    gate between a caller string and a filesystem path — refusal happens
    BEFORE any process exists."""
    unknown = [l for l in labels if l not in allow]
    if unknown:
        raise ValueError(
            f"label(s) not in allowlist: {unknown}; approved: {sorted(allow)}"
        )
    return {l: allow[l] for l in labels}


def _tail_argv(paths: list[Path], lines: int, follow: bool) -> list[str]:
    """Fixed argv vector. -v labels every source; -F follows by name across
    rotation. List form only — no shell ever sees these bytes."""
    argv = ["tail", "-v", "-n", str(min(max(1, lines), MAX_LINES))]
    if follow:
        argv.append("-F")
    argv.extend(str(p) for p in paths)
    return argv


class _Session:
    """One observation session: redacts lines, collects safe records, emits
    findings. Raw line text is held only in locals and never persisted."""

    def __init__(self, sources: dict[str, Path], evidence: EvidenceLog | None, now_fn):
        self._by_path = {str(p): label for label, p in sources.items()}
        self._evidence = evidence
        self._now = now_fn or (lambda: datetime.now(timezone.utc))
        self.trace_id = uuid.uuid4().hex
        self.records: list[dict] = []
        self._current: str | None = None
        self._lineno = 0
        self._pending_blank = False

    def feed(self, line: str) -> None:
        """Consume one raw output line from tail. `tail -v` separates file
        blocks with a blank line before each `==> path <==` header, so a blank
        is DEFERRED: a following header proves it was a separator (dropped), a
        following content line proves it was content (emitted, then content)."""
        line = line.rstrip("\n")
        if line.startswith(_HEADER_PRE) and line.endswith(_HEADER_POST):
            path = line[len(_HEADER_PRE):-len(_HEADER_POST)]
            self._current = self._by_path.get(path, path)
            self._pending_blank = False
            return
        if line == "":
            if self._current is not None:
                self._pending_blank = True
            return
        if self._current is None:
            return  # unattributable noise before any header; -v always headers
        if self._pending_blank:
            self._emit("")  # the deferred blank was real content
            self._pending_blank = False
        self._emit(line)

    def _emit(self, line: str) -> None:
        self._lineno += 1
        raw = line[:MAX_LINE_CHARS]
        # transient scan of the raw line; only masked artifacts survive
        findings = capture_hit(
            RULE_NAME,
            {"line": raw, "target": f"log:{self._current}"},
            evidence_ref=f"livetail:{self._current}:{self._lineno}",
        )
        if self._evidence is not None:
            self._evidence.emit_all(findings)
        self.records.append({
            "ts": self._now().isoformat(),
            "trace_id": self.trace_id,
            "source": self._current,
            "line": redact_text(raw),
            "findings": len(findings),
        })


def snapshot(
    labels: list[str],
    *,
    allowlist_path: str | Path | None = None,
    lines: int = 200,
    timeout: float = 10.0,
    evidence: EvidenceLog | None = None,
    now_fn=None,
) -> list[dict]:
    """Bounded historical read: `tail -v -n N` over the allowlisted paths,
    once, with an OS-level timeout. Returns safe records."""
    sources = _resolve_labels(labels, load_allowlist(allowlist_path))
    argv = _tail_argv(list(sources.values()), lines, follow=False)
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, errors="replace", timeout=timeout,
            check=False,  # a nonzero tail exit (e.g. rotated-away file) must not
        )               # raise; whatever bounded output exists is still usable
        out = proc.stdout
    except subprocess.TimeoutExpired as exc:
        out = exc.output or ""  # bounded partial output; still redacted below
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
    sess = _Session(sources, evidence, now_fn)
    for line in out.splitlines():
        sess.feed(line)
    return sess.records


def follow(
    labels: list[str],
    *,
    allowlist_path: str | Path | None = None,
    lines: int = 100,
    seconds: float = 30.0,
    max_lines: int = 1_000,
    max_chars: int = MAX_FOLLOW_CHARS,
    rate_per_sec: float = DEFAULT_RATE_PER_SEC,
    evidence: EvidenceLog | None = None,
    now_fn=None,
) -> list[dict]:
    """Bounded live follow: `tail -v -n N -F`. Stops at the first budget
    exhausted (time / lines / chars) and ALWAYS tears the child down
    (terminate, then kill). The reader paces itself to rate_per_sec."""
    sources = _resolve_labels(labels, load_allowlist(allowlist_path))
    argv = _tail_argv(list(sources.values()), lines, follow=True)
    sess = _Session(sources, evidence, now_fn)

    proc = subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, errors="replace", bufsize=1,
    )
    q: queue.Queue[str | None] = queue.Queue()

    def _reader() -> None:
        try:
            for line in proc.stdout:
                q.put(line)
        finally:
            q.put(None)

    reader = threading.Thread(target=_reader, daemon=True)
    reader.start()
    deadline = time.monotonic() + seconds
    seen_lines = seen_chars = 0
    window_start, window_count = time.monotonic(), 0
    try:
        while True:
            if seen_lines >= max_lines or seen_chars >= max_chars:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                line = q.get(timeout=min(0.1, remaining))
            except queue.Empty:
                continue
            if line is None:  # tail exited on its own
                break
            # pace the reader: at most rate_per_sec lines per 1s window
            now = time.monotonic()
            if now - window_start >= 1.0:
                window_start, window_count = now, 0
            window_count += 1
            if window_count > rate_per_sec:
                time.sleep(max(0.0, 1.0 - (now - window_start)))
                window_start, window_count = time.monotonic(), 1
            seen_lines += 1
            seen_chars += len(line)
            sess.feed(line)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
        reader.join(timeout=2)
    return sess.records


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Read-only allowlisted log observation")
    ap.add_argument("--allowlist", default=str(DEFAULT_ALLOWLIST))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("labels", help="list approved labels")
    for name in ("snapshot", "follow"):
        p = sub.add_parser(name)
        p.add_argument("labels", nargs="+")
        p.add_argument("--lines", type=int, default=200 if name == "snapshot" else 100)
        p.add_argument("--evidence", help="append redacted findings to this JSONL log")
        if name == "snapshot":
            p.add_argument("--timeout", type=float, default=10.0)
        else:
            p.add_argument("--seconds", type=float, default=30.0)
            p.add_argument("--max-lines", type=int, default=1_000)
            p.add_argument("--rate", type=float, default=DEFAULT_RATE_PER_SEC)
    args = ap.parse_args(argv)

    allow = load_allowlist(args.allowlist)
    if args.cmd == "labels":
        for label, path in sorted(allow.items()):
            print(f"{label}\t{path}")
        return 0

    evidence = EvidenceLog(args.evidence) if args.evidence else None
    if args.cmd == "snapshot":
        records = snapshot(args.labels, allowlist_path=args.allowlist,
                           lines=args.lines, timeout=args.timeout, evidence=evidence)
    else:
        records = follow(args.labels, allowlist_path=args.allowlist,
                         lines=args.lines, seconds=args.seconds,
                         max_lines=args.max_lines, rate_per_sec=args.rate,
                         evidence=evidence)
    for rec in records:
        print(json.dumps(rec, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
