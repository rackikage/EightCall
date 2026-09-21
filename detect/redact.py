#!/usr/bin/env python3
"""Redaction-capture stage: turn a detection hit into a finding that is SAFE to
persist.

This is the piece between a rule firing and the secured backend that the
governance framing asks for — "export only redacted matches + metadata; never
harvest, display, or transmit usable credentials." Nothing here ever writes,
returns, or logs a raw secret.

Design invariants — read before changing anything:

  1. THE RAW SECRET NEVER LEAVES. A matched secret is used only to compute a
     masked preview and a salted hash, both non-reversible. `Finding` has no
     field that holds the raw value, so an emitted record cannot contain it by
     construction (test_redact.py asserts the planted secret is absent from the
     written JSONL bytes).

  2. CORRELATION WITHOUT STORAGE. `secret_sha256` is HMAC-SHA256(salt, value):
     the same secret yields the same hash across runs/machines *iff* the same
     salt is configured (DETECT_REDACT_SALT), so findings can be deduped and
     correlated without the store ever holding the secret. With no salt set a
     random per-process salt is used (safe default: no cross-run correlation).
     `salt_id` = sha256(salt)[:12] records WHICH salt regime produced a hash,
     revealing nothing about the salt itself.

  3. THE PREVIEW IS A SHAPE, NOT A SAMPLE. `mask()` emits "<type>:********(N)"
     by default — the secret's type and length, no characters of the value.
     A deployment may set reveal_last>0 to expose only the last N characters
     (like a card's last-4); it defaults to 0 (nothing revealed).

  4. ONE CHAIN, SHARED WITH THE GATE. Findings append to a hash-chained JSONL
     using the SAME construction as authz_gate's audit (canonical_bytes,
     prev_hash -> record_hash, GENESIS_HASH), so `authz_gate verify` /
     `verify_audit_chain` validate this log too. The gate's own audit still
     records only an opaque evidence_ref (never contents); this findings log is
     the separate, redacted evidence trail, tied back by evidence_ref /
     decision_id. The gate never reads it — authority is still never inferred
     from content.

Contract the detection runner consumes on a hit:

    log = EvidenceLog("findings.jsonl")
    findings = capture_hit(rule, event, evidence_ref="ios_shell_abuse:seq3")
    log.emit_all(findings)                 # -> list of record hashes
    # or in one call:
    capture_and_emit(log, rule, event, evidence_ref="ios_shell_abuse:seq3")
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import threading
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

# One source of truth for the tamper-evident chain: reuse the gate's exact
# canonical serialization and verifier so both logs are the same construction.
from authz_gate import GENESIS_HASH, canonical_bytes, verify_audit_chain

SCHEMA = "detect.findings/v1"

# Resource bound: only the first MAX_SCAN_CHARS of any field are scanned.
# Detection (and therefore masking) covers that bounded prefix only — a secret
# starting beyond the cap is NOT detected. This keeps regex work linear in a
# fixed budget regardless of input size; raise it only with intent.
MAX_SCAN_CHARS = 1_000_000

# --- redaction primitives --------------------------------------------------


def _shannon_entropy(s: str) -> float:
    """Per-character Shannon entropy (bits). Used to gate the generic
    key=value matcher so low-entropy words (password=changeme) don't flood."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def mask(value: str, secret_type: str = "secret", reveal_last: int = 0) -> str:
    """Non-reversible preview. Default reveals NO characters of the value —
    only its type and length. reveal_last>0 exposes at most the last N chars
    (still never the whole secret)."""
    n = len(value)
    if reveal_last > 0 and n > reveal_last:
        return f"{secret_type}:{'*' * 4}{value[-reveal_last:]}({n})"
    return f"{secret_type}:{'*' * 8}({n})"


def fingerprint(value: str, salt: bytes) -> str:
    """Salted, non-reversible identity for a secret: HMAC-SHA256(salt, value).
    Stable within a salt regime -> dedupe/correlate; opaque without the salt."""
    return hmac.new(salt, value.encode("utf-8"), hashlib.sha256).hexdigest()


def resolve_salt(salt: bytes | str | None = None) -> tuple[bytes, str]:
    """(salt_bytes, salt_id). Explicit salt > DETECT_REDACT_SALT env > a random
    per-process salt (safe default; no cross-run correlation). salt_id is a
    short sha256 tag of the salt, safe to store."""
    if salt is None:
        env = os.environ.get("DETECT_REDACT_SALT")
        salt = env.encode("utf-8") if env else os.urandom(32)
    elif isinstance(salt, str):
        salt = salt.encode("utf-8")
    return salt, hashlib.sha256(salt).hexdigest()[:12]


# --- secret detection ------------------------------------------------------


def _luhn_ok(number: str) -> bool:
    """Luhn checksum — gates the credit-card (PAN) pattern so arbitrary 13-19
    digit runs (order ids, timestamps) are not mislabeled as card numbers."""
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


@dataclass(frozen=True)
class _Pattern:
    type: str
    regex: re.Pattern
    group: int          # capture group holding the secret (0 = whole match)
    min_entropy: float  # skip matches below this per-char entropy (0 = off)
    validator: object = None  # optional Callable[[str], bool]; match kept only if it returns True


@dataclass(frozen=True)
class _Match:
    """Internal only. `value` is the RAW secret and is never persisted or
    returned outside this module — it exists to compute preview + hash."""

    type: str
    value: str
    start: int
    end: int


_PATTERNS: tuple[_Pattern, ...] = (
    # --- cloud / platform credentials --------------------------------------
    _Pattern("aws_access_key_id",
             re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b"), 0, 0.0),
    _Pattern("aws_secret_access_key",
             re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})"), 1, 0.0),
    _Pattern("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), 0, 0.0),
    _Pattern("stripe_secret", re.compile(r"\b[rs]k_(?:live|test)_[0-9A-Za-z]{16,}\b"), 0, 0.0),
    # --- source-control / package tokens -----------------------------------
    _Pattern("github_pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), 0, 0.0),
    _Pattern("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"), 0, 0.0),
    _Pattern("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), 0, 0.0),
    _Pattern("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), 0, 0.0),
    # --- keys / tokens in transit ------------------------------------------
    _Pattern("private_key_pem",
             re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"), 0, 0.0),
    _Pattern("jwt",
             re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b"), 0, 0.0),
    _Pattern("bearer_token",
             re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/-]{16,}=*)"), 1, 0.0),
    # Quantifiers are explicitly bounded: an unbounded scheme run (`...*://`)
    # backtracks per start position on long scheme-like strings (O(n²) hang on
    # MB-scale input). Real URL schemes are <=32 chars; userinfo/password runs
    # are capped generously. Bounds keep every pattern near-linear.
    _Pattern("url_basic_auth",
             re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]{0,31}://[^\s/:@]{1,256}:([^\s/:@]{3,256})@"), 1, 0.0),
    # --- PHI / PII (redact, never store; matches the nwinx redaction intent) -
    _Pattern("us_ssn",
             re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), 0, 0.0),
    _Pattern("credit_card_pan",
             re.compile(r"\b(?:\d[ -]?){13,19}\b"), 0, 0.0, _luhn_ok),
    # --- generic key=value assignment (entropy-gated to cut noise) ----------
    _Pattern("generic_secret",
             re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key)\b"
                        r"\s*[=:]\s*[\"']?([^\s\"';,]{8,})"), 1, 3.0),
)


def scan_text(text: str) -> list[_Match]:
    """Find secret-shaped substrings. Overlapping matches are resolved by
    preferring the earlier, longer span, so a value is not double-counted by
    two patterns. Input is truncated to MAX_SCAN_CHARS first (see module
    constant) — detection covers the bounded prefix only."""
    if not isinstance(text, str) or not text:
        return []
    text = text[:MAX_SCAN_CHARS]
    raw: list[_Match] = []
    for pat in _PATTERNS:
        for m in pat.regex.finditer(text):
            val = m.group(pat.group)
            if not val:
                continue
            if pat.min_entropy and _shannon_entropy(val) < pat.min_entropy:
                continue
            if pat.validator is not None and not pat.validator(val):
                continue
            raw.append(_Match(pat.type, val, m.start(pat.group), m.end(pat.group)))
    raw.sort(key=lambda x: (x.start, -(x.end - x.start)))
    kept: list[_Match] = []
    for m in raw:
        if any(m.start < k.end and k.start < m.end for k in kept):
            continue  # overlaps a match we already kept
        kept.append(m)
    return kept


def scan_bytes(data: bytes) -> list[_Match]:
    """Scan binary content (e.g. a pcap payload). Bytes map losslessly to text
    via latin-1 so the regexes run over arbitrary binary without decode errors;
    offsets are byte offsets. The raw value stays internal, as with scan_text.
    Bounded to the first MAX_SCAN_CHARS bytes."""
    if not data:
        return []
    return scan_text(data[:MAX_SCAN_CHARS].decode("latin-1"))


def redact_text(text: str, *, reveal_last: int = 0) -> str:
    """Return `text` with every detected secret span replaced by its masked
    preview (mask()); non-secret content is preserved verbatim. The raw secret
    never appears in the return value — this is the safe-line primitive the
    live-log observer persists instead of a raw line."""
    if not isinstance(text, str) or not text:
        return text
    matches = scan_text(text)
    if not matches:
        return text
    out: list[str] = []
    pos = 0
    for mt in matches:  # scan_text returns non-overlapping, start-sorted spans
        out.append(text[pos:mt.start])
        out.append(mask(mt.value, mt.type, reveal_last=reveal_last))
        pos = mt.end
    out.append(text[pos:])
    return "".join(out)


# --- findings + evidence emitter -------------------------------------------


@dataclass(frozen=True)
class Finding:
    """A redacted, safe-to-persist detection finding. No field holds a raw
    secret: `preview` is masked and `secret_sha256` is a salted hash."""

    rule: str
    target: str
    field: str
    type: str
    offset: int
    length: int
    preview: str
    secret_sha256: str
    salt_id: str
    severity: str
    evidence_ref: str | None = None
    decision_id: str | None = None


def _event_target(event: dict) -> str:
    for key in ("dst", "target", "host", "src", "flow.id"):
        val = event.get(key)
        if isinstance(val, str) and val:
            return val
    return ""


def capture_hit(
    rule: dict | str,
    event: dict,
    *,
    fields: list[str] | None = None,
    salt: bytes | str | None = None,
    severity: str | None = None,
    evidence_ref: str | None = None,
    decision_id: str | None = None,
    reveal_last: int = 0,
) -> list[Finding]:
    """Scan a matched event's string fields and return redacted Findings.
    Never returns or logs the raw secret. `fields` scopes the scan; by default
    every string-valued field is scanned (patterns are specific + entropy-gated).
    A non-dict event is malformed input: it yields no findings, never raises."""
    if not isinstance(event, dict):
        return []
    salt_b, salt_id = resolve_salt(salt)
    if isinstance(rule, dict):
        rule_name = rule.get("title") or rule.get("id") or "rule"
        sev = severity or rule.get("level") or "medium"
    else:
        rule_name, sev = str(rule), (severity or "medium")
    target = _event_target(event)
    scan_fields = fields if fields is not None else [
        k for k, v in event.items() if isinstance(v, (str, bytes))
    ]
    findings: list[Finding] = []
    for fld in scan_fields:
        val = event.get(fld)
        if isinstance(val, bytes):
            matches = scan_bytes(val)
        elif isinstance(val, str):
            matches = scan_text(val)
        else:
            continue
        for mt in matches:
            findings.append(Finding(
                rule=str(rule_name), target=target, field=fld, type=mt.type,
                offset=mt.start, length=len(mt.value),
                preview=mask(mt.value, mt.type, reveal_last=reveal_last),
                secret_sha256=fingerprint(mt.value, salt_b), salt_id=salt_id,
                severity=str(sev), evidence_ref=evidence_ref, decision_id=decision_id,
            ))
    return findings


class EvidenceLog:
    """Append-only, hash-chained findings log. Same chain construction as the
    authz audit, so `verify_audit_chain` validates it. Thread-safe."""

    def __init__(self, path: str | os.PathLike, now_fn=None) -> None:
        self._path = Path(path)
        self._now = now_fn or (lambda: datetime.now(timezone.utc))
        self._lock = threading.Lock()
        self._prev_hash, self._seq = self._load_chain_tip()

    def _load_chain_tip(self) -> tuple[str, int]:
        prev, seq = GENESIS_HASH, 0
        if self._path.exists():
            with open(self._path) as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    rec = json.loads(line)
                    prev, seq = rec["record_hash"], rec["seq"] + 1
        return prev, seq

    def emit(self, finding: Finding) -> str:
        """Append one finding; return its chain hash. The record carries only
        the redacted Finding fields — never a raw secret."""
        with self._lock:
            record = {
                "schema": SCHEMA,
                "seq": self._seq,
                "ts": self._now().isoformat(),
                **asdict(finding),
                "prev_hash": self._prev_hash,
            }
            record["record_hash"] = hashlib.sha256(canonical_bytes(record)).hexdigest()
            with open(self._path, "a") as fh:
                fh.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._prev_hash = record["record_hash"]
            self._seq += 1
            return record["record_hash"]

    def emit_all(self, findings: list[Finding]) -> list[str]:
        return [self.emit(f) for f in findings]


def capture_and_emit(log: EvidenceLog, rule, event, **kwargs) -> list[str]:
    """Convenience for a runner: capture a hit and emit it in one call."""
    return log.emit_all(capture_hit(rule, event, **kwargs))


if __name__ == "__main__":
    import sys

    if len(sys.argv) >= 3 and sys.argv[1] == "verify":
        ok, n, bad = verify_audit_chain(sys.argv[2])
        print(f"findings chain: {n} records -> {'OK' if ok else f'BROKEN at seq {bad}'}")
        sys.exit(0 if ok else 1)
    print("usage: redact.py verify <findings.jsonl>", file=sys.stderr)
    sys.exit(2)
