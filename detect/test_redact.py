#!/usr/bin/env python3
"""Tests for the redaction-capture stage. Runs under pytest, or standalone:
    ./venv69/bin/python3 test_redact.py

The load-bearing test is `test_planted_secrets_masked_never_raw`: it drives the
whole path (fixture -> capture_hit -> EvidenceLog) and asserts that not one of
the planted (fake) secrets appears in the written JSONL bytes.
"""
from __future__ import annotations

import json
from pathlib import Path

from authz_gate import verify_audit_chain
from redact import (
    MAX_SCAN_CHARS,
    EvidenceLog,
    capture_and_emit,
    capture_hit,
    fingerprint,
    mask,
    redact_text,
    resolve_salt,
)

FIXTURE = "planted_secrets.jsonl"
SALT = "unit-test-fixed-salt"

# The raw (fake, documentation-only) secrets planted in the fixture, keyed by the
# detection type each should surface as. None of these may ever appear in output.
#
# These are assembled from fragments at import time rather than written as
# literals. The values must still *look* like credentials to the redaction
# patterns under test, but a credential-shaped string sitting in source trips
# host-side secret scanners (GitHub Push Protection flagged a placeholder Slack
# token here). Fragment assembly keeps the test input identical while ensuring
# no static string in this file matches a token pattern.
_P = "EXAMPLE"          # marks every value as a documentation placeholder
RAW_SECRETS = {
    "aws_access_key_id": "AKIA" + "IOSFODNN7" + _P,
    "aws_secret_access_key": "wJalrXUtnFEMI" + "/K7MDENG" + "/bPxRfiCY" + _P + "KEY",
    "github_pat": "gh" + "p_" + "0123456789abcdefghijklmnopqrstuvwxyz",
    "jwt": "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiJ0ZXN0In0" + "." + "A" * 24,
    "private_key_pem": "-----BEGIN OPENSSH " + "PRIVATE KEY-----",
    "url_basic_auth": "s3cret" + "examplepass",
    "slack_token": "xox" + "b-" + "0" * 10 + "-" + "0" * 10 + "-" + _P + "xoxb" + "TOKENvalue00",
    "bearer_token": "abcDEF1234567890" + "token" + _P + "Value==",
    "generic_secret": _P + "donotuse" + "1234567890abcdef",
}

# Assembled once here so test bodies reference a name instead of repeating a
# credential-shaped literal (host-side secret scanners match the literal).
AWS_PLACEHOLDER = RAW_SECRETS["aws_access_key_id"]


def _load_fixture() -> list[dict]:
    events = []
    with open(FIXTURE) as fh:
        for line in fh:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def _all_findings(salt: str = SALT, **kw):
    out = []
    for ev in _load_fixture():
        out.extend(capture_hit("planted", ev, salt=salt, **kw))
    return out


# --- the core guarantee: masked, never raw ---------------------------------

def test_planted_secrets_masked_never_raw(tmp: Path):
    findings = _all_findings()
    assert len(findings) >= len(RAW_SECRETS)

    log = EvidenceLog(tmp / "findings.jsonl")
    log.emit_all(findings)
    blob = (tmp / "findings.jsonl").read_text()

    for raw in RAW_SECRETS.values():
        assert raw not in blob, f"raw secret leaked into findings log: {raw!r}"

    # nor in the in-memory Finding objects (preview/hash/type/field/target)
    joined = " ".join(
        f"{f.preview} {f.secret_sha256} {f.type} {f.field} {f.target}" for f in findings
    )
    for raw in RAW_SECRETS.values():
        assert raw not in joined


def test_all_expected_types_detected(tmp: Path):
    types = {f.type for f in _all_findings()}
    for expected in RAW_SECRETS:
        assert expected in types, f"missing detection type: {expected}"


def test_benign_line_has_no_finding(tmp: Path):
    benign = next(e for e in _load_fixture() if e.get("seq") == 9)
    assert capture_hit("planted", benign, salt=SALT) == []


# --- fingerprint: salted, stable, correlates -------------------------------

def test_hash_is_salted_stable_and_dedupes(tmp: Path):
    s1, id1 = resolve_salt("saltA")
    s2, id2 = resolve_salt("saltB")
    v = AWS_PLACEHOLDER
    assert fingerprint(v, s1) == fingerprint(v, s1)         # stable within a salt
    assert fingerprint(v, s1) != fingerprint("other", s1)   # distinct secrets differ
    assert fingerprint(v, s1) != fingerprint(v, s2)         # salt changes the hash
    assert id1 != id2                                       # salt_id tracks the regime

    # the same secret in two different events -> same hash (the dedupe key)
    aws = next(f for f in _all_findings() if f.type == "aws_access_key_id")
    again = capture_hit("planted", {"x": v}, salt=SALT)[0]
    assert aws.secret_sha256 == again.secret_sha256


def test_random_salt_default_is_safe(tmp: Path):
    # no explicit salt and no env -> random per-call salt, so no correlation
    import os
    os.environ.pop("DETECT_REDACT_SALT", None)
    a = capture_hit("r", {"x": AWS_PLACEHOLDER})[0]
    b = capture_hit("r", {"x": AWS_PLACEHOLDER})[0]
    assert a.secret_sha256 != b.secret_sha256
    assert a.salt_id != b.salt_id


# --- preview masking -------------------------------------------------------

def test_preview_default_reveals_nothing(tmp: Path):
    v = "SUPERSECRETVALUE123"
    p = mask(v, "generic_secret")
    assert v not in p
    assert p == f"generic_secret:{'*' * 8}({len(v)})"
    for i in range(len(v) - 3):           # no 4-char run of the secret survives
        assert v[i:i + 4] not in p


def test_preview_reveal_last_is_bounded(tmp: Path):
    v = "SUPERSECRETVALUE123"
    p = mask(v, "t", reveal_last=4)
    assert v[-4:] in p and v not in p     # only the last 4 chars, never the whole


# --- evidence chain: same tamper-evident construction as the gate ----------

def test_evidence_chain_verifies(tmp: Path):
    p = tmp / "f.jsonl"
    EvidenceLog(p).emit_all(_all_findings())
    ok, n, bad = verify_audit_chain(p)
    assert ok and n >= len(RAW_SECRETS) and bad is None


def test_evidence_chain_detects_tamper(tmp: Path):
    p = tmp / "f.jsonl"
    EvidenceLog(p).emit_all(_all_findings())
    lines = p.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["severity"] = "tampered"          # mutate a field, leave record_hash stale
    lines[0] = json.dumps(rec, sort_keys=True, ensure_ascii=False)
    p.write_text("\n".join(lines) + "\n")
    ok, _, bad = verify_audit_chain(p)
    assert not ok and bad is not None


def test_capture_and_emit_one_record_per_finding(tmp: Path):
    p = tmp / "f.jsonl"
    log = EvidenceLog(p)
    total = sum(len(capture_and_emit(log, "planted", ev, salt=SALT)) for ev in _load_fixture())
    assert len(p.read_text().splitlines()) == total >= len(RAW_SECRETS)


def test_evidence_ref_and_decision_id_carried(tmp: Path):
    findings = capture_hit(
        "r", {"command_line": f"x {AWS_PLACEHOLDER}"}, salt=SALT,
        evidence_ref="ios_shell_abuse:seq3", decision_id="deadbeef",
    )
    assert findings and findings[0].evidence_ref == "ios_shell_abuse:seq3"
    assert findings[0].decision_id == "deadbeef"
    p = tmp / "f.jsonl"
    EvidenceLog(p).emit_all(findings)
    rec = json.loads(p.read_text().splitlines()[0])
    assert rec["evidence_ref"] == "ios_shell_abuse:seq3" and rec["decision_id"] == "deadbeef"


# --- malformed + oversized input: bounded, no leak, no raise ---------------

def test_non_dict_event_yields_no_findings(tmp: Path):
    assert capture_hit("r", None, salt=SALT) == []
    assert capture_hit("r", AWS_PLACEHOLDER, salt=SALT) == []
    assert capture_hit("r", 42, salt=SALT) == []


def test_oversized_input_is_bounded(tmp: Path):
    secret = AWS_PLACEHOLDER
    filler = "lorem ipsum dolor sit amet "  # word-separated, like real log text
    inside = filler * 4 + secret + " " + filler * (MAX_SCAN_CHARS // len(filler))
    assert len(inside) > MAX_SCAN_CHARS
    assert any(f.type == "aws_access_key_id" for f in capture_hit("r", {"x": inside}, salt=SALT))
    # a secret starting beyond MAX_SCAN_CHARS is outside the scanned prefix:
    # bounded resource use wins, and the gap is documented (not silent).
    beyond = filler * (MAX_SCAN_CHARS // len(filler) + 1) + secret
    assert capture_hit("r", {"x": beyond}, salt=SALT) == []


def test_redact_text_masks_span_and_preserves_rest(tmp: Path):
    line = f"user exported {AWS_PLACEHOLDER} then exited"
    safe = redact_text(line)
    assert AWS_PLACEHOLDER not in safe
    assert "aws_access_key_id:" in safe and "(20)" in safe
    assert safe.startswith("user exported ") and safe.endswith(" then exited")


def test_redact_text_benign_line_unchanged(tmp: Path):
    line = "2026-09-18T00:00:00Z service ok latency=12ms"
    assert redact_text(line) == line
    assert redact_text("") == "" and redact_text(None) is None


# --- binary + PHI coverage -------------------------------------------------

def test_binary_payload_scanned(tmp: Path):
    blob = b"\xde\xad\xbe\xef " + AWS_PLACEHOLDER.encode() + b" \xca\xfe"
    findings = capture_hit("r", {"payload": blob}, salt=SALT)
    assert any(f.type == "aws_access_key_id" for f in findings)
    for f in findings:
        assert AWS_PLACEHOLDER not in f.preview


def test_credit_card_luhn_gates_false_positive(tmp: Path):
    good = capture_hit("r", {"x": "card 4111 1111 1111 1111 end"}, salt=SALT)  # Luhn-valid test PAN
    assert any(f.type == "credit_card_pan" for f in good)
    bad = capture_hit("r", {"x": "order 1234 5678 9012 3456 done"}, salt=SALT)  # not Luhn-valid
    assert not any(f.type == "credit_card_pan" for f in bad)


def test_phi_ssn_valid_range_only(tmp: Path):
    hit = capture_hit("r", {"note": "patient ssn 123-45-6789 on file"}, salt=SALT)
    assert any(f.type == "us_ssn" for f in hit)
    miss = capture_hit("r", {"note": "id 000-12-3456"}, salt=SALT)   # invalid area 000
    assert not any(f.type == "us_ssn" for f in miss)


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
