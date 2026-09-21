#!/usr/bin/env python3
"""Claude Code transcript triage: surface refusal events and their server-side category.

A refusal classifier is a detector and fails like one. This tool reads Claude Code
session transcripts (~/.claude/projects/<slug>/<session>.jsonl) and reports every
turn that carried stop_reason=refusal, with the category code the server attached,
so a misfire is visible instead of silently ending a session.

    transcript.py scan [path ...]        summary of refusal events
    transcript.py scan --category bio    filter by category code
    transcript.py scan --json            machine-readable records
    transcript.py sessions               list sessions with refusal counts
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

DEFAULT_ROOT = Path.home() / ".claude" / "projects"


def _tool_summary(block) -> str:
    name = block.get("name", "?")
    inp = block.get("input", {}) or {}
    target = inp.get("file_path") or inp.get("description") or inp.get("command") or ""
    return f"{name}({str(target)[:80]})"


def iter_records(path: Path):
    for n, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            yield n, json.loads(raw)
        except json.JSONDecodeError:
            continue


def refusal_events(path: Path):
    """Yield one record per assistant message carrying stop_reason=refusal."""
    for n, rec in iter_records(path):
        if rec.get("type") != "assistant":
            continue
        msg = rec.get("message") or {}
        if msg.get("stop_reason") != "refusal":
            continue
        details = msg.get("stop_details") or {}
        content = msg.get("content") or []
        text = ""
        tools = []
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text":
                text += block.get("text", "")
            elif block.get("type") == "tool_use":
                tools.append(_tool_summary(block))
        usage = msg.get("usage") or {}
        yield {
            "line": n,
            "session": path.stem,
            "model": msg.get("model"),
            "category": details.get("category"),
            "explanation": details.get("explanation"),
            "recovery_offered": details.get("fallback_has_prefill_claim"),
            "synthetic": msg.get("model") == "<synthetic>",
            "output_tokens": usage.get("output_tokens"),
            "text": text.strip()[:300],
            "tool_uses": tools,
        }


def find_transcripts(root: Path):
    return sorted(root.rglob("*.jsonl"))


def cmd_scan(paths, category=None, as_json=False) -> int:
    files = [Path(p) for p in paths] if paths else find_transcripts(DEFAULT_ROOT)
    events = []
    for path in files:
        if not path.is_file():
            print(f"warning: not a file: {path}", file=sys.stderr)
            continue
        for ev in refusal_events(path):
            if category and ev["category"] != category:
                continue
            events.append(ev)

    if as_json:
        for ev in events:
            print(json.dumps(ev, sort_keys=True))
        return 0

    if not events:
        print(f"no refusal events across {len(files)} transcript(s)")
        return 0

    by_cat: Counter = Counter(ev["category"] for ev in events)
    by_sess: Counter = Counter(ev["session"] for ev in events)
    print(f"refusal events: {len(events)} across {len(by_sess)} session(s), {len(files)} file(s)")
    print("by category:", dict(by_cat))
    print()
    print(f"{'session':40s} {'line':>5s} {'category':10s} {'syn':4s} {'out':>6s}  detail")
    for ev in events:
        detail = ev["tool_uses"][0] if ev["tool_uses"] else ev["text"][:60].replace("\n", " ")
        print(f"{ev['session'][:40]:40s} {ev['line']:>5d} {str(ev['category']):10s} "
              f"{'yes' if ev['synthetic'] else 'no':4s} {str(ev['output_tokens']):>6s}  {detail}")
    print()
    print("note: category=refusal is a server-side label; a synthetic record with")
    print("      input_tokens=0 never reached the model (session-level termination).")
    return 0


def cmd_sessions(paths) -> int:
    files = [Path(p) for p in paths] if paths else find_transcripts(DEFAULT_ROOT)
    rows = []
    for path in files:
        events = list(refusal_events(path))
        if not events:
            continue
        cats = Counter(e["category"] for e in events)
        rows.append((len(events), path.name, dict(cats), path))
    rows.sort(reverse=True)
    print(f"{'refusals':>8s}  {'session':44s} categories")
    for count, name, cats, _ in rows:
        print(f"{count:>8d}  {name[:44]:44s} {cats}")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="transcript.py")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("scan", help="report refusal events")
    p.add_argument("paths", nargs="*")
    p.add_argument("--category")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("sessions", help="sessions that contain refusals")
    p.add_argument("paths", nargs="*")

    args = ap.parse_args(argv)
    if args.cmd == "scan":
        return cmd_scan(args.paths, args.category, args.json)
    return cmd_sessions(args.paths)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
