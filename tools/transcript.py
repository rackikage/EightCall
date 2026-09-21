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
    transcript.py lineage [path ...]     flag-lineage: content refusal -> synthetic kill
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


def cmd_lineage(paths) -> int:
    """Per session: order refusals, classify content-refusal vs synthetic kill.

    A content refusal emitted tokens (something was evaluated). A synthetic kill
    has model=<synthetic> and zero tokens (nothing was evaluated). A session whose
    first event is a content refusal and whose later events are synthetic kills
    shows the escalation path, and is the shape that predicts a dead session.
    """
    files = [Path(p) for p in paths] if paths else find_transcripts(DEFAULT_ROOT)
    sessions = {}
    for path in files:
        events = list(refusal_events(path))
        if events:
            sessions[path.stem] = sorted(events, key=lambda e: e["line"])

    if not sessions:
        print("no refusal events found")
        return 0

    rows = []
    for sess, events in sessions.items():
        cats = sorted({e["category"] for e in events})
        first = events[0]
        content = [e for e in events if not e["synthetic"]]
        synthetic = [e for e in events if e["synthetic"]]
        escalated = bool(content) and bool(synthetic) and synthetic[0]["line"] > content[-1]["line"]
        rows.append({
            "session": sess,
            "n": len(events),
            "cats": cats,
            "content": len(content),
            "synthetic": len(synthetic),
            "escalated": escalated,
            "first_category": first["category"],
            "first_line": first["line"],
        })
    rows.sort(key=lambda r: (-r["n"], r["session"]))

    print(f"{'session':46s} {'n':>3s} {'content':>7s} {'synth':>5s}  {'escalated':9s} cats")
    for r in rows:
        print(f"{r['session'][:46]:46s} {r['n']:>3d} {r['content']:>7d} {r['synthetic']:>5d}  "
              f"{'yes' if r['escalated'] else 'no':9s} {','.join(r['cats'])}")
    print()
    esc = [r for r in rows if r["escalated"]]
    dead = [r for r in rows if r["n"] == r["synthetic"] and r["n"] > 0]
    print(f"sessions: {len(rows)}  escalated (content -> synthetic): {len(esc)}  "
          f"all-synthetic (never reached model): {len(dead)}")
    print()
    print("reading:")
    print("  content  = stop_reason=refusal with tokens emitted (something was evaluated)")
    print("  synth    = model=<synthetic>, 0 tokens (nothing was evaluated; API-layer kill)")
    print("  escalated sessions show the content-refusal -> synthetic-kill progression")
    print("  all-synthetic sessions were terminated without any evaluation")
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

    p = sub.add_parser("lineage", help="content-refusal vs synthetic-kill progression")
    p.add_argument("paths", nargs="*")

    args = ap.parse_args(argv)
    if args.cmd == "scan":
        return cmd_scan(args.paths, args.category, args.json)
    if args.cmd == "lineage":
        return cmd_lineage(args.paths)
    return cmd_sessions(args.paths)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
