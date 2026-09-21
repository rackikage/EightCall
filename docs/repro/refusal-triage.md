# Refusal-classifier triage: the `bio` misfire

## Summary

Claude Code sessions can end with `stop_reason: refusal` and a server-assigned
`stop_details.category`. That category is **not** model output and is **not**
explanatory: across 297 local transcripts, `cyber` fired 42 times (expected for a
security repo) while `bio` fired **8 times on two sessions, 8/8 of them false**.

This document records the evidence so a misfire is recognizable instead of
mistaken for a real refusal.

## Evidence

`tools/transcript.py scan --category bio`:

| session | line | synthetic | output_tokens | detail |
|---|---|---|---|---|
| 8fcf3894 | 111 | no | 5674 | (thinking only) |
| 8fcf3894 | 141 | no | 3552 | (thinking only) |
| 8fcf3894 | 142 | no | 3552 | "I've now read every rule, fixture..." |
| 8fcf3894 | 143 | no | 3552 | `Write(.../view-a-more-offensive-streamed-codd.md)` |
| 8fcf3894 | 148 | no | 2041 | (thinking only) |
| 8fcf3894 | 150 | yes | 0 | `API Error: Opus 4.8 can't help with this` |
| cccdc43c | 194 | no | 1948 | (thinking only) |
| cccdc43c | 196 | yes | 0 | `API Error: Sonnet 5 can't help with this` |

## Mechanism (from record structure)

- `stop_details.category` is **server-assigned**; `explanation` is `null` on every
  event, so the label carries no rationale.
- Once set for a turn, the label applies to **subsequent messages in that turn**.
  Line 142 is a four-word sentence about reading files, yet carries `bio`.
- The terminal event is synthetic: `model: "<synthetic>"`, `input_tokens: 0` — it
  never reached the model. The session is terminated at the API layer.
- The misfire rate within its own bucket is 100%: no `bio` event observed here
  involved biological subject matter; all were tool writes or planning text.

## What is in scope to fix

Client-side inputs and observability. The classifier itself is not ours to patch.

**Session habits**

1. Never let a generated path inherit prompt wording. A file named after a prompt
   phrase can be the trigger at the write boundary.
2. One topic per session; do not accumulate mixed lexical domains in one envelope.
3. After any refusal, start a fresh session. Recovery within a poisoned session is
   not available.
4. Report a misfire as a bug; re-request from a clean session rather than retrying
   inside the flagged one.

**Observability**

`tools/transcript.py` makes refusals first-class telemetry:

```
tools/transcript.py scan
tools/transcript.py scan --category bio
tools/transcript.py scan --json
tools/transcript.py sessions
```

A refused-but-harmless action should be visible as a labeled event, not a dead
session.

## Explicitly out of scope

Modifying, patching, disabling, or working around the refusal classifier itself.
This document is a bug report and a triage aid, not a workaround.
