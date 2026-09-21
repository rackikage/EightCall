---
name: extracting-research-briefs
description: >-
  Use when Perplexity (or another research pane) finished answering and the
  lead agent must save raw text plus a structured engine brief under
  engine/briefs/.
---

# Extracting Research Briefs

## Overview

Clipboard-extract research panes into `engine/research/`, then grind a schema-valid brief.

## Recipe

1. Focus research window (`wmctrl` / `scripts/puppet.py focus`)
2. Click content → Ctrl+A → Ctrl+C
3. Write `engine/research/NN-raw.txt`
4. Fill `engine/briefs/brief-NNN.json` using `brief.schema.json`
5. Write human `INTEL-NNN.md` with BUILD one-liner
6. Set `stop_when` and `confidence`

## Brief must include

- `decision` (metro / path / stack as relevant)
- `build_one_liner`
- `stop_when`
- `sources_files` pointing at raw extracts

## Red flags

- Brief with only vibes, no files in `sources_files`
- Overwriting brief-001 without new id
- Pasting API keys into briefs
