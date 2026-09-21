# EightCall — harden detection + gated acceptance planner

## Context
EightCall (`~/Projects/EightCall`) is a **defensive** Windows firewall/WFP detection pack:
`tools/fwlog.py` and `tools/wfp.py` parse pfirewall.log and WFP diagnostic XML; `tools/sigma_check.py`
validates and compiles the `rules/windows/*.yml` Sigma rules to SIEM backends; `tests/attack/run.py`
fires those rules at **synthetic** fixtures + evasion variants and documents 4 blind spots.

The goal of this work is to make the *detection* harder to evade (attack harder in the offline harness,
close the documented gaps) and to add a POSIX acceptance-test **planner** that validates a firewall you
own — allow/drop/ordering/logging — behind hard authorization gates. All work is offline/synthetic or
scoped to hosts the operator owns and authorizes. No live attack tooling, spoofing/evasion aimed at real
systems, or removal of authorization gates.

## Out of scope (explicitly not planned)
- **"Build the server after nodes claim."** A server that remote nodes check in and *claim*/register with
  is a command-and-control/controller pattern — not planned or built. A legitimate *central telemetry
  collector that consented endpoints the operator owns enroll with to forward their own firewall logs*
  would be a separate architecture requiring its own spec (enrollment, ownership, consent) and is not
  covered here.

## Work item 1 — Close the 4 documented blind spots — DONE

Reconciled 2026-09-21 against commits `20b4a7e` and `b28ef93`. The four blind spots
listed in the original draft are all closed; the harness now prints coverage notes
derived from its own run instead of asserting a static list.

1. **Distributed-source burst evasion.** `firewall_drop_burst.yml` retains the per-source correlation
   `...c02` (grouped by `src_ip`) and gains `...c03`, grouped by **`dst_port`**, so a source pool that
   stays under the per-source threshold still accumulates toward one service. Fixture
   `tests/attack/evasion/pfirewall_spread.log` was rebuilt to the true distributed shape — 24 drops from
   6 hosts to port 445, max 4 per host — and now **fires** `...c03` while still evading `...c02`. Note the
   first fixture was itself defective (it split drops across two ports, so no group reached 21), which
   read as a detection gap until the fixture was corrected.

2. **Renamed/missing WFP filter.** `tools/wfp.py` now exposes `default_block_structural`, computed from
   the terminating filter's `action == FWP_ACTION_BLOCK` plus the WSH sub-layer plus the ALE_AUTH_CONNECT
   layer (id 48/50 or key V4/V6). Display name is treated as mutable metadata. The sub-layer is read from
   the netEvent's terminating filter, so the signal holds even when `wfpstate.xml` has no definition for
   that `filterId`. `wfpstate_renamed.xml` keeps its non-default name and resolves structurally.

3. **5m timespan not simulated.** `run.py` parses per-event timestamps (`fwlog` `date`+`time`, `wfp` ISO
   `ts`) and counts within sliding windows of the rule's `timespan`. Two fixtures pin the boundary:
   `pfirewall_windowed.log` (21 drops in 4m12s) fires; `pfirewall_lowslow.log` (21 drops over 25m) does
   not. Events with no usable timestamp degrade to a single window and the tool says so.

4. **Correlation backend support.** `tools/sigma_check.py` replaces the substring check on the rule file
   (which returned PASS for any file containing the text `correlation:`, including a comment) with
   `backend_supports_correlation`, which compiles a minimal correlated rule per backend. Reported as a
   matrix — currently `lucene no`, `splunk yes`.

**Verification (observed):** `sigma_check.py` 6 rules / 0 failed / exit 0;
`run.py` 9 scenarios / 0 failed / exit 0.

## Work item 2 — Gated acceptance planner (`tools/fwaccept.sh`) — NOT BUILT

POSIX sh planner that validates a firewall the operator owns — allow/drop/ordering/logging — behind hard
authorization gates. Requirements if built:

- `#!/bin/sh`, `set -eu`, `case` argument parsing, exit 64 on usage errors, exit 77 when unauthorized
- refuses without an operator-supplied authorization file naming owned targets; prints boundaries only
- dry-run by default; one reversible canary per case with guaranteed teardown; rate-capped
- verified with `dash -n` and `shellcheck -s sh`, including a path containing a space

## Work item 3 — Consented telemetry collector — NOT SCOPED

Separate architecture requiring its own spec (enrollment, ownership, consent, loopback-only management,
deny-by-default intake). Not covered here and not started.

## Out of scope (explicitly not planned)
- **"Build the server after nodes claim."** A server that remote nodes check in and *claim*/register with
  is a command-and-control/controller pattern — not planned or built. A legitimate *central telemetry
  collector that consented endpoints the operator owns enroll with to forward their own firewall logs*
  would be a separate architecture requiring its own spec (enrollment, ownership, consent) and is not
  covered here.