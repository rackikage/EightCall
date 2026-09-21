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

## Work item 1 — Close the 4 documented blind spots
Blind spots are listed at the bottom of `tests/attack/run.py::main`.

1. **Distributed-source burst evasion.** `rules/windows/firewall_drop_burst.yml` (rule `...c02`) correlates
   the single-drop rule `...c01` grouped by `src_ip`, `gte: 21`, `timespan: 5m`. A distributed source pool
   (each source < 21) evades it — this is what `tests/attack/evasion/pfirewall_spread.log` demonstrates.
   Fix: add a complementary correlation rule that groups by **`dst_port`** (many drops toward SMB/RDP
   regardless of source spread). After adding it, add a run.py scenario where `pfirewall_spread.log`
   **fires** the new rule (currently it is expected to "evade" the src_ip rule — that stays true; the new
   rule is what catches it).

2. **Renamed/missing WFP filter.** `tools/wfp.py::record` derives `default_block` by string-matching
   `filter_name == "Block Outbound Default Rule"`; a renamed filter (see
   `tests/attack/evasion/wfpstate_renamed.xml`) evades. Fix: add a **name-independent** indicator computed
   from structural signal — a terminating filter with `action == FWP_ACTION_BLOCK` + the outbound default
   layer/sublayer + `capability_count == 0` — exposed as e.g. `default_block_structural`. Update
   `wfp_default_block_no_capability.yml` / `wfp_default_block_with_capability.yml` to match the structural
   field. After the fix, the renamed-filter scenario flips from evade → fire. (Exact XML fields to be
   confirmed against the fixtures during implementation.)

3. **5m timespan not simulated.** `run.py::rule_hits` treats every batch as one window. Fix: make the
   correlation timespan real — parse a per-event timestamp (fwlog has `date`/`time`; wfp has
   `header/timeStamp`), bucket into the rule's `timespan`, and count per window. Then add a **low-and-slow**
   scenario: 21 drops spread over >5m must NOT fire; 21 within 5m must fire.

4. **Correlation backend support.** `tools/sigma_check.py` lumps correlation-unsupported backends into a
   generic "unsupported" note. Fix: detect and report correlation support explicitly (which