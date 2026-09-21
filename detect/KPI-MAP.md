# KPI-MAP.md — what counts as a measurement

**The rule, same as the gates: a KPI reported without its proving command is a
claim, not a measurement.** Every row below names the command that produces it
and exits nonzero on failure. A row whose command does not exist yet is marked
`UNBUILT` and is an *unproven row*, not a passing one.

## Why effort-duration is not on this page

"N days of scripting" measures input, not outcome, and it has no failing state —
which is what disqualifies it as a KPI. Everything here has a nonzero exit on
failure. See [Anti-KPIs](#explicit-anti-kpis--do-not-track-these).

---

## Detection quality (governs Phase 3–4)

| KPI | Definition | Proving command | Target | Gate |
|---|---|---|---|---|
| Silent-miss rate | rules that failed to fire on a known attack fixture ÷ rules exercised | `run_matrix.py` exit code | 0 | UNBUILT |
| FP rate | benign fixtures that fired ÷ benign fixtures | `run_matrix.py` exit code | 0 | UNBUILT |
| NOT_APPLICABLE coverage | rule×layout_id pairs that assert ÷ pairs exercised | `run_matrix.py` (full run) | 100% — silent = fail | UNBUILT |
| Fixture pair completeness | rules with both an attack and a benign fixture ÷ total rules | coverage script | 100% | UNBUILT |
| Cross-arch equivalence | identical verdicts across LE/BE ÷ pairs exercised | pair-equivalence gate | 100% | UNBUILT |
| CPU budget | measured cost at target rate | budget gate | < 5% of one core @ 10k evt/s | UNBUILT |

A silent rule is a failing rule. `NOT_APPLICABLE` must be *asserted* per
rule×layout pair — a pair that produces no verdict is a miss, not a pass, and
that is the whole reason the column exists.

## Enforcement integrity (governs Phase 0 + 2)

| KPI | Definition | Target | Gate |
|---|---|---|---|
| Gate integrity | gates that are a command with nonzero-on-fail ÷ gates claimed | 100% | partial (see [Gate status](#gate-status)) |
| Default-deny coverage | enforcement points with default-deny ÷ enforcement points | 100% | per-point, below |
| Refusing-state availability | enforcement points that can refuse unattended ÷ total | all | UNBUILT |
| Inventory truth ratio | privileged listeners captured ÷ privileged listeners present | 1.0 | UNBUILT |
| Unexplained listeners | listeners with no allowlisted row + reviewed justification | 0 | UNBUILT |
| All-interfaces / link-local binds | unscoped binds remaining | 0 | UNBUILT |
| Lockout-drill pass rate | drills recovered without console access ÷ drills run | 100% | UNBUILT |
| Time-to-detect new listener | bind → appears as a finding | < poll interval | UNBUILT |

### Enforcement points — the denominator, enumerated

So the ratios above are over a real, closed set:

| # | Point | Mechanism | Default-deny today |
|---|---|---|---|
| 1 | sockets | `pf` | no |
| 2 | capabilities | `toolbox_registry.json` (+ boot lint, `effects: [contacts_host]` → signed allow) | yes — fails closed when `DETECT_AUTHZ_KEY_TOOLBOX` is unset |
| 3 | permissions | Claude Code settings | no |
| 4 | rules | rule-load lint (`validate_rules.py`) | yes |

Claude Code was at **0/3 on refusing-state availability in Phase 0**. That is why
Phase 0 is first: an enforcement point that cannot refuse while unattended is not
an enforcement point, it is a prompt.

Known open exposure feeding rows 5–6 (from `CLAUDE.md` open thread 7): kind/py-box
nginx on `*:80` and limactl DNS on `*:53`, both all-interfaces. Until the
inventory gate exists, these are counted by hand and therefore unproven.

## Coverage (governs Phase 5)

| KPI | Definition | Proving command | Target | Gate |
|---|---|---|---|---|
| Matrix completeness | techniques mapped to (field rule, byte rule, fixture, gate) ÷ techniques claimed | coverage script | 100% | UNBUILT |
| Unproven rows | rows whose gate has not been run | this file's Gate column | 0 | manual until the matrix exists |
| Lint rejection rate | deliberately-bad rules rejected ÷ submitted | rule-load lint over a bad-rule corpus | 100% | UNBUILT (corpus missing) |
| Baseline | the four commands below all PASS | see [Gate status](#gate-status) | all PASS | BUILT |

## Explicit anti-KPIs — do not track these

- **Rule count** — rises monotonically with no coverage, and rewards the
  silent-miss failure mode directly.
- **Alert volume** — rewards false positives.
- **"% covered" without a fixture** — unfalsifiable, and unfalsifiable metrics
  are the entire problem this page exists to fix.
- **Days spent / lines scripted** — measures effort, cannot fail.

A metric belongs here if you cannot describe the observation that would make it
go down.

---

## Phase map

| Phase | KPIs it governs |
|---|---|
| 0 | refusing-state availability |
| 1 | inventory truth ratio · unexplained listeners |
| 2 | lockout drills · all-interfaces binds · time-to-detect new listener |
| 3 | fixture pair completeness · cross-arch equivalence |
| 4 | CPU budget · silent-miss rate |
| 5 | matrix completeness · anti-KPI scrub |

## Gate status

Built and runnable today (`cd detect`):

```bash
../bin/python3 validate_rules.py     # rule-load lint + fixture evaluation
../bin/python3 check_coverage.py     # shell_api_map signature ↔ rule selection coverage
ruff check .
../bin/python3 -m pytest -q          # 147 collected
cd toolbox-rs && cargo test          # 17 passed — token/lint/argv safety
```

`check_coverage.py` is the shape the rest should copy: it prints a per-signature
`OK`/`MISMATCH` line, derives the expected set from the rule rather than a frozen
literal, and returns 1 on any failure.

Not yet built — every KPI above marked `UNBUILT` depends on one of these:

| Missing gate | Feeds |
|---|---|
| `run_matrix.py` | silent-miss rate, FP rate, NOT_APPLICABLE coverage |
| fixture-pair coverage script | fixture pair completeness, matrix completeness |
| pair-equivalence gate (LE/BE) | cross-arch equivalence |
| budget gate | CPU budget |
| listener inventory + poll | inventory truth ratio, unexplained listeners, unscoped binds, time-to-detect |
| bad-rule corpus | lint rejection rate |

Current rule set is 9 files under `rules/`. Fixtures on disk: `live_capture.log`,
`icmp_exfil_attack.pcap` / `icmp_benign.pcap`, `c2_beacon_attack.flowlog` /
`c2_beacon_benign.flowlog`, `nodebox_telemetry.jsonl`. Fixture pair completeness
is therefore **not 100% today**, but the number is not reported here because no
command produces it — reporting it by eye would be exactly the failure mode this
page forbids.

## Reporting cadence

One row per KPI per week: **value, command, exit code**. Three columns, no prose.
A week where a gate did not run reports `UNBUILT`/`NOT RUN` for that row rather
than carrying the previous value forward.
