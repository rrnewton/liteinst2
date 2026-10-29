# Nested-call native validation and session prerequisite failure

Source: `38934ddcabe0be94820b1a25bdf5574c0c8323df`, including main
`469fa27fa400e7d0617d3c04706f88af72cf8834`. Hardware: AMD EPYC Zen 5 dev host;
Rust 1.97.1. Claim 4 only. A5 remains open. These are functional validation
results, not application throughput or deadline qualification.

The change borrows immutable expected-state records and unrolls the journal's
zero-tail loop. It preserves all 512 ordered volatile reads, both transfer
validations, the full journal copy/reset and all existing runtime tests.

The single native attempt **passed** all 192 pairs in 12 coverage groups:
18,756 state comparisons, zero mismatches, 768 target CALLs and RETs, 384 outer
RETs and 384 normal reaps. All 37 stages closed normally without rescue; the
36 preceding stages passed 356 controls with one existing ignore. The native
cohort took 474.653 s within the unchanged 510 s wall limit. Candidate steps
ranged from 14,570 to 16,146. All pair rows are retained in `pairs.csv`.

CPUs 102/130/274 were hard-reserved, with native tracer and tracees on 130.
Owner load was 52.69/41.88/39.60 before and 32.73/30.54/34.30 after; native-stage
load was 30.55/38.13/38.69 to 32.70/30.50/34.31. The root audit rechecked 324
retained files and 1,171 source pins. Raw logs remain ignored.

The subsequent fixed-five session campaign **FAILED before subjects**.
All 35 setup stages passed (228 Rust/Python controls plus ten C controls),
then the native prerequisite reader raised `KeyError`. The separate native
result above remains valid, but the session recipe did not accept it.
All five qualifications are **UNRUN**: zero of 320 installed cases, 32 reference
cases and eight malformed-input cases ran. All 762 raw outcome records were
audited; `qualifications.csv` records every qualification and `session.json`
records the complete counts and hashes. There was no replacement attempt.

The campaign reserved controller CPU 3, worker CPU 8 and producer CPU 75.
Its owner closed normally with exit 1, no timeout and no rescue, in 61.823 s.
`session.json` records both owner and recipe load averages. The 2 ms arm,
10 ms period and 2 s shutdown gates remain unchanged; this failed prerequisite
attempt supplies no evidence about meeting them. The source contract mismatch
must be fixed before a new revision can qualify.

The workspace check **FAILED** its original 360 s limit (360.060 s, one rescue
reap). Completed terminal observations contained 2,146 passes, zero assertion
failures and one ignore; these are a prefix and can include nested summaries.
Formatting, strict Clippy and check passed. The three checks left UNRUN by the
fail-stop runner then ran once: serial launch 1,039 passes in 131.333 s, staged
allocation three passes, prefixed pun 36 passes. Both phases reserved eight
CPUs. Their success does not replace the workspace timeout. No full-suite or
316-thread pass is claimed.

Development records include eight invocations: seven passed, one formatting
check failed and was corrected before its successor. The runtime tests passed
18 cases. Exact commands and base-plus-changed-source hashes are in
`development.json` and every outcome is in `development.csv`. The seven
workspace checks have separate receipts and commands in `receipt.json` and
`checks.csv`. Earlier failed revisions remain recorded in their own directories.

Reproduce at the exact source using the tracked
[native protocol](../ordinary-call-pair-native/ROOT_PROTOCOL.md), then the
[session protocol](../ordinary-call-pair-session/ROOT_PROTOCOL.md). Both provide
`freeze.py` and `launch.py`; record explicit local tool/home paths in ignored
protocols. Use allocator revision `d0c2867be75b495eb64239e664c6306af9747783`,
release optimization 3, enabled assertions/overflow checks and four compiler
jobs. Keep all original native and campaign bounds and fresh attempt
destinations. `receipt.json` and `session.json` hold exact command vectors,
protocol/receipt/tool hashes, CPU roles and load; `$REPO`, `$TOOLCHAIN`,
`$AGENT_UTILS`, `$PYTHON`, `$USER_HOME`, `$CARGO_HOME` and `$RUNTIME_DIR` represent
local paths, not literal arguments.

Workspace reproduction uses `evaluation/admission/check_exec_identity.py
--checks-only` with the recorded arguments. The
[tail generator](../ordinary-call-pair-native-cfc8d76/reproduce_tail.py)
reconstructs the three checks that were not started after the timeout. Do not
repeat the full suite or replace failed outcomes with the tail's successes.
