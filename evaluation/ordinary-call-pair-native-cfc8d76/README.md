# Original-address nested call qualification: timeout retained

Exact source: `cfc8d7679053ffd71e95bb7b02317a0531a8cd04`, which includes
main `469fa27fa400e7d0617d3c04706f88af72cf8834`.
Hardware: AMD EPYC Zen 5 dev host. Rust 1.97.1. Claim 4 validation only;
no performance, deadline, whole-worker-state or full-A5 claim.

The single fixed release cohort **FAILED** its unchanged 510-second wall bound
(510.059 s). All 36 prerequisites passed: 356 controls plus one existing ignore.
The native process emitted 180 of 192 ordered pair rows before timeout. Those
rows contain 16,515 observed comparisons, 720 target CALL/RETs, 360 outer RETs
and 360 normal reaps; all remain **OBSERVED_UNQUALIFIED**. Candidate steps range
from 16,837 to 18,412. Twelve slots have no accepted result, including interrupted
work. Two children required rescue reaping. Empty native stderr is not a proof
that interrupted work passed. No replacement run occurred.

The source correction distinguishes retained group policy from effective entry
control after removal: history retains `enabled=true`, while a later real root
and child each receive Removed receipts and add no sampled completion. The
exact Published/Removed action checks remain. Independent source review and
actual-receipt controls cover StableA, RearmB and RemovedChild. The earlier
`fb37514` failed postflight remains recorded separately.

The native owner reserved CPUs 34/53/170, with tracer and tracees on 53. Load
was 65.33/59.88/57.48 before the owner and 41.04/40.29/48.71 afterward; during
the native stage it was 47.14/56.10/56.67 to 39.39/39.95/48.65. Root closure
completed normally with no rescue reaps. After closure, all 322 retained files
(58,959,264 bytes) and 1,171 source pins were authenticated. Raw captures/logs
remain ignored. `pairs.csv` preserves all 192 slots; `stages.csv` preserves all
37 stage outcomes. The receipt records exact commands, profile, limits,
reservation, tools, geometry and hashes.

The separate seven-check run **FAILED** the original 360-second workspace
bound (360.145 s, eight rescue reaps). Its completed terminal observations
reported 1,982 passes, zero assertion failures and one ignore; these are a
prefix, may include nested child summaries, and do not establish suite success.
Fmt, strict workspace/all-target/all-feature Clippy and check passed. Only the
three initially UNRUN commands ran once afterward: serial launch 1,039 passes,
staged allocation three, prefixed pun 36; each closed normally without rescue.
Both phases had hard eight-CPU reservations. The first phase did not record
load, shown as null; the second did. No 316-thread or whole-seven-pass claim.
`checks.csv` and the receipt retain both phases without replacing the failure.

Reproduce the native recipe at the exact source revision with the request argv
and environment in `receipt.json`, replacing `$REPO`, `$AGENT_UTILS`,
`$TOOLCHAIN`, `$PYTHON`, `$USER_HOME`, `$CARGO_HOME` and `$RUNTIME_DIR` with local
locations. The tracked entry point is
`evaluation/ordinary-call-pair-native/reproduce.py`; use a fresh raw directory,
a hard three-CPU cpuset reservation and the recorded external ownership bounds.
Release optimization is 3, with assertions/overflow checks enabled and four
compiler jobs. Keep the 20,000-step, 15-second pair and 480-CPU/510-wall limits.

The original checks use `evaluation/admission/check_exec_identity.py
--checks-only` with the exact toolchain/cargo-home/output arguments in the
receipt. `reproduce_tail.py` materializes the byte-identical reviewed isolated
three-check script from that pinned shared source; invoke its printed path with
`--checks-only` under a hard eight-CPU reservation and a fresh output directory.
The generator was verified by static reconstruction, not executed in this run.
It cannot turn the workspace timeout into whole-suite acceptance.
