# Scalar graph qualification: component passes, application owner fails

Revision `99d4c88e0ce4a731bb735732364f0a357e49e7ba` adds a bounded scalar
graph decoder, planner and generated-code owner. Component execution preserves
native machine state across five paths and identifies six real failing loads.
The application owner does not yet qualify; there is no whole-program or
performance claim. This evidence supports systematic tactic validation (claim 4)
and tests the publication machinery needed for claim 1.

All three runs used one reserved CPU on an AMD EPYC 9D85, x86-64, Linux 7.1.3.
The JSON receipts record hardware summaries, reproduction commands, revision,
original resource bounds, and hashes identifying the closed command and artifact
records. Matching CSV files
retain the individual results. These are qualification runs, not benchmarks.

| Run | Result | Evidence |
| --- | --- | --- |
| Decoder | 8/8 processes; 104 supplied reader refusals | [JSON](20261030T101832.949414Z-region-decoder-99d4c88e0ce4.json) |
| Scalar component | 5 completed paths, 6 required read faults; 535 supplied reader refusals | [JSON](20261030T101912.768928Z-scalar-region-component-99d4c88e0ce4.json) |
| Application owner | Failed: 40 attempts, 13 native references qualified, 0 gated cases or pairs qualified | [JSON](20261030T101950.821705Z-scalar-region-owner-99d4c88e0ce4.json) |

The decoder covers 47 forms, 3,898 accepted rows, 7,796 descriptor calls,
34 literal refusals, 124 prefix truncations and 171 guard checks. The component
compares all GPRs, flags including actual AF, full FP state, signal mask, TLS,
stack and data; generated execution uses no single-step traps. Its separate
planner prerequisite passes 16 positive, 27 refusal and 23 corruption cases.

The owner run exposed three independent problems:

* The reader's expected layout omitted the three embedded `stat` timestamps.
  Actual DWARF contains 47 types and 100 edges; the old inventory listed 97
  edges. The correction adds those exact edges and retains whole-layout equality.
* All 27 gated attempts fill the 64-slot cache during loader startup. Each
  records 64 publications and 225 completed nonfocal entries, but zero focal
  redirects or completions. Lifetime cache exhaustion prevents the application
  graph from entering generated code. Eleven required refusal controls exit
  successfully instead of exercising the intended owner failure.
* The generation-change case exits with failure 155: its `mprotect` request
  intersects an initial code mapping protected by the existing runtime policy.
  That failure requires a supported mapping transition, not an expected-status
  change.

All commands and child processes closed, source identity remained unchanged,
and cleanup completed. Independent reviews authenticated the closed decoder,
component and failed owner evidence. The owner failure remains a failure after
the layout correction; a fresh complete owner run is required.

The most recent whole-program cohort remains the failed generated-loop cohort
described in [the previous report](2026-10-30-generated-loader-loop.md).
Its ordinary `ls` samples took about 10 seconds with about 188,000 traps and
59,000 fresh maps acquisitions. The historical 10-times-DynamoRIO target is
263.060775 ms and remains unmet.
