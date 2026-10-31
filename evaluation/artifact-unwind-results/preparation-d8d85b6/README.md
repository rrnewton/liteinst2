# Artifact unwind preparation at d8d

The full gate passed at `d8d85b6f3b3652752470516bee1b4d48469439ec`: **4,113 passed, 0 failed and 37 ignored**, plus **1,039 passed** in the separate serial launch. All five commands closed normally: source unchanged, cleanup complete, zero rescues.

The artifact API retains an authenticated NOP5 trace and prepares relative `.eh_frame` records from certified original CFI and a frame-preserving hook. This is **claim 4: pure preparation**. ELF placement/indexing, original FDE discovery, lifetime and actual unwinder qualification remain owed. Native artifact unwinding, exceptions, LSDA and asynchronous use are unqualified; [A3 remains open](../../../A3-OFFLINE.md).

[receipt.json](receipt.json) preserves all focused attempts, exact commands, overlays, CPUs, load, durations and raw hashes.

| Attempt | Passed / failed / ignored | Exit | Rescues |
| --- | ---: | ---: | ---: |
| Artifact v1 | Compilation failed; no tests | 101 | 0 |
| Artifact v2 | 37 / 0 / 0 | 0 | 0 |
| Library v2 | 416 / 1 / 1 | 101 | 1 |
| Cleanup controls v1 | 12 / 0 / 0 | 0 | 0 |
| Library v3 | 383 / 34 / 1 | 101 | 34 |
| Cleanup controls v2 | 12 / 0 / 0 | 0 | 0 |
| Library v4 | 417 / 0 / 1 | 0 | 0 |

The first failure was a test import. Library v2 failed process-inventory cleanup. The initial prefilter then rejected valid foreign kernel group 0, which source review and mocks missed; the exact failing PID is unknown. After correction, all 34 previously failed names and all 12 artifact controls passed. Earlier failures stay failures; overlapping runs are not additive coverage.

Focused runs used `bf8b9622` plus artifact overlays, then `1058edc5` plus cleanup overlays. Corrected bytes were committed later as `1058edc5` and `d8d85b6`. The full gate executed committed d8d.

Workspace totals cover 111 summaries; three nested `controlled_oracle` summaries (one pass/35 filtered each) are excluded only from totals. All 114 raw summaries remain retained. Earlier terminal identities and 37 ignored outcomes are unchanged, plus 24 passing controls. All 202 earlier required names passed in 208 occurrences, including RapidProbe mutation, staged-drop, observing-control, prefixed-pun and 21 short-neighbor cases. Ordinary had 506 passes and 1 ignored; all 45 SDK controls passed. Both `rapid_profiler` doctest groups are included. Serial has 27 summaries.

Reproduce using the existing [validator](../../short-neighbor-parallel/validate.py) and [workspace-5d1 owner snippet](../../ordinary-accuracy-results/workspace-5d1/README.md), this receipt outside a clean checkout of the exact revision, local path substitutions and fresh output/log paths. Reserve 16 CPUs; retain 316 harness threads, 900 seconds for workspace, 180 seconds for each other command, and the 1,200-second/8 MiB outer owner with 3-second cleanup.

For focused checks at the final revision, use the same owner with four reserved CPUs and its affinity assertion changed to four. Use `outer.environment` and argv `focused.command_prefix` plus one `focused.commands` array. Keep the recorded 180-second timeout, 3-second kill grace and outer bounds. Use fresh `target/evaluation/` logs and authenticate closure before reading. This reproduces current checks, not broken overlays.

Only configured tool paths/environment were captured, without contemporary compiler hashes/versions or a separate allocator ledger. The linked snippet's historical versions do not apply. Durations/load are correctness observations, not performance evidence; raw logs stay ignored.

Worker report: both planned A5 coordinate cells and all seven owners remain UNRUN with zero attempts while capacity cleanup is pending. Prior native and strict 2 ms failures remain unchanged. No PMU, phase, performance or full-matrix qualification follows.
