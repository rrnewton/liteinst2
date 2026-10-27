# Common-corpus carrier and loader fixes

Revision `cbb189d1d17f947c97194842129b66eb68b0531f` passed all four required workspace gates: **1,685 tests passed, zero failed, four unchanged ignores**. The 90 outer test groups retain all 1,675 prior identities and add eight COPY and six GNU-property tests. Five nested child summaries are counted separately.

The carrier now inventories a restricted ET_EXEC/DT_RELA COPY destination from complete symbol/version metadata and preserves known non-CET GNU ISA notes. The E9 reader selects the exact restore suffix for each authenticated producer lane. Unknown COPY profiles, malformed ownership, CET properties and incorrect loader bytes remain refused.

| Gate | Result | Command time (seconds) |
|---|---|---:|
| Formatting | PASS | 3.470 |
| Workspace Clippy, all targets/features | PASS | 17.860 |
| Workspace tests | PASS | 324.554 |
| Workspace check, all targets/features | PASS | 1.017 |

The complete twelve-stage build/inventory recipe took 352.293 seconds and produced eight complete 87-head inventories. These are operational durations, not performance benchmarks. Hardware: **AMD EPYC Zen 5 dev host**, with the exact saved model/kernel in the results.

[Validation counts](results/e9-common-fixes-cbb189d/validation.json) bind the independent full-log accounting. The [build cohort](results/e9-common-builds-cbb189d/summary.json) includes normalized complete [commands and environments](results/e9-common-builds-cbb189d/commands.json), CSV gate/stage/inventory results and artifact identities. Run [required-gates.py](required-gates.py) at the tested revision to reproduce workspace validation; [build_inventory.py](e9-common-app/build_inventory.py) and [the build collector contract](e9-common-app/COLLECT-BUILD.md) cover the full inventory recipe and reporting.

The separate [b0 build, original-observation and failed-production report](e9-common-app-b0d94f0.md) retains the earlier evidence. Both build cohorts repeat the same two historical attempts for provenance; their counts must not be added together. Reporting revisions remain separate from tested revisions. Raw logs, captures, binaries and private path inverses stay ignored.

Fresh production and rewritten-program architectural comparisons are still required. This report establishes workspace and static-inventory validation; it does not claim loader execution, rewritten application equivalence, performance or completion of A3.
