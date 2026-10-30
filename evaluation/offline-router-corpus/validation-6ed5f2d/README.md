# Full validation at 6ed5f2d

All five fixed checks passed at `6ed5f2d24293d414169ff4e7688671b230a35775`: fmt, strict workspace Clippy, check, parallel workspace tests and serial launch. Workspace totals are **3,824 passed, 0 failed, 37 ignored** across 107 unfiltered summaries; serial launch is **1,039 passed, 0 failed** across 27. Three filtered child summaries (3 passes; 105 filtered cases) are excluded. Both rapid-profiler doctest groups are counted.

All **117 exact prior regression names** pass: RapidProbe rejection (2), observing-control (8), short-neighbor (21), prefixed pun (1), quiescent (4), staged-image drop (1), and the complete remaining roster. Six additional launch regressions pass in both commands. The existing public roster and canonical tuple hash bind every name.

The 15 host-identity controls are feature-gated and **not selected by this default-feature workspace run**. Their separate focused run passed all 15 against source bytes committed here; [runtime-mapping-controls.json](../runtime-mapping-controls.json) retains that evidence and the earlier strict-Clippy failure. They are not added to workspace totals.

The owner reserved 16 CPUs and retained 316 test threads; serial launch explicitly uses one. Workspace finished in 895.808793 seconds within its unchanged 900-second limit. Every command and outer owner closed with cleanup complete, zero rescued descendants and source unchanged. The [prior 559a timeout](../validation-559a845/README.md) remains incomplete.

`receipt.json` records commands, environment, load, raw hashes and caps. Reproduce with [validate.py](../../short-neighbor-parallel/validate.py) at the recorded revision/environment and CPU affinity, using a fresh ignored output directory. Raw logs stay ignored. These are debug-correctness results, not native-corpus, E9 or performance qualification.
