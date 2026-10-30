All five correctness checks passed on `a72c96408d51b366ad2b1433821f534a593b4d26`: formatting, strict workspace Clippy, all-feature/all-target checking, parallel workspace tests, and serial launch tests. Source remained unchanged; every command and the outer owner closed with exit 0, complete cleanup and zero rescued descendants.

The workspace completed in 865.850 seconds within its unchanged 900-second bound: **3,794 passed, 0 failed, 37 ignored**, across 107 unfiltered summaries. Three filtered nested-child summaries (3 passed, 105 filtered) are retained separately and excluded from that total. Serial launch tests passed **1,039/1,039**. The harness used 316 test threads on 16 reserved CPUs.

All **117** previously required regression names have exact pass lines. Their original source-derived roster and group counts are unchanged. Of 21 newly authored explicit Rust tests since `559a845`, nine absolute-startup carrier/catalog tests passed here. Seven standalone-verifier tests and five feature-gated producer tests are outside this workspace invocation; this receipt claims no result for those twelve.

`receipt.json` records commands, revision, toolchain, CPU reservation, load averages, bounds and raw-log hashes. Run `evaluation/short-neighbor-parallel/validate.py` from the pinned clean checkout with the recorded debug profile and reserved affinity; `$OUTPUT` denotes a fresh output directory. Keep raw logs private. Elapsed times are correctness-command accounting, not performance or full-program native qualification.

The earlier `evaluation/offline-router-corpus/validation-559a845` result remains **workspace incomplete: timeout**, with 112/117 required pass lines. This later result does not relabel that attempt or replace its evidence.
