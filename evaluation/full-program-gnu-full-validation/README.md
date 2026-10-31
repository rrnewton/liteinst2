# Empty-GNU-hash repair: full workspace validation

At `cbb585d9e2f250f5365b34aa654e14bf5e87aa48`, all five required checks passed: formatting, strict workspace Clippy, all-target/all-feature check, the parallel workspace and serial launch tests. Workspace: **4,264 passed / 0 failed / 39 ignored**. Serial launch: **1,039 / 0 / 0**.

The complete prior test/context/status/ignore multiset is retained. Exactly four new empty-GNU-hash tests pass. The same three controlled child summaries are excluded from the raw count of4,267; their parent tests remain counted. Historical Rapid, trampoline, prefixed-pun, short-neighbor and exec-source regression identities are preserved. No assertions, comparators or wall limits changed.

[receipt.json](receipt.json) records exact commands, revision, CPUs, environment, limits, elapsed times and log hashes. Twelve reserved CPUs, Cargo12/harness12; serial harness1. All owners closed normally with zero rescues and unchanged source. The owner PID and exact child scope were absent after closure. This is correctness evidence, not a performance or full-program execution qualification. Earlier failures remain in their original receipts.

To reproduce, retain this receipt outside the checkout and check out its exact `revision`. Use the [existing bounded owner recipe](../whole-owned-full-validation/README.md) with `RECEIPT` pointing to this receipt, the selected stable toolchain/Cargo bin directories, twelve disjoint reserved CPUs and a fresh output name. Its `environment` and `reproduction` fields carry the complete unchanged recipe, including1200-second outer /8MiB log bounds and180/180/180/900/180-second command limits. Use one nonincremental target with dev/test debug symbols disabled.
