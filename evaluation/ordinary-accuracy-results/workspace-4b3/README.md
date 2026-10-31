# Merged workspace validation at 4b3

The fixed five-command correctness suite passed once at `4b37934180971dfd437aaef59d2275836c5fec7e` (tree `e44320c593ea8110e3b2be6197ffa85f1b269ad4`). Its direct parents are prepared-source commit `27e57a250104f0b0e55e9ac441e0b96217ec010d` and main `acc2474c696b8c745c0bb819e04aa2282c6cc0c5`. All 85 declared audit source pins and the root workspace Cargo inputs are unchanged. This is not whole-tree equality: the separate page-entry decoder workspace changed on main.

Every command and the outer owner closed normally at exit 0, with complete cleanup and zero rescued descendants. The owner recorded unchanged source and an empty working overlay. One allocator reservation held 16 CPUs while the parallel workspace retained 316 test threads.

| Command | Actual seconds | Unchanged wall bound (s) |
| --- | ---: | ---: |
| `cargo fmt --check` | 15.613349 | 180 |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0.255134 | 180 |
| `cargo check --workspace --all-features --all-targets` | 0.212486 | 180 |
| `cargo test -j 16 --workspace --no-fail-fast` | 869.925013 | 900 |
| `cargo test -p liteinst-launch --tests -- --test-threads=1 --nocapture` | 147.395099 | 180 |

Workspace: **4,089 passed, zero failed, 37 ignored**, across 110 unfiltered summary occurrences. All **202 required identities passed**: the prior 139, all 18 prepared-phase controls and the 45 SDK pure controls. The ordinary-interval target contributed 506 passes and one ignored outcome. Separate serial launch passed **1,039** tests over 27 summaries; it overlaps workspace coverage and is not added as unique coverage.

The raw workspace has 113 summaries: 4,092 passes, zero failures, 37 ignored and 105 filtered. Only the same three `controlled_oracle` child summaries, each one pass and 35 filtered tests, are excluded from aggregate totals. Their exact parent context, order and outcomes remain checked. Both profiler doctest groups stay included. Custom harnesses without libtest summaries receive no invented counts. Original ignored names, reasons and multiplicities are unchanged; no new ignore or exemption was admitted.

The outer owner took 1,033.728301 seconds under its original 1,200-second limit. Each command and outer log retained its 8 MiB cap and separate three-second cleanup budget. The host was an AMD EPYC Zen 5 development machine. Dev/test optimization and debug information remained zero, with assertions and overflow checks enabled. Host load averages were 120.40/88.78/76.22 at outer start and 285.10/346.32/263.84 at closure; workspace closure recorded 390.43/369.92/254.66. These loads and elapsed times are observations, not performance or causal-speedup evidence.

[receipt.json](receipt.json) records the exact command arrays, closures, CPU IDs, loads, fixed settings, path-normalized environment, raw log hashes, source pins and root-executed closed-data audit. Raw logs and individual audit rows remain private. The generic owner recorded stable-toolchain paths, not fresh compiler/interpreter binary hashes or version captures.

Reproduce with the existing `evaluation/short-neighbor-parallel/validate.py` and `evaluation/admission/processes.py`. The owner snippet in [workspace-5d1](../workspace-5d1/README.md) consumes this receipt's `outer.command`, `outer.environment` and `source.reproduction_sources`. Use a clean checkout of the exact revision, keep this later receipt outside it, and substitute local `ROOT`, `USER_HOME`, `TOOLCHAIN`, `CARGO_HOME`, `RUN_TMP`, `RUN`, `OWNER_LOG` and `RECEIPT`. `TOOLCHAIN` contains `bin/cargo`; use the offline stable toolchain/cache and Python 3.9. `RUN` is a fresh relative path below `ignored/`, and `OWNER_LOG` a fresh absolute path below `${ROOT}/target/evaluation/`. Reserve 16 CPUs through the allocator; affinity alone is not a reservation. Keep all original bounds and retain every failure or unresolved outcome.

The [pre-merge 27e workspace run](../workspace-27e/README.md) remains a separate execution. Prepared-profile native evidence also retains its executed 27e attribution; this merged debug suite does not rerun or requalify that release profile. The failed bf4 run remains [failed history](../workspace-78b/README.md), including its formatting failure, 900-second timeout and nine rescued descendants. No earlier failure or unrun outcome is promoted. This receipt grants no new release-native, PMU accuracy, realized phase, cadence, strict 2 ms runtime, performance, MSRV or full A5-matrix qualification.
