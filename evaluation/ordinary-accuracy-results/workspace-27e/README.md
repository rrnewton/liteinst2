# Workspace validation at 27e

The fixed five-command correctness suite passed once at `27e57a250104f0b0e55e9ac441e0b96217ec010d` (tree `14064e384ef7c104601b41676cf28840bd408923`). Every command and the outer owner closed normally at exit 0, with complete cleanup and zero rescued descendants. The owner recorded unchanged source and an empty working overlay. One allocator reservation held 16 CPUs while the parallel workspace retained 316 test threads.

| Command | Actual seconds | Unchanged wall bound (s) |
| --- | ---: | ---: |
| `cargo fmt --check` | 9.944229 | 180 |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 12.011114 | 180 |
| `cargo check --workspace --all-features --all-targets` | 7.817906 | 180 |
| `cargo test -j 16 --workspace --no-fail-fast` | 829.342887 | 900 |
| `cargo test -p liteinst-launch --tests -- --test-threads=1 --nocapture` | 129.797805 | 180 |

Workspace: **4,089 passed, zero failed, 37 ignored**, across 110 unfiltered summary occurrences. All **202 required identities passed**: the prior 139, all 18 prepared-phase controls, and the 45 SDK pure controls. The ordinary-interval target contributed 506 passes and one ignored outcome. The separate serial launch passed **1,039** tests over 27 summaries; it overlaps workspace coverage and is not added as unique coverage.

The raw workspace has 113 summaries: 4,092 passes, zero failures, 37 ignored and 105 filtered. Only the same three `controlled_oracle` child summaries, each one pass and 35 filtered tests, are excluded from aggregate totals. Their exact parent context, order and outcomes remain checked. Both profiler doctest groups remain included. Custom harnesses without libtest summaries receive no invented counts. The original ignored names, reasons and multiplicities are unchanged; no new ignore or exemption was admitted.

The outer owner took 989.822212 seconds under its original 1,200-second limit. Each command and outer log retained its 8 MiB cap and separate three-second cleanup budget. The host was an AMD EPYC Zen 5 development machine. Dev/test optimization and debug information remained zero, with assertions and overflow checks enabled. These elapsed times are correctness-command observations, not performance or causal-speedup evidence.

[receipt.json](receipt.json) records all five exact command arrays, closures, CPU IDs, loads, fixed settings, path-normalized environment, raw log hashes, source pins and the root-executed closed-data audit. The 85 declared source files match the exact Git revision. Raw logs and individual audit rows remain private. The generic owner recorded stable-toolchain paths, not fresh compiler/interpreter binary hashes or version captures.

Reproduce with the existing `evaluation/short-neighbor-parallel/validate.py` and `evaluation/admission/processes.py`. The owner snippet in [workspace-5d1](../workspace-5d1/README.md) consumes this receipt's `outer.command`, `outer.environment` and `source.reproduction_sources`. Use a clean checkout of the exact revision, keep this later receipt outside it, and substitute local `ROOT`, `USER_HOME`, `TOOLCHAIN`, `CARGO_HOME`, `RUN_TMP`, `RUN`, `OWNER_LOG` and `RECEIPT`. `TOOLCHAIN` contains `bin/cargo`; use the offline stable toolchain/cache and Python 3.9. `RUN` is a fresh relative path below `ignored/`, and `OWNER_LOG` a fresh absolute path below `${ROOT}/target/evaluation/`. Reserve 16 CPUs through the allocator; affinity alone is not a reservation. Keep the original bounds and retain every failure or unresolved outcome.

The failed bf4 workspace run remains [failed history](../workspace-78b/README.md), including its formatting failure, 900-second timeout and nine rescued descendants. Earlier successes and focused/native/phase results retain their own revisions. This receipt grants no new release-native, PMU accuracy, realized phase, cadence, strict 2 ms runtime, performance, MSRV or full A5-matrix qualification. The separate prepared-profile native campaign is outside its scope.
