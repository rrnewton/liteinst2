# Workspace validation at 78b

The five fixed correctness commands passed at `78bdf7137e4dfd017553b8af0028108910fba2df` (tree `5def75730fbd8c119b62afc7aa16e4057beb63db`). Every command closed at exit 0 with no termination or rescued descendants, complete cleanup, and unchanged source. One 16-CPU reservation covered the run; the parallel test setting remained 316 threads.

| Command | Seconds | Unchanged wall bound (s) |
| --- | ---: | ---: |
| `cargo fmt --check` | 10.442249 | 180 |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 31.337306 | 180 |
| `cargo check --workspace --all-features --all-targets` | 32.524189 | 180 |
| `cargo test -j 16 --workspace --no-fail-fast` | 845.900261 | 900 |
| `cargo test -p liteinst-launch --tests -- --test-threads=1 --nocapture` | 130.963162 | 180 |

Workspace: **4,062 passed, zero failed, 37 ignored**, across 110 unfiltered summary occurrences. All 130 required names passed (136 passing occurrences); ignored names, reasons and multiplicities are unchanged. Raw 113-summary totals contain 4,065 passes and 105 filtered. Only three authenticated `controlled_oracle` child summaries, each one pass/35 filtered, are excluded from aggregate totals; their raw outcomes remain checked. Both profiler doctest groups (2 and 45 passes) remain included. Custom harnesses receive no invented counts. Serial launch passed **1,039** tests across 27 summaries; it overlaps workspace coverage and is not added as unique coverage.

The preceding `bf4c7f7cb71fb1af57c306d73d9ce5af6d8ca0b6` run remains **FAILED**: formatting exited 1 and workspace timed out after 900.219 seconds, with nine rescued descendants and complete cleanup. Its partial 95 completed summaries contain 2,683 passes, zero failures and four ignored; 35 further terminal successes in the unfinished whole-ADC target remain separate. Four native terminals and all eight required Exact37 completions were absent; only four of 37 expected ignored outcomes were observed. No never-started count is inferred. Its serial run passed 1,039 tests. The frozen auditor's nonexistent `log_archived` field refusal also remains retained; a separate failure-only census authenticated actual archived bytes without turning that failure into a pass.

The intervening three-file repair replaced the legacy endpoint/family global mutex with the existing per-fixture neighbor arena, releasing only the same two 8,192-byte planner windows. Seeds, heads, comparison populations, geometry, ownership and retirement predicates stayed intact. Exact37 HEADS whitespace and an arena comment were corrected. This new complete run satisfies the same gates; elapsed times establish neither performance nor a causal speedup.

[receipt.json](receipt.json) records exact commands/environment, hardware, reserved CPUs, loads, closures, source and raw hashes, the complete prior failure history, and the independently audited census. The outer bound stayed 1,200 seconds, each output cap 8 MiB, and separate cleanup budget three seconds. Dev/test optimization and debug information stayed zero, with assertions and overflow checks enabled. Only serial launch explicitly selected one test thread.

Reproduce through public `evaluation/short-neighbor-parallel/validate.py` and `evaluation/admission/processes.py`. The owner snippet in [workspace-5d1](../workspace-5d1/README.md) consumes this receipt's `outer.command`, `outer.environment` and `source.reproduction_sources`: keep the receipt outside the checkout, substitute local `ROOT`, `USER_HOME`, `TOOLCHAIN`, `CARGO_HOME`, `RUN_TMP`, `RUN`, `OWNER_LOG`, and use fresh paths and a real reservation. The generic owner records stable-toolchain commands, not compiler/interpreter binary hashes or a fresh version capture; absent custody is not invented.

The [128-pair native campaign](../native-062/README.md) remains executed at 062f. These debug checks grant no new release-native execution at 78b, PMU accuracy, cadence, strict 2 ms, performance, complete A5 matrix or MSRV qualification. Earlier failures and prerequisite limitations remain unchanged. Raw logs remain private.
