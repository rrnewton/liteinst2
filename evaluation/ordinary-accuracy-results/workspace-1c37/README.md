# Workspace validation at 1c37

One fresh five-command harness execution at `1c37c74619a924b0aad39890da432dad2a8993c1` completed with unchanged sources, normal exit 0 and complete cleanup. Workspace totals are **4,089 passed, 0 failed, 37 ignored**; serial launch totals are **1,039 passed, 0 failed, 0 ignored**. All **202 required regression names (208 occurrences)** passed, including `rapid::tests::live::install_rejects_each_mutated_window_byte`. The separately checked, expanded `normal::csv::tests::csv_mapping_classes_keep_private_source_and_shared_images_distinct` control also passed.

| Command | Bound (s) | Actual (s) |
| --- | ---: | ---: |
| `cargo fmt --check` | 180 | 9.857393 |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 180 | 11.417142 |
| `cargo check --workspace --all-features --all-targets` | 180 | 7.731684 |
| `cargo test -j 16 --workspace --no-fail-fast` | 900 | 811.342201 |
| `cargo test -p liteinst-launch --tests -- --test-threads=1 --nocapture` | 180 | 129.491334 |

Every command exited 0 with no termination or rescued descendants. The outer owner took 969.917599 seconds under its fixed 1,200-second bound. Each owner retained its 8 MiB log cap and separate three-second cleanup budget. The AMD EPYC Zen 5 dev host used 16 reserved CPUs while the harness retained `RUST_TEST_THREADS=316`; the final command explicitly used one test thread. The receipt records exact CPUs, loads, environment, timings and raw-log hashes. Full-gate custody has the allocator invocation and recorded child affinity, without a separate allocator ledger capture. Configured tool paths were recorded, but this pipeline did not capture contemporaneous compiler versions or binary hashes.

The original 37 ignored outcomes have identical names, reasons and multiplicities. All 110 unfiltered workspace summaries count, including both rapid-profiler doctest groups (2 and 45 passes). Three successful nested controlled-oracle summaries are excluded only from aggregate totals to avoid double counting; the 113 raw summaries retain 4,092 passes, 37 ignored and 105 filtered cases. Serial launch has 27 summaries. Workspace and serial coverage overlap; harnesses without libtest summaries receive no invented counts.

[receipt.json](receipt.json) is the compact projection of authenticated closed owners, logs and the census audit. Raw logs and exhaustive rosters remain private. These are correctness durations, not performance results. No native sampling, hardware/PMU accuracy, phase realization, strict 2 ms or full 43,200-cell matrix qualification follows. Prior failures, including the [earlier full-suite failures](../workspace-78b/README.md) and [focused prepared-profile failures](../prepared-focused-27e/README.md), remain unchanged.

To reproduce, use the existing five-command [reproduction snippet](../workspace-5d1/README.md) with this receipt as `RECEIPT` and a clean checkout of the exact revision as `ROOT`. Set its documented local path variables, Python 3.9 and the offline stable Rust toolchain/cache. The receipt preserves the exact environment; `${RUN}` must be a fresh path under `ignored/`. Only that five-command snippet applies here. It authenticates the existing process owner and validator, reserves 16 CPUs, preserves every bound and runs once without retries. The full-gate source only records the configured stable selector, so a new run must record its own actual tool versions. Inspect all resulting closures and retained logs; preserve any failure, timeout, unknown cleanup or census change.
