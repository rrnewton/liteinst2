# Workspace validation at bc53

One five-command execution validated merge `bc53aebec22a0b9500f238dfd8afe5de3e2fe619`, with unchanged sources and cleanup: **4,089 workspace passes, 0 failures, 37 ignored**; **1,039 serial-launch passes, 0 failures, 0 ignored**. All **202 required names / 208 passing occurrences** retain their exact multiplicities, including `rapid::tests::live::install_rejects_each_mutated_window_byte`. The separate expanded `normal::csv::tests::csv_mapping_classes_keep_private_source_and_shared_images_distinct` control passed.

| Command | Bound (s) | Actual (s) |
| --- | ---: | ---: |
| `cargo fmt --check` | 180 | 11.301651 |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 180 | 0.504630 |
| `cargo check --workspace --all-features --all-targets` | 180 | 0.501960 |
| `cargo test -j 16 --workspace --no-fail-fast` | 900 | 890.878584 |
| `cargo test -p liteinst-launch --tests -- --test-threads=1 --nocapture` | 180 | 131.916748 |

All commands exited 0 with complete cleanup and no rescues. The outer took 1,035.351419 s under its fixed 1,200 s bound; all owners retained 8 MiB output and three-second cleanup budgets. The AMD EPYC Zen 5 dev host used 16 reserved CPUs and `RUST_TEST_THREADS=316`, except explicit serial execution. [receipt.json](receipt.json) retains exact CPUs/loads/environment/timings/hashes. Durations are correctness bookkeeping, not performance. Reservation attribution uses the coordinator's allocator launch and child affinity; no separate ledger capture exists. Tool selectors were recorded, without contemporaneous compiler versions/hashes.

All 110 unfiltered summaries count, including both rapid-profiler doctest groups. Only three controlled-oracle child summaries (one pass/35 filtered each) are excluded from totals; child failures still fail. Raw 113 summaries retain 4,092 passes/37 ignored/105 filtered; serial has 27. Original ignored names/reasons/multiplicities are exact. Workspace/serial overlap; custom harnesses receive no invented counts.

This validates the new merge of `b959c8d` with `34c47f5`, separately from [workspace-1c37](../workspace-1c37/README.md). Earlier [full-suite](../workspace-78b/README.md) and [focused](../prepared-focused-27e/README.md) failures remain. [Native1c37](../native-1c37/README.md) remains aggregate **FAILED**, with its original partial locked observations; it was not rerun at this merge. No native sampling, hardware/PMU accuracy, phase realization, strict 2 ms or full 43,200-cell qualification follows.

Reproduce with only the five-command [workspace-5d1 snippet](../workspace-5d1/README.md), this `RECEIPT`, exact-revision `ROOT`, its local variables, Python 3.9 and offline stable Rust cache/toolchain. Use fresh output/log paths. The receipt authenticates the existing owner/validator and exact environment. Keep all commands/bounds/16 reserved CPUs/316 harness threads; run once and retain failures/timeouts/unknown cleanup/census changes. Record actual new tool versions; native hashes are no substitute. Raw logs/rosters stay private.
