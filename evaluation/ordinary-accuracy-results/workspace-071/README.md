# Workspace validation at 071783b9

The five fixed debug correctness commands passed at `071783b9a3c27ae26c439c7c5b7ac599cfeb7245` (tree `4f14e4d780ef73d9dbabe8d85e570a39649ba3fa`). Every command was attempted once and closed at exit 0 with no termination, complete cleanup, zero rescued descendants and unchanged source. One 16-CPU reservation covered the run; the parallel test setting remained 316 threads.

| Command | Seconds | Unchanged wall bound (s) |
| --- | ---: | ---: |
| `cargo fmt --check` | 12.924333 | 180 |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 17.320906 | 180 |
| `cargo check --workspace --all-features --all-targets` | 9.757937 | 180 |
| `cargo test -j 16 --workspace --no-fail-fast` | 832.649374 | 900 |
| `cargo test -p liteinst-launch --tests -- --test-threads=1 --nocapture` | 129.645965 | 180 |

Workspace: **4,071 passed, zero failed, 37 ignored**, across 110 unfiltered summary occurrences. All 139 required identities passed (145 passing occurrences), including the nine additive Rust phase controls. The 36 ignored names/37 outcomes retain the exact prior reasons and multiplicities. Raw totals over 113 summaries contain 4,074 passes and 105 filtered. Only the three authenticated `controlled_oracle` child summaries, each one pass/35 filtered, are excluded from aggregate totals; any child failure still fails validation. Both profiler doctest groups (2 and 45 passes) remain included. Ordinary-interval is 488 passed/one ignored. Custom harnesses receive no invented counts.

Separate serial Launch passed **1,039** tests with zero failed or ignored, across 27 summaries. It overlaps workspace coverage and is not added as unique coverage. The unchanged approved auditor ran once, authenticated all receipts/logs and 66 exact source pins at this revision, and returned no findings.

[receipt.json](receipt.json) records the exact commands/environment, hardware, reserved CPU IDs, loads, closures, source and raw hashes. The machine was an AMD EPYC Zen 5 dev host. The outer owner took 1,002.408448 seconds under its original 1,200-second bound; each output cap remained 8 MiB and the separate cleanup budget three seconds. Dev/test optimization and debug information stayed zero, with assertions and overflow checks enabled, incremental compilation off and four default build jobs. Workspace explicitly used `-j 16`; only serial Launch selected one test thread. These elapsed times are operational correctness-command durations, not performance measurements or evidence of a causal speedup.

The previous [workspace-78b record](../workspace-78b/README.md) remains separately attributed to that revision. It retains the earlier bf4c formatting failure, 900-second workspace timeout with nine rescued descendants, partial populations and auditor refusal/failure-only follow-up. None of that history is overwritten or relabeled by this passing run.

Reproduce from a clean checkout of the exact revision through public `evaluation/short-neighbor-parallel/validate.py` and `evaluation/admission/processes.py`. The existing owner snippet in [workspace-5d1](../workspace-5d1/README.md) consumes this receipt's `outer.command`, `outer.environment` and `source.reproduction_sources`: keep this later receipt outside the checkout, substitute local `ROOT`, `USER_HOME`, `TOOLCHAIN`, `CARGO_HOME`, `RUN_TMP`, `RUN`, `OWNER_LOG`, and use fresh paths plus one real 16-CPU reservation. Apply this receipt's five commands, 316-thread setting, fixed limits and prospective census; do not run the older record's separate minimum-version command or adopt its result claims. Retain every new failure, partial population or unknown closure without retries or new exemptions.

Tool custody is limited to the configured stable-toolchain selectors and environment recorded by this generic validation pipeline. It did not capture contemporaneous compiler/interpreter binary hashes or fresh versions; hashes from other pipelines are not substituted. Source and raw-log hashes in this receipt are authenticated by the closed audit.

These debug checks grant no phase realization, PMU accuracy, cadence, strict 2 ms, performance, complete 43,200-cell A5 matrix, release-native execution or new MSRV qualification. The separate [phase observations](../phase-071/README.md) retain both requested phase positions as UNRESOLVED. Raw logs and exact private inventories remain private.
