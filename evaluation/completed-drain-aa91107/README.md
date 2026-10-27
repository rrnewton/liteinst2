# Two completed buffers at aa911072

All 25 native recipe stages passed at `aa911072c32912dfb7b73c1dee168c429289bb2e`. Every stage closed with an ECHILD proof, complete parent cleanup and zero rescued descendants. [Separate required gates](gates.json) passed all seven checks at the same revision: workspace 2,563 passed/0 failed/8 ignored; serial launch 1,039/0/0. Workspace totals exclude five nested summaries. The new native test remains one of the default ignores; its explicit release PASS is recorded separately.

One fresh release test made 64 original and 64 installed checksum calls on one thread and registration. Two explicit drains transferred 32 raw rows and the entire 512-word journal each. Lifetime ordinals, completion sequences and ownership continued across reuse. The test checked both full journals against actual call results, all 64 Report records, two capacity refusals, three empty drains and the retained first batch after the second refill. These native assertions are source-attested; this projection does not independently replay saved machine state.

[cases.csv](cases.csv), [commands.csv](commands.csv) and [receipt.json](receipt.json) contain the result and exact commands. All 24 prior stages passed again: checksum/exact/concurrent-mode state oracles made 978/844/844 comparisons; 12 exact-work populations covered 288 calls (140 sampled, 148 closed); the timed client covered 24 calls (18 sampled, six removed); both retirement cases passed. The concurrent-mode state oracle has no competing controller. Its coverage is distinct from the forced contention test.

The inherited state boundary is gate entry through post-POP: full GPR/flags/XSAVE/data and exact `[S-128, stack_end)` comparisons, followed by real outer return after harness-context restoration. Setup and the remaining stack are excluded from those comparisons; the absolute deadline includes setup. Drain adds no new full-state oracle, timing accuracy, performance, indefinite-service or complete-A5 claim. Earlier failures remain in the [concurrent report and follow-ups](../concurrent-epochs-84d0040/README.md), the [ordinary-interval report](../ordinary-interval-ff18353/README.md) (seven failed earlier attempts and the first workspace-test timeout), and the [exact-work report](../exact-work-723f09e/README.md) (two initial development failures).

The run used the AMD EPYC Zen 5 dev host (observed AMD family 26/model 17/stepping 0), Rust/Cargo 1.97.1 and GCC 11.5.0. All three Rust artifacts were rebuilt with release opt 3, debug info 0, assertions and overflow checks enabled; exact hashes and versions are recorded. The drain child uses 10 CPU seconds, 15 wall seconds and 1 MiB output. Existing state-oracle limits remain 20,000 steps and 15 seconds per child. Mandatory callbacks remain active.

From the clean exact checkout with the recorded tools:

```sh
env -u PYTHONOPTIMIZE python3 -B tools/rapid-profiler/verify_ordinary_interval.py \
  --revision aa911072c32912dfb7b73c1dee168c429289bb2e \
  --exact-work --concurrent-epochs --retire-epochs --drain-completed \
  --raw "$REPO/ignored/NEW_RUN" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME"
```

`TOOLCHAIN` contains Cargo/rustc. The recipe records the actual selected tools and enforces clean source identity. `python3 -B project.py --raw "$CLOSED_RUN" --out "$NEW_OUTPUT"` reproduces this exact metadata projection from its closed private records; it runs no workload.
