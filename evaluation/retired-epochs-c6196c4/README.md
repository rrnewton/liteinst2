# Finite epoch retirement at c6196c4

All 24 stages passed at `c6196c448e01da0875724938262d5e0070f16e76`, with clean closures and zero rescued descendants. [Separate gates](gates.json) passed all seven checks: workspace 2,554 passed/0 failed/7 ignored; serial launch 1,039/0/0.

Two fresh native processes check retirement:

- Sixteen epochs: 16 original/16 installed calls, one registration, 32 events/actions; each held Report prevents permit reuse.
- FunctionClosed: two original/two installed calls, one sampled/one closed. The outstanding receipt retains the permit despite a ready report; staging succeeds after normal return. Retention until physical RET is not established.

[cases.csv](cases.csv), [commands.csv](commands.csv) and [receipt.json](receipt.json) record the evidence. All three release artifacts were rebuilt: opt 3, debug info 0, assertions/overflow checks enabled.

The 22 regression stages passed again; the receipt states their counts and exact state/setup boundary. Retirement adds no state comparator, buffer drain, indefinite-service, accuracy, performance or completed-A5 credit. Earlier failures remain in the [concurrent report](../concurrent-epochs-84d0040/README.md) and follow-ups.

From the clean exact checkout and recorded tool versions:

```sh
env -u PYTHONOPTIMIZE python3 -B tools/rapid-profiler/verify_ordinary_interval.py \
  --revision c6196c448e01da0875724938262d5e0070f16e76 \
  --exact-work --concurrent-epochs --retire-epochs \
  --raw "$REPO/ignored/NEW_RUN" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME"
```

`TOOLCHAIN` contains Cargo/rustc. Retirement bounds: 10 CPU/15 wall seconds/1 MiB. State bounds: 20,000 steps/15 seconds. Hooks remain active.

`python3 -B project.py --raw "$CLOSED_RUN" --out "$NEW_OUTPUT"` authenticates the exact private records; it executes no workload or state replay.
