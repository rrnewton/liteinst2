# Explicit streamed controller history

`PreparedIntervalController::new_streaming_history(...).activate_concurrent()`
opts into bounded resident action history. `drain_history(&mut self)` transfers
an immutable `HistoryBatch`; `history_window()` gives a qualified resident
snapshot. Consumers retain and replay contiguous batch ranges and carry-in
bindings to join old receipt prefixes to their original generation. The opaque
stream key identifies one in-process stream; installation numbers alone do not.
The committed high-water proves a prefix bound, not its historical owner.

Legacy construction retains the 256-total-action limit and prefix-257 refusal.
The new mode uses checked 49-bit absolute prefixes without changing the
seven-word event, 64-event/32-row buffers or full 512-word journal. No action,
epoch, ordinal, invocation or lifetime counter is reset. Export, report readiness
and receipt consumption inside an exit callback do not prove physical RET or
code quiescence. Handle finite export backpressure explicitly; retain unsent
batches. This is neither an indefinite service nor arbitrary-ABI support.

From a clean committed checkout, run the existing release recipe with every
prerequisite and a fresh `ignored` output directory:

```sh
env -u PYTHONOPTIMIZE python3 -B tools/rapid-profiler/verify_ordinary_interval.py \
  --revision "$REVISION" --raw "$REPO/ignored/history-run" \
  --toolchain "$TOOLCHAIN" --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" \
  --exact-work --concurrent-epochs --retire-epochs --drain-completed \
  --streamed-epochs --stream-history
```

Use absolute existing paths for the checkout, toolchain and homes.
`--stream-history` requires `--streamed-epochs` and appends one fresh exact
ignored-test process after all 26 prior stages. Without it, existing flag
behavior and the 26-stage full prerequisite run remain unchanged. The new child
has 10 CPU seconds, 15 wall seconds and 1 MiB output, inside the existing
40-second parent. It uses the same authenticated C candidate/trusted pair and
release libtest artifact (optimization 3, assertions and overflow checks enabled).

The finite control makes two originals and two installed calls, with an actual
old-owner call paused across history drains/rearms. It checks 600 actions in 77
chunks, 300 staged/retired epochs, two slots, prefixes 1/599, two complete journal
pages, four events and one registration. Independent full action replay checks
carry-in and owner association; retained reports release owners 2→1→0 while
exported batches remain alive. The recipe requires empty stderr and the exact
PASS terminal plus one passed/zero failed/zero ignored libtest summary. Parsed
protocol counts are separate from source-checked slot, owner-release and full
journal assertions. Missing, failed or partial output cannot complete the run.

This is a functional lifecycle control, not a benchmark, calibrated timing,
new full-register-state oracle or completed A5 claim. Earlier native-state and
workload results remain separate. Synthetic parser/flag controls run without
native execution:

```sh
env -u PYTHONOPTIMIZE python3 -B tools/rapid-profiler/history-stream/test_recipe.py
```
