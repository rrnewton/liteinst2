# Actual counters inside an eight-call source batch

Revision `eda7f58f91304f06ddb9f438a1577f2c8834909d` qualifies the actual
`TreeSourceBatch::totals()` accessor. Twenty fresh owner cases passed with
29 original and 62 installed root calls, eight successful finishes and two
controller joins. The nineteen earlier cases retain their separate 29/61
denominator. A new case makes the accessor cause the first ControllerReentry
refusal, then requires the exact retained error and unchanged caller state.
Positive cases read counters twice at every batch position, including zero
and eight, with independently expected sampled/closed counts.

All ten batch controls and five owner-parser controls passed. The separate
release state recipe passed four pairs / eight children / 64 root calls,
including 2,744 full state comparisons on calls zero and seven, 304 hardware
stops and eight consumed batch finishes. Middle calls retain functional and
physical-transfer checks only. All four pairs took 716 original and 11,098
candidate explicit steps under the unchanged 20,000-step / 15-second bounds.
Both recipes completed all 34 stages normally, with ECHILD and zero rescues.
This supports claim 4; it is not a throughput or full-A5 result.

`owner-cases.csv` and `state-tree-batch-pairs.csv` are the exact compact raw
outputs. `receipt.json` records revision, commands, hardware, tools, release
profiles, artifact hashes and closure summaries. All 523 source descriptors
(175 owner and 348 state, with overlap) were rejoined to that Git revision;
every stage receipt/request/stream and parent closure was checked. Detailed
logs and manifests remain private under ignored/.

The host was the **AMD EPYC Zen 5 dev host** (family 26, model 17, stepping 0).
Rust was stable 1.97.1, GCC 11.5.0 and the explicitly selected Python was
3.9.25. Builds used four jobs, release opt3/debug0, assertions and overflow
checks enabled. One earlier attempt failed exact-revision preflight because
the operator supplied a wrong hash; it executed no stages and remains failed.

At the recorded clean revision, set `PYTHON` to the recorded Python version,
`TOOLCHAIN` to the stable toolchain and `CARGO_HOME` to its cache. Use two new
output directories under ignored/:

```sh
"$PYTHON" -B tools/rapid-profiler/tree-work/verify_batch_owners.py \
  --revision eda7f58f91304f06ddb9f438a1577f2c8834909d \
  --raw "$PWD/ignored/NEW_TOTALS_OWNER" --toolchain "$TOOLCHAIN" \
  --user-home "$HOME" --cargo-home "$CARGO_HOME"
"$PYTHON" -B tools/rapid-profiler/tree-work/verify_hardware_stop.py \
  --batch-state --revision eda7f58f91304f06ddb9f438a1577f2c8834909d \
  --raw "$PWD/ignored/NEW_TOTALS_STATE" --toolchain "$TOOLCHAIN" \
  --user-home "$HOME" --cargo-home "$CARGO_HOME"
```
