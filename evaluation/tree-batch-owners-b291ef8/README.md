# Eight-call source-batch owner qualification

At revision `b291ef854736977cdff8f4271ce4141d1d8cda63`, all nineteen
new public-owner controls passed on their first release run. The unchanged
one-call owner prerequisite also passed. This supports claim 4's lifecycle and
ownership checks for the new batch API; full-state batch comparison is pending.

| New population | Observed |
| --- | ---: |
| Fresh exact native tests | 19 passed, 0 failed |
| Actual original root calls | 29 |
| Actual installed root calls | 61 |
| Successful eight-call batch finishes | 8 |
| Actual controller helper joins | 2 |
| Cleanup rescues | 0 |

The population includes successful reuse and full-buffer drain, nonreserving
capacity/input/ID refusals, E1 Report permit retention, distinct sampled root and
child owners, and FunctionClosed receipt retention after all Reports are dropped.
Sixteen negative cases exercise real guard drop/forget, first-error retention,
caller unwind, early finish and extra-call refusal. These negative controls have
zero successful batch finishes, even when individual calls returned successfully.

All 23 runner stages completed normally with ECHILD and zero rescue. They comprise
three setup/build/parser stages, the unchanged prerequisite, and the nineteen
new native processes. The prerequisite's one original call, one installed call
and one helper join are separate from the table. Every new successful drain
checks all rows, all 512 journal words, actual return words/RSPs, Reports, history,
whole guarded input and lifetime sequences. Poisoned owners retain their data.

Hardware: **AMD EPYC Zen 5 dev host**, observed AuthenticAMD family 26,
model 17, stepping 0. Rust 1.97.1, GCC 11.5.0, Python 3.12.15. Cargo emitted a new
release test binary at optimization level 3, no debug information, assertions
and overflow checks enabled. Builds used four CPUs; each native caller and its
helper shared one CPU. Native limits remained 10 CPU seconds, 15 wall seconds,
1 MiB output and the existing two-second helper waits.

Reproduce using [the checked-in runner](../../tools/rapid-profiler/tree-work/verify_batch_owners.py)
at the exact revision:

```sh
python3 -B tools/rapid-profiler/tree-work/verify_batch_owners.py \
  --revision b291ef854736977cdff8f4271ce4141d1d8cda63 \
  --raw "$RAW" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME"
```

Use a new absolute directory under the checkout's `ignored/` for `$RAW`.
`result.json` records all 175 source inputs, direct tool/artifact hashes, exact
commands with local-path placeholders, profile, hardware and closure receipts.
`cases.csv` contains every case and its observed counts. Command logs and
executables remain ignored. Root independently rejoined the recorded source
bytes to the tested Git blobs and all 23 closed receipt/stream hashes.

Receipt SHA256: `03c16242c14a5640ab746542f7989935911b3228f4eb294c9e2027c420914fcd`.
Elapsed fields are operational run records, not throughput measurements. This
result grants no architectural-state comparison, performance, inside-invoke
Busy-unwind or abandoned-original public-seal runtime credit.
