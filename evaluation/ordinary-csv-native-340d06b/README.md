# Compiled CSV body: native state qualification

One fixed release qualification at
`340d06b337a43f166c6e0d947c8c39d7ec112f1d` passed all 32 original/instrumented
pairs: two seeds × 16 CSV records. It completed 5,804 state comparisons with zero
mismatches, 128 target calls and returns, 64 actual outer returns and 64 normal
child reaps. No retry or warmup was used. All 17 prerequisite stages passed,
including 149 active calibration controls, the one unchanged ignored hardware
control, four caller controls and nine Python controls.

The complete 126-byte compiled function ran through the existing 67-byte C
caller. The authenticated oracle checks GPRs, defined flags, XSAVE state,
protected stack, input data, source bytes and complete SDK lifecycle accounting.
Both declared RETs were observed for each seed. Each seed observed 38/42 decoded
instruction heads and 45/49 CFG edges; this is partial path coverage, not a claim
that every possible input path was exercised.

The [ordinary Rust application qualification](../ordinary-csv-6c2b5df/README.md)
separately passed 16 original and 16 instrumented calls and complete profiling
records. This native result qualifies the CSV body under the C helper; it does
not establish full architectural-state preservation for the Rust caller. Neither
result supplies throughput, timing accuracy, general-module support or full A5
completion.

The one native owner closed normally after 28.048 s, inside its frozen 510 s wall
limit. Each pair retained its absolute 15 s/20,000-step limits. CPU 480 seconds was
per process, not an aggregate CPU budget. No timeout or rescued descendant
occurred. The whole build/control/qualification owner closed in 180.924 s.
These are operational durations, not performance measurements.

CPU 290 was reserved with hard AllowedCPUs290; load is recorded in the receipt
without claiming scheduler quiet. Builds used release opt3/debug0, assertions
and overflow checks enabled, offline locked Cargo, four jobs and no incremental
compilation. All seven exact-source checks passed: default workspace 3,141 passed,
zero failed, 36 ignored in 331.239 s; serial launch 1,039; staged allocation 3;
prefixed-pun 36; fmt, strict Clippy and workspace check. Both historical allocation
regressions passed at default parallelism.

The two CSV files retain every pair and both coverage rows. `receipt.json`
records exact revision, reproduction command, hardware, reservation, tool and
artifact hashes, limits, control counts and every closed stage. Root readback
checked 521 source files against Git, 180 retained evidence pins and 12 tool
binaries. Raw logs and ELF captures remain ignored. Run the
[one-shot reproducer](../ordinary-csv-native/README.md) at the recorded revision
with a fresh output directory. Prior functional loader/mapping refusals and the
source-check timeout remain tracked with their original failed statuses.
