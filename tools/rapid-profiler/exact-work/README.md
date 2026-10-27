# Exact work and sample selection

`exact_work_nonempty` is a normally loaded read-only integer leaf with a fixed
37-byte assembly body. For an input of `n` bytes, with `1 <= n <= 64`, it executes
`6*n + 5` original instructions including its RET, `n` conditional branches,
`n - 1` taken branches, `n` input-byte reads, and one eight-byte return-address
read. The function has no calls, stores, padding NOPs or stack adjustments.

`truth.rs` independently interprets these exact bytes. The native `exact-state`
mode compares its ordered instruction PCs, next PCs, branch decisions, operand
reads, return value and resumed stack pointer with original single-step states.
Two lengths and two seeds provide four original/instrumented pairs. The existing
whole-state comparisons, real outer returns, short-RET refusal, child deadlines
and cleanup checks also apply. Reconstructed reads describe these instruction
semantics, not measured memory events or cache misses.

`ordinary-interval exact-work CANDIDATE TRUSTED SCHEDULE K` runs 24 original and
24 instrumented calls. Schedules are `short`, `long`, `alternating`, and
`late-long` (ten short calls followed by fourteen long calls). Each fresh process
uses `K=24`, `K=1`, or `K=10`. The harness assigns IDs before calls and joins each
synchronous completion to exactly one new raw interval. It checks all 24 calls,
including those after sampling closes, against the source model and retained
generation report. `join.rs` rejects missing, duplicate, substituted or changed
rows, boundaries, labels and ownership.

The output separates retained work from the complete population. For example,
`late-long` with `K=10` retains a mean of 11 original instructions while the
whole-population mean is 231.5. The exact selection error is -220.5 instructions
per invocation. This arithmetic describes the fixed schedule; the native recipe
must pass before claiming that its observed records implement that schedule.

Run `../verify_ordinary_interval.py --exact-work` with its required revision,
raw-output and toolchain arguments. It builds release binaries, retains the
existing checksum regression, runs the native state pairs, and checks all twelve
fresh-process populations. Raw RDTSCP endpoints remain uncalibrated. Mandatory
entry/RET hooks remain active after K closes; this experiment establishes no
elapsed-time accuracy, PMU accuracy, cache-model result or saved toggle overhead.
