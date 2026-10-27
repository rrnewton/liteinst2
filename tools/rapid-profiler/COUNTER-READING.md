# Counter endpoint arithmetic

`rapid_profiler::counter_reading` is a pure building block for future raw
measurement records. It acquires no counter, timestamp or event identity and
is not connected to the live profiler, generation records or native frontend.
Their existing output and behavior are unchanged.

Construct a `CounterRecord` from two `Option<CounterReading>` endpoints. Each
reading retains its original `value`, `time_enabled` and `time_running` u64
words. The record always retains both inputs, even when arithmetic is rejected
or an endpoint is missing. `None` means only that the endpoint was not supplied;
this API cannot distinguish a missing event, failed read, permission denial,
unsupported counter or any other cause. An acquisition layer must retain its
own observed diagnostics separately.

`arithmetic()` reports one of these cases:

| Case | Meaning |
| --- | --- |
| `Missing` | Start, end or both are absent. Known inconsistencies in the present endpoint remain visible; cross-endpoint facts are unknown. |
| `Rejected` | At least one value/time field regresses, an endpoint has running time above enabled time, the running delta exceeds the enabled delta, or a positive count delta has zero running delta. All observed issues and each individually computable delta remain available. |
| `ZeroRunning` | Present, consistent endpoints have zero running delta and zero count delta. No estimate is available, even if the enabled delta is positive. |
| `FullRunning` | Positive running delta equals enabled delta. This describes the supplied words, not qualified hardware scheduling. |
| `Multiplexed` | Positive running delta is less than enabled delta. The scale is arithmetic, not an accuracy claim. |

A value regression is ambiguous: a wrap, reset, different event or another
discontinuity may explain it. The module neither chooses a cause nor performs
modular subtraction. A reset or identity change can also be invisible in a
monotonic pair; passing these checks cannot establish continuity. The same
limitation applies to monotonic time words. A count change with no running-time
change receives no estimate and no inferred explanation, including assumptions
about time resolution.

For each running interval, `ExactEstimate` retains the unreduced ratio
`delta_value * delta_time_enabled / delta_time_running`. The numerator is u128
and denominator is a positive u64. Two u64 factors have a product at most
`(2^64 - 1)^2`, which fits u128. The exact quotient remains u128, including values
larger than u64::MAX; the remainder is strictly smaller than the denominator.
No multiplication or result is saturated, no fraction is discarded from the
record and no floating-point rounding is used. `quotient()` alone is only the
integer part. For example, 7 events with enabled/running deltas 5/3 give the
exact ratio 35/3, quotient 11 and remainder 2. A zero count with positive running
time is the valid arithmetic ratio zero, distinct from missing or zero-running
observations.

The eight pure tests specify hand-derived integer/fractional examples, missing
endpoints, zero-running versus zero-count, all three regressions, inconsistent
times and the maximum u64 product. They do not read PMUs or execute a fixture.
Their presence in source is not a claim that they have compiled or passed.

This is preparation for lossless measurement data, not the bounded raw accuracy
mode or the study's accuracy experiment. Event definitions, privilege filters,
thread/function/invocation identity, completed/cancelled status, boundary
synchronization, timer qualification, exact trace/cache-model truth, calibration
uncertainty and full-population accounting remain separate obligations. The
existing PMU path still reads events sequentially; existing elapsed TSC readings
remain unfenced and have different inclusion semantics from the PMU events.
No clock, hardware accuracy, frontend coverage, performance or full A5
qualification follows from any arithmetic classification.
