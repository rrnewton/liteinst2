# Normally loaded integer-function intervals

`ordinary-interval` profiles a scalar checksum in a normally loaded shared
library. The C source has no patching NOPs or function-alignment attributes.
The frontend decodes its control flow and requires instrumentation at the
entry and every reachable `RET`. A library-owned assembly gate performs the
actual `CALL`; the original function executes its own `RET` with its original
return word.

The client checks eight original calls against an independent Rust checksum,
publishes the entry/exit bundle while it is the only thread, and runs eight
instrumented calls on one worker. The controller retains four completions,
observes two more calls after that function's sampling budget closes, then
rearms for two completions. It checks both reports, all eight raw interval
rows, unchanged input bytes, actual stack restoration, and worker completion.

The ordinary empty-capable checksum is a required negative case: the selected
compiler emits a one-byte return block, so the whole factory must refuse it.
The separate `ordinary_checksum_nonempty` function requires a positive input
length and has an instrumentable return block. The client calls it only with
lengths from 1 through 64. A different compiler layout can fail these checks;
the client does not omit a return site to accommodate it.

Use `../verify_ordinary_interval.py --help` for the single release-build
reproducer. It builds both executables and a trusted shared library from
`../native-interval/ordinary_checksum.c`, supplying a distinct candidate copy
and the independent expected file. It first requires four native state pairs
(lengths 1 and 64 under two seeds), eight clean child exits and the distinct
short-RET refusal, then runs the eight-call functional client. The result records
the exact revision, commands, hardware, both binary hashes and each Cargo
artifact's profile/cache status. Raw logs and the four native/eight functional
CSV rows stay under `ignored/`.

Native CSV totals report the live comparator, not an independent saved-state
audit. Native state qualification covers the actual gate entry through its post-POP
boundary: full inherited GPR/flags/XSAVE comparison, the complete data page and
exact `[S-128, stack_end)` application-stack range. Each child then restores
only its own saved harness context and executes the real outer return before
normal invocation validation. This is not whole-64KiB stack qualification,
arbitrary-function coverage or timing accuracy. The state and functional
checks are separate required stages of the same wrapper; neither substitutes
for the other. The combined wrapper is source-only until its own execution is
recorded at an exact committed revision.

The endpoint columns contain fenced RDTSCP observations taken after the
application state has been saved at the entry and exit callbacks. Differences
include instrumentation and descheduling. They are uncalibrated TSC ticks;
this example does not establish duration accuracy or compare profiler overhead.

The supported ABI is `uint64_t(const uint8_t *, size_t)` for a bounded integer
leaf using caller-saved registers and read-only input memory. Loading requires
independently trusted compiler output and complete external-entry closure.
Calls, tail calls, stores, indirect control flow, active CET, signal/nonlocal
exits, unwind, fork, unload and concurrent source mutation are outside this
profile. The loaded code, controls and installed image stay alive until process
exit. Input storage is released only after the worker has joined.
