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

Use `../verify_ordinary_interval.py --help` for the release-build reproducer.
It builds a trusted shared library from `../native-interval/ordinary_checksum.c`
and gives the client a distinct candidate copy and the original expected file.
Its raw logs stay under `ignored/`; its result includes the revision, commands,
tool and binary hashes, hardware description, and eight rows. The native state
oracle is a separate qualification step, not implied by this functional check.

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
