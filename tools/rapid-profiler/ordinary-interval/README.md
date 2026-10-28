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
exact `[S-16-128, stack_end)` application-stack range, where `S` is the gate-entry
stack pointer. The extra 16 bytes cover the gate's saved register and the subject's
return word before its red zone. Each child then restores
only its own saved harness context and executes the real outer return before
normal invocation validation. After that return, every flag except ptrace's TF
bit must equal the saved harness flags; the adapter clears only TF before
continuing. This is not whole-64KiB stack qualification,
arbitrary-function coverage or timing accuracy. The state and functional
checks are separate required stages of the same wrapper; neither substitutes
for the other. The [recorded run](../../../evaluation/ordinary-interval-ff18353/README.md)
contains the exact revision, four state pairs, eight functional rows and final
workspace validation results.

The native original uses a one-shot prepared call: complete file/mapping/source
validation runs before the readiness stop, while an exclusive borrow keeps the
preparation unavailable for publication. Consumption on the same process/thread
calls the unchanged gate and requires the complete after-check before returning.
Candidate publication and attachment also precede readiness. The continuous
20,000-step allowance starts at readiness; the 15-second child deadline starts
before either fork and includes setup. A diagnostic attempt that single-stepped
the original's file/mapping preflight exhausted the allowance before gate entry.
It remains a failure; this boundary does not establish that the previous path
fits the allowance. Every gate/function state comparison remains required.

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

## Selecting an internal function

`TrustedFunctionSelection` binds the complete independently trusted final ELF
bytes to an ELF virtual address, complete function length and printable metadata
label. `LoadedIntegerLeaf::load_selected` uses that descriptor and the retained
normal-loader handle to resolve the function. It does not use the label for a
symbol lookup. The named `load` API still requires its original dynamic symbol.

The caller must establish the function's complete extent and entry closure from
trusted metadata. For a stripped file, pre-strip metadata is usable only with
proof that stripping preserved the selected code and load geometry. A candidate's
own range or hash does not supply that independent authority. The safe descriptor
constructor checks representation bounds; it does not prove function boundaries
or make loading safe. An interior range can itself decode as a valid smaller CFG.

Range selection retains the existing whole-file, loader-object, mapping, source
page, CFG and every-RET checks and all execution contracts above. It supports an
eligible internal function without requiring its exported name; it does not add
sectionless ELF, dependencies, constructors, relocations or a broader instruction
grammar. Native qualification of this new selection path is separate from the
named-function evidence linked above.
