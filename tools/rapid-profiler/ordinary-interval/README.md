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

## Ordinary application callers

The separate normal-caller API lets application code call the installed function
through its original C ABI. Attach the worker once, then acknowledge its returned
calls at a batch checkpoint. The entry and pre-RET callbacks retain each call's
original epoch until that worker's next entry or explicit checkpoint confirms
return. Seeing a pre-RET callback, a ready report, or another worker finish does
not confirm this worker's return.

`LoadedNormalLeaf`, `NormalSitePreparation` and `PreparedNormalController` carry
the single-caller contract. The corresponding two-caller types are
`LoadedTwoCallerNormalLeaf`, `TwoCallerNormalSitePreparation` and
`PreparedTwoCallerNormalController`. Their contracts are distinct: increasing a
single-caller controller's thread limit cannot turn it into a two-caller site.
The two-caller controller requires concurrent activation and exactly two
lifetime registrations, each with depth one. Both workers must attach with
`NormalClient::attach_two_callers` and report ready before either calls the
function. The application supplies this barrier.

Each `NormalThread` stays on its actual worker thread. It owns that thread's
pending return, journal and sequence counters. Before acknowledging a batch,
the caller verifies its immutable input and source/generated code under the
continuous loader contract. A final empty checkpoint and explicit detach release
metadata only; executable owners remain alive until process exit. Registration
identities cannot be recycled after detach.

The per-function sampling budget counts retained completions. With two callers,
both may be admitted before the budget closes; a completed admission can therefore
be `DroppedAfterBudget`. A consumer must account for those completions and join
records by generation, invocation and worker identity. Completion rank and the
order in which the controller receives results need not match invocation order.
The report does not turn dropped records into unsampled calls.

These profiles retain the bounded read-only leaf, complete-function, ordinary
CALL/RET, no-reentry and no-unload requirements above. They do not add recursive
calls, arbitrary worker counts or general shared-library instrumentation.

## Raw counters for selected sessions

The explicit `normal-selected-accuracy-session` command accepts this grammar:

```
normal-selected-accuracy-session CANDIDATE TRUSTED_FINAL TABLE K EPOCH_MS EPOCHS N (ID LABEL ELF_VA EXTENT POLICY){N}
```

It uses the existing selected-function loader, complete `LI2SELECTED 1` input
table, worker, publication, banks and history. K is one of 1, 10, 100 or 1000;
the epoch period is 1, 10 or 100 ms. It admits one to four functions, at most
520 epochs and 4,096 physical calls. The old selected command keeps its original
K10/K1000 and 10 ms profile. The new READY version is
`selected-accuracy-session-v1`; old wire readers must refuse it.

Each invocation, including unsampled work, retains two raw counter endpoint
records for a pinned, non-inherited, current-thread `instructions:u` event.
Acquisition records keep
the requested and kernel-returned attribute bytes, event ID and enable result.
Endpoints keep the full initialized read buffer, actual return value and errno,
PID/TID, event-ID match and fenced TSC/AUX observations before and after the
read. Explicit detach returns disable and close results. A failed open or read
does not skip application work or become a zero event count. These counter
windows differ from the existing callback timestamp windows and include
instrumentation. Neither window establishes original-body cost.

The SDK entrypoints are `Policy::accuracy`,
`PreparedNormalLeafSetSessionController::new_accuracy`, and the separate unsafe
`NormalLeafSetClient::attach_accuracy`. Accuracy attachment requires the strict
AMD reference-clock profile in addition to the ordinary source, ABI, thread,
stack and return contracts. Its completed batches transfer normal records,
counter records and acquisition evidence together. Native state validation is
required before measurement of this new callback path.

ARM rows retain each original due time, actual arm start and completion after
publication/history. The lateness limit remains 2 ms. At a 1 ms cadence these
windows overlap; actual timing is reported and no deadline is renewed. Only
this version has an 8 MiB output buffer, bounded by 20,018 rows of at most 350
bytes; old commands retain 4 MiB. Output failure is terminal.

The [accuracy evaluation](../../../evaluation/ordinary-accuracy/README.md)
prepares independent complete populations. These APIs collect evidence; their
names do not imply calibrated interval accuracy, unbiased population estimates,
realized phase locking or a performance result.
