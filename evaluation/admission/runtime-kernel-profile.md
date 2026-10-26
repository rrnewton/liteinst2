# Opt-in original-site identity and termination syscalls

`DynamicRuntimeOptions::kernel` defaults to `RuntimeKernelProfile::Refuse`.
`IdentityAndTermination` admits only an exact two-byte native64 `SYSCALL`
(`0f 05`) for getpid, gettid, exit and exit_group, and only when the instruction
provider returns `ProviderDecision::Native`. INT 80, SYSENTER, x32 numbers,
native selected CPU decisions and other syscall numbers remain outside this
profile. A selected instruction never falls back to ordinary execution.
Provider faults remain typed faults; they do not execute the original syscall.

The existing unsafe immutable-source, private-writer, singleton, initial-mm
and architectural-control contract remains. Positive namespace-object checks
require the tracer active PID namespace, tracee active PID namespace and tracee
PID namespace for children to match. Numeric PIDs are never normalized across
namespaces. Full current GPRs, initialized XSTATE, signal mask, maps, debug
registers, disabled CET and unregistered rseq are checked independently.

A genuine captured-source proof binds the exact current origin and invocation.
The native producer opens only the one or two fetch pages containing that
instruction, executes the original bytes at their original PC with
`PTRACE_SYSCALL`, and authenticates the real syscall ENTRY. The full original
source window is rechecked before that ENTRY is continued. No ordinary
application instruction runs during the kernel transaction.

For getpid/gettid, the producer retains the actual EXIT and its complete state,
uses the existing private neutral-return bridge, and restores every original
page to NX before the new origin is committed. Nine actual raw waits remain
separate: three opening calls, ENTRY, EXIT, the neutral trap and three closing
calls. Full source and state are reauthenticated at the final closed checkpoint.
The public completed event contains the actual native return state.

A real kernel return retains its syscall number in `orig_rax`. Private control
and census provenance bind that value to the genuine consumed return and exact
current checkpoint. A subsequent emulated CPU instruction must preserve it.
A subsequent ordinary instruction must produce the genuine single-step state
with `orig_rax == u64::MAX`; its closed successor resets the inherited kernel
provenance. No register normalization or general relaxation of the existing
strict single-step predicate is used.

For exit/exit_group, the producer instead retains the actual pre-exit event,
its full initialized state, actual event message and release request, followed
by the real terminal wait. Six raw waits are retained. The application terminal
proof also requires the matching natural-parent status and the original pidfd's
terminal readiness. There is no invented syscall EXIT, user successor, neutral
bridge or NX-closing observation after the mm is destroyed. Pre-exit XSTATE
and mask are retained as observed, without asserting a fictitious returning
state relationship. Final broker cleanup is reported separately by terminate.

## Reservation and retention

One complete six-axis reservation precedes allocation and provider delivery.
The original absolute invocation deadline is used throughout; callbacks and
replies cannot renew it. The default 64 MiB source/evidence ceiling and all
other lifetime limits remain unchanged. Refusal, retirement and unused storage
do not refund a reservation.

The native retained bound is
`H_native + 11 * MAX_XSTATE + 12 * 65536 + 11 * size_of::<ControlProfile>()`,
where `H_native` is the compiled prepared-attempt header. It includes all nine raw
state slots, before/work state, maps and bounded membership storage. The eleven
distinct control profiles occupy an exact-capacity heap allocation, initialized
one at a time after reservation; their large CET arrays are not copied inside
the attempt's by-value constructor. Their full retained bytes remain charged.
The census
separately prepares 19 MAX buffers for a return or eight for termination. The
persistent public journal separately owns eight MAX state copies. Root source
checks, response buffers, full replacement indices and named temporary-query
bounds are additional explicit charges. Fixed Layout allocations give the new
buffers their exact managed capacities. These formulas describe managed
evidence storage, not allocator metadata, arbitrary stack frames or process RSS.

The runtime owner retains all native attempts, including failures and partially
initialized reads, through physical cleanup until owner destruction. The
separate `KernelProgressReader` archive survives owner destruction and exposes
fixed request metadata, nine bounded raw headers and the selected-phase state
copies. It does not promise all private-call maps or XSTATE after owner drop.
Maps summaries record the observed prefix length, completion, read count and
last read outcome; they do not invent a record of every intermediate read.
The first failure remains distinct from actual cleanup status.

Returned and terminal journal completion require distinct private census
receipts after the corresponding real native seal is consumed. Diagnostic
snapshots, source identities and copied trace fields cannot authorize release
or substitute for those receipts. Existing legacy installed-plan journal
contracts remain separate.

## Evidence scope

Exact source `aa8aa54ceeab9f35c8583fa65ee452fe4bcfeaa2` passed the
[recorded native qualification](runtime-kernel-results.md), including six new
native controls, the fixed six bounded commands and eight default-parallel
repetitions. The controls retain complete-body process isolation, original
operation deadlines, literal full-state comparisons and physical cleanup checks.
Pure controls remain identified separately and supply no native qualification
by themselves. Compiler-produced consumer results require a recorded compiler
identity, exact command and artifact identity; no such consumer was run in this
revision, and hand-encoded puzzle fixtures are not described as compiled programs.

The finite native evidence targets claims 1, 2 and 4. It does not establish
loader/TLS/I/O support, memory/stack or indirect ordinary execution, thread,
signal or fork/exec composition, dlopen/JIT, arbitrary application coverage,
persistent shared artifact activation, performance or claim 3's software
preemption clock. Those B3/B4 obligations remain open.
