# Admission from the actual program counter

`DynamicAdmissionSession::launch_runtime` captures the initial executable and
interpreter itself. It accepts storage limits and an instruction provider;
it does not require a caller-supplied image or complete instruction-head list.
This document defines the finite profile and its required validation. It is
not an execution result. A result must cite a complete exact-revision receipt
from `python3 evaluation/admission/run.py --expect-revision FULL_REVISION`.

The constructor retains the genuine EXEC, syscall EXIT, first-user entry trap
and restored entry observations. Original executable mappings are then NX.
Full original VMA identity is separate from bounded overlapping source windows.
Window entry hints remain Partial. Source lookup follows the actual held PC,
and every operation rechecks its complete retained window, backing identity,
map table, private island and complete GPR/XSTATE/signal-mask input under the
current task token and the same absolute invocation deadline.

The ordinary profile admits register/immediate MOV, arithmetic and comparison,
LEA, architectural NOP and direct relative branches from a closed encoding
inventory. A classifier match is descriptive. Native execution additionally
requires a real current source proof, exclusive initial singleton custody,
exact debug-register control lineage, unregistered rseq and disabled CET.
External writers, writable aliases, code observers, independent tracers/reapers,
perf/uprobe interposition and application signal/saved-context activity remain
excluded by the unsafe caller contract. Memory accesses, stack operations,
CALL/RET and indirect transfers refuse before original execution.

For one ordinary instruction the owner uses six private calls and seven actual
waits: synchronization, temporary RX permission for exactly one or two fetch
pages, synchronization, one original PTRACE_SINGLESTEP, synchronization, NX
restoration, and synchronization. All unrelated mappings stay byte-exact. Each
wait retains its actual result before any query of the held task. Only a real
SIGTRAP/TRAP_TRACE with the expected address and control state certifies the
original step. The first private closing call has a dedicated native proof;
a generic source reader never treats NativeCompleted as a settled checkpoint.
Complete source and state are rechecked after opening and closing. Census
commit occurs only after NX restoration and final verification. A same-PC
branch consumes its old origin and creates a distinct current origin through
this native completion path; ordinary unchanged-state bookkeeping stays strict.

Selected CPUID, RDTSC, RDTSCP, RDRAND, RDSEED and RDPID instructions use the
existing typed provider semantics. Their scripted result is installed and
verified through a private neutral trap while original source remains NX.
A consumed native completion proof advances the control lineage. Native
selected decisions and syscall completion are refused in this initial profile.
A selected instruction cannot fall back to the ordinary path. Each callback
and reply shares its original absolute deadline; an expired reply is not
retried with a renewed budget.

All six existing lifetime limits remain. Source, state, map, request, history
and attempt storage is reserved before effects, including unused MAX-capacity
XSTATE buffers. Attempts are installed before native queries and survive error
or unwind. Census preparation allocates its complete commit storage before the
first effect; final commit moves those allocations without allocation or a
partial origin update. Retirement and unused reservations give no refund.
The account describes retained evidence and specified temporary work, not all
allocator internals or process RSS. Failed public diagnostic Memory-query
prefixes are not archived; this does not change retained source/native attempt
diagnostics. The original owner remains responsible for app and broker reaping.

Validation includes literal first-instruction startup, exact one-instruction
state transitions, same-page successor exclusion, taken/untaken branches,
same-PC origin consumption, an independent raw single-step NOP comparison,
selected-to-ordinary lineage, unsupported memory/stack/native/syscall decisions,
and a real enabled-debug-register refusal. Negative model controls corrupt
source/stop/encoding/state/map/history/budget fields individually. Native fixture
names belong to the strict recorder catalog; missing, ignored, failed, unknown
or wrong-harness outcomes cannot qualify. Counts and results are supplied only
by the committed corpus and the exact-revision run receipt.

Each runtime native test executes its complete body in a separate exact-filter
test process. This prevents unrelated parallel tests from changing the tracer's
map table during source reauthentication; the outer suite keeps its normal
parallel scheduling. The real public client/provider and owner threads remain.
Success requires both the exact one-test result and a parent-bound receipt
written after every original assertion and cleanup check. Child output and
process lifetime are bounded; uncertain cleanup aborts validation. Original
operation deadlines, complete map comparisons and outer recorder gates remain
unchanged. This fixture boundary does not make production map reads atomic or
establish the precise subtype of an earlier map-parse refusal.

The intended evidence supports claims 1, 2 and 4 within this finite profile:
page confinement and closure, first-instruction selected interception and
explicit tactic controls. This adds no in-place pun publication, performance
result or software preemption clock. Loader syscalls, TLS, I/O, threads,
signals, fork/exec composition, dlopen/JIT and arbitrary ordinary applications
remain unfinished B3 work. Persistent shared artifact activation remains B4.
