# liteinst-launch

This Linux x86-64 crate owns an ELF child from its kernel exec event, before
its first executable or interpreter instruction. It provides a stopped launch
checkpoint, a restricted remote-control adapter and a first-touch page gate
with a deliberately slow trap reference for selected instructions.

`ExecCheckpoint::launch` accepts an explicit executable path and arguments; it
never invokes a shell or searches `PATH`. A private pre-exec stop installs
`PTRACE_O_EXITKILL` before `execve`. The checkpoint exposes bounded memory reads,
registers and entry evidence from the auxiliary vector and mapped ELF headers.
Its exec-event registers describe that kernel stop; the kernel still has to
complete exec before the first user instruction.

`into_stopped_process` completes that kernel transition and creates a private
RX `syscall; int3` island. Bootstrap temporarily modifies original entry bytes
while the sole child task is stopped. It restores and verifies original bytes
and the actual first-user GPR/extended-state image before returning. Remote
operations always pass numeric child addresses to ptrace or the child syscall
ABI; they never dereference them as supervisor pointers. Instruction-stream
synchronization uses queried/registered sync-core in the **child's address
space**. Missing support is a refusal.

`StoppedProcess::hold` returns a scoped, non-transferable stopped-task borrow.
It supports expected-byte writes with readback, checked page permissions,
register access and native single-step. Its held stop alone is not a core
quiescence lease: external writers, aliases and saved resumes need separate
proof. `with_core_lease` accepts those explicit unsafe owner certifications and
borrows the actual stopped-process owner through a restricted publication view.
It exposes no application-resume operation; callback errors, poisoned leases
and unwinding terminate the child. Signals
remain unowned until the caller authenticates the exact stop. Partial or
uncertain control failures terminate the child. The syscall policy permits
only native read on fd 0, write on fd 1/2, getpid, gettid, exit and exit_group.
Other syscalls, compatibility ABIs and lifecycle operations refuse before
kernel execution. Ordinary execution into the private island is refused.

`gate::SingleThreadPageGate` revokes execute permission on all initial user
executable mappings, including the vDSO. A supplied `ImageFacts` is an explicit,
complete instruction-head census and original byte snapshot for one mapping;
code without a census stays gated and refuses on first touch. The unsafe
constructor requires a closed-world ownership contract, including no external
writers/aliases, no code reads as data, and no execution in the private island
or fixed kernel vsyscall pseudo-mapping. Census assertions are not inferred
from symbols or a linear disassembly.

On an authenticated instruction-fetch fault, RuntimeScan checks complete pages
and all-start boundary candidates. Selected straddlers bring both complete
pages into the admission bundle. Source bytes are reauthenticated while the
sole task is stopped, INT3 reference sites are installed, original permissions
are restored, and sync-core completes before release. Each admitted selected trap yields
an immutable pre-instruction observation. The next call executes the original
instruction once under SINGLESTEP, reinstalls its trap and synchronizes again.
An unowned application signal is reported at its original PC and closes the
loop. Each `next_event` has one overall deadline, including permitted syscall
stops, so a syscall loop cannot renew the timeout indefinitely.

Before caller admission, the gate records potential CALL fallthroughs. A CALL
ending at an admitted page boundary can push a return into a still-NX next
page. The live fixture checks the stack and actual permissions. The initial
gate permits a clean destination but refuses selected publication overlapping
a retained return obligation; it does not invent an empty resume census from
page history. Records persist across the entire execution domain.

The initially qualified selected class is CPUID; all other selected classes
refuse before publication. In particular, native SYSCALL stepping produces a
different trap cause and exposes debugger TF in R11. Its raw primitive test
records that difference; it is not accepted as a no-op observation.
The broader default scan policy still finds those sites; it does not silently
deselect them.

`SingleThreadPageGate::new_core` selects a separate A1 path. It requires a
generalized pun for every selected CPUID; a refusal does not fall back to the
trap reference. The complete five-byte E9 fetch range participates in page
admission, including unchanged successor bytes. Source dependency locks refuse
interacting plans. The publisher creates child mappings with
`MAP_FIXED_NOREPLACE`, initializes and verifies generated code before source
publication, uses one native exact-width MOV for the pun, restores scanned
page permissions and completes child-mm sync-core before issuing a receipt.

The core embeds a genuine callback function value. The remote adapter reserves
the same numeric address in the child and installs its separately authenticated
callback there; a collision refuses. No child address becomes a supervisor
function pointer. A callback INT3 yields the original logical PC and saved
context. On continuation, its native CPUID writes EAX/EBX/ECX/EDX results into
that context before the core restores state. This uses `ReplaceFirst` with the
instruction's real semantics. It does not skip CPUID or change the core's
observing allowlist. Code mappings remain owned until child termination.

The A1 constructor additionally requires owner certification of the exact
emitter/child extended-state layout, System V ABI, no CET or AMX use, sufficient
writable callback stack, no reads of instrumentation-private stack, and entry
to generated code only through installed source entries. These are unsafe
closed-world preconditions, not properties inferred from the parent's CPU or
from a private VMA. Every saved continuation must be a declared head; the core
receives all such heads as a conservative resume superset, never an empty list
inferred from NX history.

The reference currently supports one task, immutable private code, 4 KiB pages,
at most 64 initial executable mappings/censuses, at most 64 MiB of initial
executable mappings and at most 64 KiB per census. It is groundwork
for B1 and the B2 reference path. **It does not complete B1:** concurrent
first-fault rendezvous remains open. The
custom interpreter fixture is not general dynamic-loader support. Mapping
churn, threads, application signal handlers, aliases, self-modifying code and
the broader B2 instruction-class/ISA campaign remain unsupported.

Dropping any owner kills and reaps only its child. The caller must not trace or
reap it independently, install a competing global child reaper, or change
SIGCHLD disposition to discard children. Launch/control waits are bounded by
at most 30 seconds. Cleanup waits two seconds per attempt; a failed explicit
termination followed by Drop may spend four seconds. A reserved cleanup worker
retains delayed reaping duty. No original instructions are released for cleanup.

Native tests construct tiny ELF images directly, with static and PIE programs
and a custom ET_DYN interpreter. They require child-ptrace permission; denial
fails instead of skipping. The page-gate differential observer uses independent
raw ptrace operations and compares seeded GPRs, flags, full kernel extended
state and initialized stack memory against native execution.

```console
cargo test -p liteinst-launch
cargo run -p liteinst-launch --example checkpoint -- /bin/true
```

The example captures and terminates a checkpoint. Its timing is exec inspection,
not page admission or application startup. Gate metrics separately report
bootstrap/NX setup, successful first-touch bundles, admitted/untouched pages
and observation counts; debug shared-host samples are diagnostic only.
