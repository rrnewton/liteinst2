# Quiescent install-once core

`liteinst2::quiescent` plans and publishes standalone interception under a
caller-owned rendezvous or admission gate. It is separate from the existing
concurrent `InstalledHook`/`RapidProbe` interfaces. It has no scheduler, loader,
or syscall-policy dependency.

## Planning and publication

`plan_install(&InstallRequest)` consumes authenticated original bytes, a
mapping incarnation/generation, containing function/basic-block bounds, legal
entry and saved-resume facts, a callback and allocation/search budgets. It
tries a generalized instruction pun, then same-site relocation, then bounded
upstream instruction heads within that block. This install-once ordering follows
the owner's generalized-pun clarification. `SearchPolicy::tactics` can force
either tactic for qualification. Among upstream candidates it prefers a single-cache-line start,
then shorter upstream distance. `plan_install_detailed` retains every attempted
physical site's refusal. `PlannedInstall::metrics` records upstream distance,
displaced bytes, extra prefix instructions, and allocation attempts. Every
`SiteAttempt` identifies its tactic, so a refused pun and successful relocation
at the same PC remain distinct outcomes.

`PlanKind::GeneralizedPun` replaces exactly one original instruction of length
L=1–4 with E9 followed by L−1 chosen low displacement bytes. The unchanged
successor bytes supply the remaining high displacement bytes. Thus L=1,2,3,4
permits 1, 256, 65,536 and 16,777,216 consecutive target addresses respectively,
including negative signed rel32 displacements. The allocator tries addresses
inside that window under the existing placement, candidate and mapping budgets.
It never changes a successor to make an address fit. The generated stream
observes/replaces only the original instruction and rejoins at original PC+L;
successor entries continue at their original addresses without SIGILL routing.

`GeneralizedPun::consumed` records all five bytes fetched by E9;
`target_window` records the mathematical destination interval. `PlanParts::writes`
contains exactly the L instruction bytes, while `GeneralizedPun::store` records
the actual one-, two- or four-byte machine store. A three-byte instruction uses
one four-byte MOV preserving the following byte. At cache-line offset 61 the
store shifts left one byte instead, preserving the preceding byte. All padding
must be present in the authenticated snapshot and held dependency range. A
line-crossing instruction or unavailable padding refuses the pun; default policy
then tries relocation. Publication and retirement each use one explicit MOV for
the pun, with unchanged padding included. Quiescence, final permissions and
sync-core remain required. All five consumed bytes must be executable after
permission finalization, including across a page boundary. RapidProbe's exact
opcode-byte activation/deactivation API remains separate.

The generated stream executes the prefix, saves application state, invokes the
callback with the **logical** PC, restores state, executes the suffix, and
continues at the original boundary. Replacement skips only the logical
instruction. Explicit original-to-generated entries distinguish entering the
logical callback from entering a later displaced instruction. Separate
`instruction_boundaries` identify restored application state before an original
instruction; callback save/restore PCs are not differential comparison points.

For a relocation plan, every possible displaced entry is either redirected,
preserved behaviorally, or refused. Inside E9's four displacement bytes, a legal instruction head
constrains the chosen address to an architecturally illegal long-mode opcode.
The planner never overwrites a chosen displacement byte afterward. Outside
E9, it prefers `0x62` only with EVEX's reserved P1 bit 2 clear under the
declared legacy/EVEX ISA envelope and the entire maximum 15-byte instruction
fetch inside the authenticated source and one executable page. Even an invalid
EVEX encoding can fetch later bytes before raising #UD; merely having P0/P1
available can cause a page fault instead. Otherwise it uses
long-mode-invalid `0x60` (PUSHA). Displacement constraints use the explicit
long-mode-invalid opcode set in the planner, excluding D4/D5. APX and MIC/MVEX
hosts are refused; qualifying additional ISA profiles is separate work.

Publication checks the trusted plan, lease identity, full snapshot, byte
ownership shared with legacy publishers, mapping budget, and router ownership.
It allocates exact RX trampoline mappings using MAP_FIXED_NOREPLACE, initializes
code, stages immutable routes, and rechecks source/lease before the first store.
Source stores cover the recorded edits and explicit generalized-pun padding;
there is no hidden store span. The caller excludes **all** concurrent source fetches, data
readers/writers, signal reentry and aliases for the full read dependency.

A dual-alias client uses `publish`; a client changing its source page permissions
uses `publish_with` and supplies a non-unwinding finalizer. The finalizer runs
after source stores while the lease remains held. A receipt is issued only after
final permissions and `MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE` complete.
Query/registration failure refuses before writing. Failure after writing leaves
the lease poisoned and source ownership, generated code and routes retained;
the gate must stay held until verified recovery or termination. A failed
permission operation is not followed by a blind write-based rollback.

An `InstalledOnce` has no sampling flag or arm/disarm API. `retire_with` requires
another lease holding both original dependencies and generated allocation
ranges, with every execution/saved reference drained. It verifies the patched
snapshot, restores original bytes, finalizes permissions, synchronizes, and
then disables entry routing and releases source ownership. Dropping an active
handle retains its code, routes and source reservation. This version retains
RX trampoline pages and immutable reverse-PC/route metadata for process lifetime
even after retirement; budgets are per plan, not a process-wide reclamation
policy. Generation retirement is functional; reclaimable arenas are later work.

## Supported envelope and explicit refusals

The caller certifies Linux x86-64, System V AMD64 callbacks, no active CET/IBT,
no overlapping instruction stream, no code-as-data reads/writes, and sufficient
mapped callback stack below the application's preserved red zone. The callback
must obey `HookCallback`, including its extended-state and no-unwind rules.
The core checks shadow-stack status where Linux reports it and rejects an
entry requiring ENDBR within the displaced interval. An existing active CET
application is not qualified by these tests.

The initial relocatable instruction allowlist covers ordinary GPR/memory
arithmetic, moves, stack operations and final control transfers. Segment/control/
debug-register writes, far branches, POPFQ, calls, x87 operations, locked/repeated
instructions and unqualified instructions are refused. Calls need original
application-visible return addresses, and x87 instructions can expose the
relocated instruction pointer; the current implementation does not pretend to
preserve those semantics. Replacements may intercept a logical instruction
outside the observing allowlist but must implement its declared behavior.

The client owns signal policy. SIGILL routing installs only over SIG_DFL,
requires SIGILL unblocked on every executor, and forbids later disposition
replacement while routes exist. The publisher rechecks the exact handler,
flags, mask, and restorer and its calling thread's mask before writing.
Only a synchronous #UD with matching signal, si_code, exception vector, fault
address and original PC can take an owned route. Unowned SIGILL uses the
kernel's default action. Custom/ignored handlers and masked/replaced routers
are refused. Transparent application signal handlers, asynchronous signal-frame
translation and generated-code DWARF unwind registration remain embedding work;
reverse PC translation alone does not provide them.

Allocation search is bounded and reports exhaustion. Constrained placements can
remain impossible even with ample virtual memory. The fixed corpus declares
placement regions and retains its source mappings to avoid unrelated loader
adjacency and address reuse; it does not establish arbitrary-binary coverage.
T1/T2/T3, preserved-original/INT3 pun alternatives, coalescing, grouping, ELF
output and qualified repeated toggles remain later milestones.

## Evidence

The fixed native oracle obtains execution and register/xstate/memory snapshots
through Linux ptrace, independently of iced-x86. Original and patched children
use the same application addresses and seeded architectural states. It compares
at original instruction boundaries and the rejoin, enters every declared head,
and checks exact code edits. Fixed masks exclude debugger TF/RF and reserved
XSAVE bytes; no mismatch-driven tolerance is used. It compares exposed extended
state, while only x87/SSE/AVX/AVX-512 register data are deliberately seeded with
nonzero values. Permission-sensitive components begin in their initial state.
Two additional runs compare a synchronous null-load fault's logical PC, signal,
si_code, fault address and architectural state. Six negative controls deliberately
corrupt distinct state classes or the fault address and must be detected.

This is a finite native AMD-host corpus, not all-ISA proof or Intel/CET hardware
qualification. The source baseline, compiler/hardware, commands, outputs,
coverage counts and remaining gaps are recorded under `evidence/`.
