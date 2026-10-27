# Selected-site leaf

The `selected` module publishes CPUID, RDTSC and returning-SYSCALL replacements
through the existing `liteinst2` core. Dependencies are that core and `libc`;
there is no ptrace path, INT3 shim, TLS registry, or signal-handler publication.

## Preparation and ownership

`PreparedSelected::prepare(SelectedSite)` takes the caller's actual identity,
snapshot, function/block bounds, complete entry/resume certificate, allocation
policy, and search bounds. It requires the literal two-byte opcode and invokes
the real `quiescent::plan_install` with its class-specific ReplaceFirst callback.
It does not infer complete heads from symbols or a linear scan. The returned
core plan and image remain inspectable. Forced relocation is expressed by the
existing `SearchPolicy`/`TacticPolicy::RelocationOnly`, with zero upstream search
when the exact physical site is required; a refusal is never relabelled.

The core reserves each whole supplied source snapshot. Independent installs
therefore need disjoint certified snapshot intervals. This leaf does not bypass
that restriction or provide a multi-site/coalesced publisher.

`unsafe publish_with(alias, real_lease, finalizer)` performs the actual core
publication, returning `Box<InstalledSelected>` only after observing the entire
final source and generated image and comparing both to the actual core plan.
All observation buffers and the outer owner are allocated before publication.
The genuine `InstalledOnce` and `PublicationReceipt` are installed before these
additional checks. Uncaptured buffers are exposed as `None`, never zero-valued
evidence. A verification failure poisons the original lease and returns an
owning `SelectedPublicationFailure`; the caller must retain exclusion and the
source mapping, or terminate. Core post-write failure retains its own reachable
resources under the existing KeepGated contract. Allocation failure before
publication cannot publish bytes.

The finalizer must establish readable RX permissions without admitting
execution, changing bytes/identity, or unwinding. Only after successful eager
publication may the caller arm the NX gate while keeping the original real
exclusion. The source mapping and installed owner must outlive gate disarm and
all executing/saved references. The core's generated code/reverse-PC metadata
remain process-lifetime resources; dropping this wrapper is not retirement.

## Callback semantics and limits

* CPUID forwards the saved low EAX and ECX to one real CPUID. Actual EAX/EBX/ECX/
  EDX results are zero-extended into their saved 64-bit registers. Other saved
  GPRs and flags are untouched. Callback RBX is preserved for the Rust ABI.
* RDTSC executes one real RDTSC without adding LFENCE or substituting a clock.
  Its actual EAX/EDX results are zero-extended; other saved state is untouched.
* SYSCALL admits only native x86-64 `read`, `write`, `getpid`, and `gettid`. All
  six original Linux register arguments are passed to the kernel. Actual RAX,
  including negative errno, is retained without libc errno/TLS conversion or
  retries. Restored RCX is the original instruction address plus two; restored
  R11 is the original RFLAGS. Original RFLAGS and other GPRs are retained.
  The supported flag set is CF/PF/AF/ZF/SF/IF/DF/OF plus fixed bit 1, with IF and
  bit 1 required. Unsupported syscall numbers or flags terminate through one
  raw `exit_group(126)` before the requested syscall. UD2 prevents a return if
  termination itself is refused. No unsupported request receives fake success.

These are incoming-stack callbacks under the core's System V, no-CET/IBT,
qualified XSAVE/FXSAVE, PKRU and sufficient writable stack-below-red-zone
contracts. The context's PC/RSP fields are metadata; callbacks do not use them
to redirect control. The generated core restores GPRs, flags, and its complete
qualified extended-state image. No callback constructs native authority or
modifies the saved extended-state descriptor.

The embedding profile excludes application signal delivery/handlers, restarts,
active rseq critical sections, signal returns, TLS/mapping/lifecycle changes,
unsupported extended state (including AMX), concurrent execution/mutation, and
code-as-data access. Core-owned SIGILL entry routes and the synchronous NX
fault handler are separate existing mechanisms, not application signal support.
Native CPUID/RDTSC must be enabled for the thread. Syscall buffers must be
caller-owned and disjoint from source, trampolines, callback state, and gate
storage; no argument validation or complete pointer provenance is inferred.
This is not generic syscall interception or a dynamic-loader/`/bin/ls` claim.

The syscall callback executes at a different PC and on the core's callback
stack. Its unsafe caller must exclude kernel policies that distinguish that
instrumentation context from the original syscall context, such as IP-sensitive
seccomp or syscall-user-dispatch regions. Address-insensitive seccomp is not
categorically excluded. This leaf does not infer or query policy equivalence.
Tracing that changes kernel behavior based on that context is likewise outside
the contract; address-sensitive tracing/audit records are not transparent
original-context evidence. Supported syscalls still return their actual raw
kernel result, including policy errors, without reinterpretation. The native
fixtures do not establish equivalence under these policies.

## Native validation

The `native_probe` fixture executes the actual published sites without ptrace
and compares original versus selected GPRs/flags/qualified XSTATE/red zone and
real read/write memory effects. RDTSC uses a measured bracket rather than equal
timestamps. The cross-page E9 case checks the actual relocation tactic and
five-byte redirect geometry. Permission faults, first-touch counts and steady
behavior are observed through the gate. Run `evaluation/inprocess/run.py` for
release measurements bound to the tested revision. These fixtures do not
establish application-signal transparency or arbitrary-program coverage.
