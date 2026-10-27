# Selected-site leaf

The `selected` module publishes CPUID, RDTSC, returning-SYSCALL, RDRAND, RDSEED,
RDPID and RDTSCP replacements through the existing `liteinst2` core. Dependencies
are that core, `libc`, and the same decoder-only `iced-x86` version used by core;
there is no ptrace path, INT3 shim, TLS registry, or signal-handler publication.

## Preparation and ownership

`PreparedSelected::prepare(SelectedSite)` takes the caller's actual identity,
snapshot, function/block bounds, complete entry/resume certificate, allocation
policy, and search bounds. It decodes the exact first instruction and retains its original bytes, operand
width, destination, logical PC and fallthrough. The three existing classes keep
their exact unprefixed two-byte profile. New classes accept decoder-valid prefix
and effective REX forms, and reject invalid LOCK/memory/overlength forms. It
invokes the real `quiescent::plan_install` with its class-specific ReplaceFirst callback.
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

* RDRAND and RDSEED execute exactly one actual instruction at the original
  16-, 32- or 64-bit width, with no retry, supplied sample or CPUID-based
  deselection. Actual carry determines CF; OF/SF/ZF/AF/PF are cleared. A carry-
  clear native result must be zero. Sixteen-bit writes preserve the upper 48
  destination bits, 32-bit writes zero the upper half, and 64-bit writes replace
  the whole register. All other saved registers and admitted flags stay exact.
* RDPID executes actual hardware once, zero-extending its actual TSC_AUX into
  the full non-RSP destination, including valid forms without REX.W. Flags stay
  exact. RDTSCP executes the real instruction once and zero-extends actual EAX,
  EDX and ECX; its architectural ordering is retained without an added LFENCE.

All 15 non-RSP destinations are supported for the register-output classes.
SP/ESP/RSP destinations **refuse during preparation**: the current core callback
ABI exposes RSP as metadata and cannot restore a replacement RSP result. This
is an outstanding B2 capability, not native fallback or complete B2 support.
Core Observe-before semantics cannot supply an after-state completion and are
not substituted. The new completion callbacks explicitly refuse TF/RF; debug-
event and original fault-PC equivalence are outside this closed profile.
Hardware support and thread permission for every invoked class remain required.
An unsupported real opcode faults; it is never replaced by fabricated success
or omitted because a CPUID report hid its feature bit.

`SelectedKind::encoding()` now returns `Option<&'static [u8]>`: operand-free
classes have a canonical encoding, while RDRAND/RDSEED/RDPID return `None`.
`decode_selected()` and `PreparedSelected::instruction()` expose the exact typed
instruction. This replaces the old fixed two-byte return type.

`selected_counters(kind)` reads seven fixed process-lifetime class records:
CPUID, RDTSC, SYSCALL, RDRAND, RDSEED, RDPID and RDTSCP each have actual entered,
completed, carry-clear, and first/last logical-PC fields. Entered advances before
native execution; completed advances only after applying its actual output.
Carry-clear counts only completed random instructions and is zero for other
classes. No counter resets or wraps. Overflow fail-stops. Read snapshots with no
callback active under the existing singleton exclusion; separate atomics do not
promise a coherent concurrent snapshot. First/last PC fields are genuine core
HookContext values, not a complete per-site history. There is no TLS, allocation
or registry lookup. These counters do not measure isolated callback time.

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
Native CPUID/TSC and each selected ISA operation must be enabled for the thread. Syscall buffers must be
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

The separate `selected_probe` keeps the original ten probes unchanged. Its 118
native cases cover 90 random width/register cases, 15 RDPID destinations, RDTSCP,
four actual CPUID-mask dispatch cases and eight accepted prefix forms crossing
a page. A separate preparation control counts seven RSP and six invalid-form
refusals rather than skipping them. The masking callback uses the existing core
HookCallback ABI, retains actual returned CPUID registers with the relevant bit
cleared, and then deliberately executes the selected site unconditionally.
Random native and patched samples need not match: each is checked against carry,
width, defined flags, unchanged state and the same seeded input. Four pure
supplied-value controls check forced success/failure application separately;
they do not claim to force real hardware success or exhaustion. RDPID/RDTSCP AUX
is compared to actual native output on the pinned CPU, and timestamps use real
serialized bounds. State comparisons cover the existing qualified XSTATE
projection and red zone, not unsupported active AMX or arbitrary signal state.

The selected timing wrapper owns its loop/entry on the stack and preserves all
host callee-saved registers, including destinations R12/R13/RBP/RBX/R14/R15.
Native and patched batches use the same original source address and wrapper.
Reported steady timing includes the wrapper, actual hardware, core trampoline
and class-counter cost. It is not an isolated callback-cost measurement.
