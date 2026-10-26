# Bounded dynamic page admission

`DynamicAdmissionSession<P>` combines the seized native owner with page admission
and a typed selected-instruction provider. It is a separate unsafe API; the
ordinary `DynamicSession` retains its own uninstrumented control contract.
This document describes the finite implementation. Qualification requires an
exact-source result from the [evaluation protocol](README.md); it does not
establish full B3 or unrestricted application support.

The [public API](../../crates/liteinst-launch/src/linux/remote/dynamic/admission.rs)
accepts a `LaunchCommand`, complete `ImageFacts`, `DynamicAdmissionOptions`, a
provider and an operation timeout. It exposes no raw session, resume token,
ptrace operation or publication lease.

| API | Contract |
| --- | --- |
| `unsafe launch(...)` | Certify the finite image/continuation envelope, bootstrap the owned process and return held initial state. |
| `next_event()` | Advance to a selected completion or diagnostic event under one absolute operation deadline. |
| `initial_state()`, `state(task)`, `read_memory(...)` | Inspect retained initial evidence or an authenticated current held task; snapshots confer no release authority. |
| `provider()`, `provider_mut()` | Inspect or update caller-owned policy between operations. |
| `metrics()`, `terminate(timeout)` | Read diagnostic work/history counters, or request complete physical cleanup. |

The caller must certify every instruction head and saved-context origin in the
supplied immutable private images, including alternate entries. External
writers, writable aliases, code-as-data dependencies, competing tracers/reapers
and opaque saved contexts are outside the contract. TF and RF must be clear at
original guarded entries; observing a later INT3 cannot prove their earlier
values. Application signal frames, exception/nonlocal contexts, later mapping
changes and later exec are not admitted. Code without supplied facts remains
NX and refuses on touch. The private instrumentation island and fixed kernel
vsyscall mapping are not application execution destinations.

Bootstrap is an explicit singleton exception to the later NX-before-write rule.
While the only application task is owned and stopped, it temporarily patches
the original entry to observe an actual user-boundary INT3 and to initialize a
private syscall island. Kernel EXEC, actual exec EXIT and this user-boundary
snapshot remain separate evidence. Bootstrap restores the original bytes and
the observed GPR/XSTATE/signal-mask image, rewinding only the owned INT3 PC,
then revokes execute permission on the original executable mappings, including
the vDSO. `initial_state()` is that authenticated retained snapshot; it is not
an independent native oracle for the bootstrap implementation.

`StrictTrap` retains the strict scanner's refusals. `CoverageTrap(budget)` is an
explicit choice for complete overlapping guard closure; its collateral native
executor is limited to the qualified MOV-immediate profile. Both use the
default selection of CPUID, RDTSC, RDTSCP, RDRAND, RDSEED, RDPID and native
SYSCALL. Selection does not guarantee that every encoding can be admitted.
Original refused reports remain retained. Neither choice silently falls back
from A1 publication; A1 is a separate existing API. Typed provider semantics
are described in [SELECTED.md](../../crates/liteinst-launch/SELECTED.md).

Before source mutation or release, the owner authenticates every current member
of the shared address space, full held state, source bytes, installed guards and
each continuation route. The pure pending plan cannot authorize publication.
Changed continuation facts cause actual NX revocation, guard restoration and
generation rebinding before new publication. Complete expected bytes, final
permissions and target-mm synchronization are checked before release. Current
origins, consumed history, original reports and potential CALL returns remain
retained under nonrefundable lifetime bounds; a task disappearing cannot erase
a CALL obligation. Cache hits do not replace these native checks.

Resource sizing scans every supplied source image once at startup. Its candidate
count remains bound to exact original bytes, policy and declared heads; future
page reports still charge repeated candidates and all retained facts. This work
is reported separately as `resource_scan_decoded_starts`, outside demand/cache
metrics. The implementation makes no incremental-startup or performance claim.

The provider runs on the caller's thread. Advance, callback and completion share
one deadline established before the exchange; returning from a callback does
not renew it. The tracer independently watches a pending callback deadline and
retains cleanup ownership. A blocked callback can still block its own host
thread. A provider error, panic, expired operation or owner error closes the
session; a scripted fault is reported without fabricating a native signal.
Partial publication failure does not promise source rollback before termination.

The native syscall completion profile admits Linux x86-64 `getpid`/`gettid` and,
when explicitly enabled, one exact `SYS_clone` with flags `0x10f00`, no TLS/TID
output and a checked child stack. This is the bounded `ThreadClone` profile:
at most two lifetime native tasks sharing one process/mm, with per-task CET and
full inherited-state checks. Parent syscall EXIT and child automatic
return-ready remain distinct phases. Native `exit`/`exit_group` may enter the
kernel, but terminal or pre-exit events do not qualify continued admission of
survivors. Application signals, unsupported syscalls/ABIs, mapping changes,
fork and later exec fail closed. Census terminal retirement remains test-only;
physical cleanup continues to require the native owner's terminal waits,
process/thread pidfd evidence and natural-parent reaping protocol. `Drop`
requests cancellation; `terminate` waits for its cleanup receipt.

The initial [seven native fixtures](../../crates/liteinst-launch/tests/dynamic_admission.rs)
cover executable/interpreter first-entry CPUID, scripted/native CPUID state,
clone across a page boundary with both tasks faulting, strict versus explicit
coverage RDPID, mapping-policy refusal, provider panic and blocked-provider
cleanup. They retain full-state assertions but do not establish dynamic native
coverage for every selected class or encoding. Existing static-gate oracles,
pure semantics and uninstrumented lifecycle/signal fixtures are separate
evidence. Counts, failures and cleanup outcomes must be read from the exact
revision's receipt; counters alone are not qualification or performance evidence.
