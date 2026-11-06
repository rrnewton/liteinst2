# The safety contract and refusals

LiteInst's most important behaviour is what it *won't* do. This chapter
is the contract: the envelope inside which patching is sound, what you
must provide to stay inside it, and the named refusals you get outside
it. A refusal is never a euphemism for "probably fine."

## The six invariants

The implementation maintains these at all times:

1. A cross-cache-line patch uses guarded publication unless the caller
   proves no concurrent fetch or data access is possible.
2. Probe installation publishes state only after planning and
   allocation pass.
3. Trampoline sizing and emission use the same checked plan.
4. Signal handlers use only async-signal-safe, pre-published data.
5. Trampolines never use one RWX mapping; arenas keep separate RW and
   RX aliases (and therefore do not provide strict W^X).
6. Continuation uses a direct jump when reachable, with a CET `NOTRACK`
   indirect fallback, so a continuation need not begin with `ENDBR64`.
   Unpreservable IBT entries are refused, not approximated.

## What clients must provide

Generic hooks can displace several complete instructions, replace a
short first instruction such as `syscall`, and mutate the saved integer
context. They do not establish arbitrary-binary, probe-anywhere
support. You must provide:

* a **trustworthy code region** with **writable access** to the live
  patch word;
* **mapping-lifecycle ownership** — nobody unmaps, remaps, or rewrites
  the region behind the library's back;
* proof that **no control-flow entry targets the interior** of a
  relocated window;
* a **trap fallback** for when the planner returns
  `PunPlan::TrapRequired`;
* for split (cache-line-crossing) concurrent sites, a
  machine/topology-qualified **`StalenessBudget`** — or route those
  sites to the trap fallback;
* for the controller-owned trampoline form, an external controller
  that performs both documented stack pivots. Using that entrypoint
  without one is unsupported.

Signal obligations are equally explicit. Concurrent WordPatch++
installation owns the process SIGTRAP router and refuses a prior custom
handler (unless the host supplies exact callbacks). Installed
trampolines publish immutable generated-to-application PC ranges;
signal handlers and unwind front ends translate a faulting PC with
`trampoline::translate_program_counter` — allocation-free and
lock-free — before reporting or unwinding. That translation path
synthesizes no DWARF; separately, the opt-in `generated_unwind`
module can publish source-certified CFI for normal backtracing
(no exception or signal admission). Trampoline arenas seal their
memfd against new writable mappings, writes, resizing, and policy
changes, and arena creation *fails closed* when the backing store
cannot provide the required seal set.

## The envelope, in one list

* **Platform:** Linux x86-64 for anything that patches or gates. Per
  crate: the core's live modules are cfg-gated (empty/refused
  surfaces elsewhere); `liteinst-inprocess` is `compile_error!` off
  Linux x86-64 and `liteinst-launch` exposes its API only there. The
  fact-only crates (`liteinst-x86`, `liteinst-artifact`, and the
  admission model) carry no such gate — decode facts alone buy no
  execution authority anywhere.
* **Kernel:** no SUD required. ptrace is required only where a
  controller drives another process (`liteinst-launch`, hybrid
  clients); pure in-process use needs none.
* **Binaries:** caller-certified regions. General static/PIE/musl
  turnkey support is not claimed; static `ET_EXEC` has an opt-in
  per-product bootstrap (`liteinst-bootstrap`, unpublished).
* **Dynamic code:** JIT and self-modifying code are not discovered.
  Gates admit *certified* pages lazily; uncensused code stays gated
  and refuses on first touch.
* **Threads/signals:** as above — quiescent entrypoints require total
  exclusion for the call; handlers see only pre-published translations.

If your program sits outside this envelope, the correct outcome is a
named refusal and a different mechanism (see
[Interception mechanisms compared](mechanisms.md)), not a workaround
inside LiteInst. At the Reverie layer, this library's refusals surface
under the shared `R-*` names — an uncensusable region or a
`TrapRequired` with no trap cell becomes `R-CODE`, a SIGTRAP-ownership
conflict `R-SIGNAL`, a strict-W^X policy `R-WX` — so a tool author
sees one taxonomy no matter which layer refused.

## The catalogue

Every public variant of the seven envelope-facing refusal/error
enums, with its trigger (from the variant's own documentation) and
the supported remedy. It is checked against the source enums when
this chapter changes: a variant added without a row here is a
chapter bug, not a detail.

### `contracts::Refusal`

Plan/lease layer (`contracts`): returned by `PatchPlan::checked`, obligation checks, and lease checks — all before any write.

| Variant | Trigger | Remedy |
|---|---|---|
| `InvalidRange` | Empty or overflowing range. | Fix the range arithmetic; never clamp silently. |
| `InvalidPlan` | Inconsistent plan structure. | Rebuild the plan so reads, writes, displaced interval, and requirements agree. |
| `StaleGeneration` | Mapping incarnation, generation, or entry identity differs. | Re-plan against the current generation; do not reuse the plan. |
| `ExpectedBytesChanged` | Source differs from the authenticated snapshot. | Re-authenticate the region and re-plan from fresh bytes. |
| `DependencyNotHeld` | Lease does not hold every required byte. | Widen the lease to cover every dependency range, or shrink the plan. |
| `LeasePoisoned` | A prior postwrite error has not been resolved. | Verified rollback + synchronization, or terminate; never drop-and-continue. |
| `UnresolvedEntry` | Static or dynamic entries remain unproved. | Supply the missing entry/resume proof, or refuse the site. |
| `NotInstructionHead` | Requested instruction is not a verified head. | Pick a verified instruction head from the scan. |
| `NoPatchWindow` | No complete same-block window exists within the search bound. | Move the site, widen the search bound deliberately, or trap. |
| `UnsupportedSemantics` | Supported ISA/ABI cannot preserve this instruction or entry. | Choose a mechanism that preserves this instruction/entry, or refuse it. |
| `AllocationUnavailable` | No permitted mapping satisfies the displacement and resource budget. | Free or widen the permitted mapping budget; do not clobber. |
| `OwnershipConflict` | Another installed patch owns dependent bytes. | Retire or relocate the owning patch first. |
| `SignalContract` | Signal disposition or mask violates the router contract. | Restore the router-compatible disposition/mask, or supply exact host callbacks. |
| `Synchronization` | Instruction-stream synchronization is unavailable or failed. | Provide working sync-core, or use a tactic that does not require it. |
| `Backend` | A bounded lower-level operation failed. | Fix the named lower-level failure; it is carried verbatim for diagnosis. |

### `patcher::PatchError`

Concurrent publication (`patcher`): plan/bind/apply-time refusals of the WordPatch++ path.

| Variant | Trigger | Remedy |
|---|---|---|
| `SiteNotFound` | The requested address is not an instruction head in the scan. | Rescan and pick a real instruction head. |
| `InvalidCodeRegion` | The supplied code region cannot be completely decoded. | Supply the complete, decodable region. |
| `RegionMismatch` | The scan and supplied code region disagree about instruction heads. | Rescan the current bytes; the region changed since the scan. |
| `InstructionTooShort` | The first instruction cannot contain a five-byte direct jump. | Use a pun/relocation tactic for short instructions, or trap. |
| `PatchWindowContainsBranchTarget` | A decoded direct branch can enter the displaced window after its head. | Choose another site; interior entries cannot be displaced safely here. |
| `PatchWindowOutOfRange` | The region does not contain the complete eight-byte patch window. | Supply the complete 8-byte window inside the region. |
| `TargetOutOfRange` | The trampoline cannot be reached by a signed rel32 jump. | Allocate the trampoline within rel32 reach. |
| `AddressNotRepresentable` | An address cannot be represented by the host pointer width. | Run where guest addresses fit host pointers (64-bit host). |
| `UnsupportedCacheLineSize` | Cache-line geometry cannot support aligned atomic front/back words. | Use a host whose cache-line geometry supports aligned words. |
| `GuardByteConflict` | An instruction head already contains the temporary breakpoint opcode. | A head already starts with `0xCC`; pick another site or own that breakpoint. |
| `NullWritableAddress` | The writable alias is null. | Pass the real writable alias. |
| `AliasAlignmentMismatch` | Writable and executable aliases have different cache-line offsets. | Make aliases share cache-line offsets (same backing object). |
| `AddressRangeOverflow` | Address arithmetic overflowed while reserving atomic write words. | Move the site away from the address-space edge. |
| `OverlappingPatchSite` | Another patch owns an incompatible displacement or atomic write envelope. | Serialize or relocate one of the overlapping patches. |
| `Contended` | Registry admission or an overlapping writer is busy. | Retry after the competing writer finishes; contention is reported, not hidden. |
| `ExpectedBytesMismatch` | Live code does not match the state expected by apply or revert. | Re-authenticate live bytes and re-plan; someone changed the site. |
| `QuiescentPublicationRequired` | A quiescent binding was passed to the concurrent publication entrypoint. | Publish through the quiescent entrypoint under a lease instead. |
| `SignalHandlerInstall` | Installing the SIGTRAP guard handler failed. | Resolve the SIGTRAP disposition conflict (custom handler needs host callbacks). |
| `UnsupportedPlatform` | Live patching is unavailable on this target. | Linux x86-64 only for live patching. |

### `rapid::RapidToggleError`

Rapid one-byte toggles (`rapid`): exact-pun planning and install refusals.

| Variant | Trigger | Remedy |
|---|---|---|
| `InvalidCodeRegion` | The code region cannot be decoded completely. | Supply the complete, decodable region. |
| `RegionMismatch` | The supplied scan does not describe the current code region. | Rescan the current bytes. |
| `PatchWindowOutOfRange` | The five-byte pun window is outside the supplied region. | Keep the five-byte window inside the region. |
| `AlreadyNearJump` | The inactive instruction already begins with E9. | Site already starts with `E9`; choose another site or tactic. |
| `TargetOutOfRange` | The original tail bytes imply an unrepresentable destination. | Choose a site whose inherited displacement can name a trampoline. |
| `NullWritableAddress` | The writable opcode alias is null. | Pass the real writable alias. |
| `AliasAlignmentMismatch` | Writable and executable aliases have different cache-line offsets. | Make aliases share cache-line offsets. |
| `PatchWindowContainsInstructionHead` | Another instruction begins inside the five-byte pun window. | Choose a site whose window contains no other head. |
| `PatchWindowContainsBranchTarget` | A decoded direct branch targets the interior of the pun window. | Choose a site no branch targets into. |
| `ExpectedOpcodeMismatch` | The writable alias does not contain the planned inactive opcode. | Re-authenticate the site; its opcode changed since planning. |
| `ExpectedWindowMismatch` | The writable alias does not contain the planned five-byte pun window. | Re-authenticate the whole five-byte window and re-plan. |
| `OverlappingPatchSite` | Another live patch owns part of the five-byte pun window. | Retire or move the owning patch first. |
| `ReservationContended` | Registering process-wide ownership raced an active writer. | Retry once the racing writer finishes. |
| `SignalHandlerInstall` | Installing the process-wide SIGTRAP router failed. | Resolve the SIGTRAP disposition conflict. |
| `Trampoline` | Planning or allocating the exact trampoline failed. | Inspect the wrapped trampoline error below. |
| `UnsupportedPlatform` | Rapid probes are unavailable on this target. | Linux x86-64 only. |

### `scanner::ScanError`

Decoding (`scanner`): why a region could not be scanned at all.

| Variant | Trigger | Remedy |
|---|---|---|
| `PrefixTooShort` | A requested instruction prefix is longer than the available byte window. | Widen the supplied byte window around the site. |
| `AddressRangeOverflow` | The half-open virtual-address range cannot be represented by `u64`. | Move the region away from the u64 edge. |
| `AddressNotRepresentable` | A decoded address cannot be represented as a native pointer. | Use a 64-bit host for these addresses. |
| `UnsupportedCacheLineGeometry` | One instruction would span more than two configured cache lines. | Configure a cache-line size an instruction can span at most twice. |
| `InvalidInstruction` | iced-x86 rejected an instruction encoding. | The bytes at a claimed head do not decode; fix the entry claim. |

### `trampoline::TrampolineError`

Trampoline construction (`trampoline`): planning and allocation refusals before any hook exists.

| Variant | Trigger | Remedy |
|---|---|---|
| `SiteNotFound` | The requested address is not an instruction head in the scan. | Rescan and pick a real instruction head. |
| `InstructionTooShort` | The direct jump cannot displace this instruction by itself. | Use a pun tactic, or displace more instructions. |
| `NotExactSyscall` | The exact-syscall plan requires the literal two-byte `0F 05` instruction. | The exact-syscall plan needs a literal `0F 05`; pick the generic plan otherwise. |
| `ReturnAddressOverflow` | Computing the address after the displaced instruction overflowed. | Move the site away from the address-space edge. |
| `Encoding` | iced-x86 could not encode generated or relocated code. | Report the instruction shape; choose a site whose relocation encodes. |
| `Artifact` | Provisional artifact emission failed a field/provenance/PIC obligation. | Fix the named emission field/provenance obligation. |
| `AddressNotRepresentable` | An address cannot be represented by this process. | Use a 64-bit host process. |
| `InvalidPageSize` | The operating-system page size is unavailable or unsupported. | Run where the OS page size is available and supported. |
| `BackingStore` | Creating or publishing executable backing storage failed. | Fix memfd/mapping permissions for arena backing storage. |
| `ProcessMaps` | Reading or parsing the process memory map failed. | Make `/proc/self/maps` readable and well-formed. |
| `NoReachableMapping` | No free page could be mapped within signed rel32 reach. | Free address space within rel32 reach of the site. |
| `ExactAddressUnavailable` | The exact instruction-pun destination is already occupied or unavailable. | Let placement search choose another exact destination. |
| `InvalidArenaCapacity` | A trampoline arena must contain at least one checked slot. | Request at least one slot. |
| `ControlledArenaUnsupported` | Process-local observing controls cannot be stored in a fork-shared arena. | Use a process-local arena for observing controls. |
| `ArenaFull` | Every slot in a prepared trampoline arena has been reserved. | Allocate a larger arena or retire hooks. |
| `CodeTooLarge` | Emitted code does not fit in its executable allocation. | Shrink the trampoline (fewer saved effects) or enlarge the allocation. |
| `InvalidExtendedStateLayout` | The tracee CPU's enabled standard XSAVE layout cannot be encoded exactly. | Use a CPU whose standard XSAVE layout the encoder covers exactly. |
| `TransitionInProgress` | A hook toggle raced another toggle on the same site. | Serialize toggles of one site; retry after the in-flight toggle. |
| `Patch` | M2 rejected patch planning, binding, or publication. | See the wrapped patcher refusal above. |
| `UnsupportedPlatform` | Trampolines are unavailable on this target. | Linux x86-64 only. |

### `synchronized::SyncPatchError`

Sync-core batches (`patcher::synchronized`): batch-level refusals; every post-store failure is terminal for the handle.

| Variant | Trigger | Remedy |
|---|---|---|
| `Patch` | Existing scan, geometry, signal-route or ownership refusal. | See the wrapped patcher refusal above. |
| `Synchronize` | The prepared synchronization capability failed; no delay substitutes. | Provide a working sync-core capability; no delay substitutes. |
| `UnsupportedInstruction` | The first original instruction is not the entire 5..=8-byte displacement. | Displacement must be exactly the first 5–8-byte instruction; pick another site. |
| `EmptyBatch` | The batch has no members. | Add at least one member. |
| `OverlappingMembers` | Two members duplicate or overlap their actual write envelopes. | Make member write envelopes disjoint. |
| `DifferentProcess` | A binding was inherited from a different process. | Re-bind patches in the publishing process (e.g. after fork). |
| `Aborted` | The transition was already aborted and cannot be resumed. | The handle is dead by design; build a new batch. |
| `IncompleteOperation` | An advance unwound before recording its complete result. | Treat as terminal: state may be partially published; do not resume. |

### `sync_core::SyncCoreError`

Sync-core preparation (`sync_core`): why a synchronization capability could not be prepared.

| Variant | Trigger | Remedy |
|---|---|---|
| `UnsupportedPlatform` | This target has no implemented synchronization backend. | Use a platform with a synchronization backend. |
| `MissingCapability` | The kernel did not advertise both required commands. | Use a kernel advertising both membarrier commands. |
| `SystemCall` | A command failed with the recorded operating-system error. | Fix the recorded syscall failure (permissions/registration) and re-prepare. |
| `UnexpectedResult` | A command that requires zero returned a different value. | Kernel contract violated; do not use this capability handle. |
| `DifferentProcess` | The handle was prepared in a different process, such as a fork parent. | Prepare a fresh handle in the publishing process. |

Specialist families live one layer down and are documented where
they belong rather than duplicated here: offline emission
(`emission::ArtifactRefusalKind`, frame-trace refusals), generated
unwind publication, the offline router's `StartupError`, control-flow
graph construction, the backedge clock, and artifact fixups. Their
common rule is the same as above — a named variant, never a bare
"unsupported".
