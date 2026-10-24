# Standalone core contract, version 1

This is the A0 boundary shared by the core and admission clients. The public
types live in `liteinst2::contracts`; no loader, scheduler, or syscall policy
belongs in this module. Existing `InstalledHook` and `RapidProbe` APIs retain
their existing contracts. This document does not qualify their live publication
protocols for a new application.

* `CodeIdentity` combines an original-content identifier, mapping incarnation,
  and generation. The mapping owner advances the generation before changing
  bytes, aliases, entries, or policy. An address or ELF build ID alone is not
  an identity. Reusing an incarnation/generation pair is forbidden.
* `LegalEntrySet` records identity, scope, provenance, completeness, instruction
  entries, and dynamic resume obligations. Symbols and a linear decode are
  positive evidence only. `AllInstructionHeads` is a caller assertion that no
  overlapping stream is enterable; `Complete` certifies the enumerated set.
  `Incomplete` cannot authorize publication. A mapping owner must account for
  signal frames, syscall returns, parked threads, and nonlocal continuations.
* `PatchPlan` is immutable, inspectable, and contains exact original snapshots,
  source edits, complete dependency ranges, entry obligations, generated images,
  PC maps, allocation requests, profile, and synchronization requirements.
  Constructing or inspecting it does not write executable memory. An unresolved
  obligation refuses publication; requesting a fallback does not install one.
  Version 1 uses bound virtual addresses; ELF load-bias fixups are later work.
* `QuiescenceLease<'a>` borrows an exclusive gate guard. It is neither Send nor
  Sync, cannot be cloned, and is bound to one identity and a dependency set.
  Its unsafe constructor is the admission/rendezvous implementor's proof
  boundary. For its entire lifetime the owner excludes instruction fetches,
  data readers, writers, signal reentry, and uncoordinated aliases, and owns
  every saved continuation into the held ranges. NX alone is insufficient.
  The owner also authenticates the entry facts, source identity, and mappings.
* Publication rechecks identity, dependency coverage, bytes, allocation and
  signal ownership before writing. Generated code and immutable routes precede
  source edits. A success receipt includes the exact plan and generation,
  resolved obligations, and instruction-stream completion. A prewrite failure
  leaves source bytes intact. A postwrite failure poisons the lease: the gate
  must remain held until verified rollback and synchronization, or termination.
  Dropping an error or a poisoned lease does **not** authorize admission.
* `PublicationReceipt` is evidence from a trusted publisher, not an arbitrary
  Boolean. `Publisher` is an unsafe implementation boundary: a mock may only
  certify mock storage. A gate checks receipt identity and dependency coverage
  before admitting that generation. Each publisher has its own installed-handle
  type; receipts alone do not own trampoline or route lifetimes.
* `InstallOnce` exposes no arm/disarm operation. Retirement requires a fresh
  generation-bound lease and draining every executable/saved reference. A
  `ToggleProbe` separately exposes epoch-labelled arm/disarm, visibility
  completion, and close/drain. Raw eventual visibility never means completed
  activation or cancelled in-flight callbacks. A0 defines this interface; A4
  must qualify concrete live toggle implementations against it.

## Initial supported envelope

Linux x86-64, the System V AMD64 callback ABI, and little-endian 64-bit addresses.
Callbacks may not unwind and must honor `HookCallback`'s documented extended
state contract. Architectural equivalence excludes inspection/writes of patched
code and instrumentation-private stack storage below the application red zone.
The client supplies readable/writable mappings, instruction locations, block
and function limits, mapping ownership, and complete legal-entry facts.

A1 requires certified alias ownership and explicitly refuses overlapping
streams, unknown entries/resumes, CET
IBT entry requirements it cannot preserve, unsupported relocation semantics,
allocation exhaustion, and unavailable sync-core. No claim of
transparent signal delivery or DWARF unwinding inside generated code is made:
PC translation is available, and the embedding runtime must provide those
semantics. SIGILL routing admits only an owned, unmasked router and qualifies
the exact illegal encoding; `0x62` alone is not an illegal-instruction proof.
Application SIGILL handlers require a separately qualified embedding contract.

The implementation and its additional concrete restrictions are documented in
`A1-QUIESCENT.md`. These restrictions stay visible as refusals; they are not
successful coverage.
