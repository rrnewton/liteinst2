# Runtime patcher design (W4 next slice, for review before code)

Goal: flip one live `SVC` word to `B` (near island) or `BRK` (trap
fallback) at runtime, stopped-executors first, using only landed
`liteinst-aarch64` emit facts. Non-goals until the Section-5 gate closes
(Arm DDI0487 primary text on concurrent-modifiable membership of
SVC/BRK): no lock-free live flip, no concurrent publication claim, no
foreign-text writes, no BLR x8 path (probe/refuse only).

## Home: new crate `crates/liteinst-aarch64-patch` (accepted in review)

- `liteinst-aarch64` is unconditionally `#![no_std]` +
  `#![forbid(unsafe_code)]` and fact-only ("never execution authority");
  a patcher cannot live there without revoking the reviewed guarantee.
- The `liteinst` core package is documented Linux x86-64 only and its
  tree is x86 machinery; embedding an AArch64 runtime there is the
  arch-split refactor, wrong for a first slice.
- The workspace already separates runtime crates (`liteinst-launch`,
  `liteinst-inprocess`, unpublished `liteinst-jit`) over fact crates. A
  small `std`, AArch64-Linux patch crate containing the unsafe surface
  follows that grain; future core integration can use the same boundary.

Publication: `publish = false` initially (the `liteinst-jit`
precedent). A published patch crate cannot resolve against crates.io
`liteinst-aarch64 0.2.0`, which predates the emit module; workspace
path dependency only until the fact crate version is bumped.

Non-AArch64 surface (x86-64 workspace gates must stay meaningful): the
protocol core — site state machine, flip/rollback transitions, error
taxonomy — compiles and host-tests on every target against fake
store/stop implementations. Island allocation, cache maintenance, and
execution entry points return `PatchError::Unsupported` off AArch64
Linux instead of being cfg'd out of existence, so host tests exercise
the refusal paths too.

## Publication lease and stop contract

There is no per-thread stop. A flip runs only under an **exclusive
publication lease** covering every thread that may execute the site or
the island, the mapping generation of both, and every writer to either.
Thread membership is frozen for the lease duration (no executor may be
created, and a thread that was running the site's code object when the
lease was taken must be accounted in the stopped set). If that cannot
be established, the first slice refuses: it supports only provably
single-executor owned mappings (the test harness shape) and leases
whose `StopControl` proves the full set.

Admitted stop points: no stopped PC may be at the patch site word, or
inside the island during rollback or island drop/retirement. A
self-thread flip must prove the flipping thread executes outside the
affected range for the whole lease (its own code is neither site nor
island). A cooperative park is an acknowledged handshake (parked flag
observed by the flipper, release flag observed by the worker), never a
sleep or a best-effort request.

Resume requires a **context-synchronization acknowledgement from each
consuming thread** after cache maintenance; the patching core's own
ISB does not synchronize another PE. Per implementation: ptrace stops
resume via ptrace continue (exception return is the synchronizing
event, acknowledged by the wait status); a cooperative park executes
an explicit `isb` after observing the release flag and before
re-entering the site, then acknowledges. No thread re-enters the site
until its acknowledgement protocol has run.

## Flip protocol

Invariant: at every instant the site word is either the original `SVC`
(executes and re-traps normally) or the new `B`/`BRK` whose target —
island body for `B`, armed handler registration for `BRK` — is already
published and synced. Never a torn word (one aligned 4-byte store is
single-copy atomic), never a branch to a half-built island, never a
`BRK` without an owned route.

1. **Prepare Branch target (if Branch is permitted).** Build the
   island in its dual RW/RX memfd mapping (`MFD_EXEC` requested;
   `EACCES` under `vm.memfd_noexec=2` removes Branch from the menu for
   this flip, see step 3). Entry starts with the `landing_pad` for its
   reach; body ends branching back to site+4. Placement is the
   caller's `Island` input: the patcher allocates from the offered
   island (or builds one at a caller-provided base) and refuses unless
   `island_reaches` holds in both directions. Near allocation probing
   stays caller policy in this slice.
2. **Prepare Trap target (if Trap may be selected).** The handler
   route — site address, `BRK` immediate, and site generation recorded
   in an owned registration, continuation preserves guest state — must
   be armed and proven owned **before** any write. If it is absent,
   fallback is not available; a flip that would need it refuses with a
   named error before writing. The old `SVC` route (re-trap/emulation
   by the caller's existing machinery) stays armed throughout, since
   executions legitimately observing the original word remain possible
   until the store.
3. **Publish the island** (Branch path): writes complete through the
   RW alias, then dual-alias cache maintenance — clean the written
   range via its RW addresses to the point of unification (`DC CVAU`
   per CTR_EL0 D-line), `DSB ISH`, invalidate via the RX addresses of
   the same range (`IC IVAU` per CTR_EL0 I-line), `DSB ISH`; the
   consuming threads' `ISB` happens under the resume contract above,
   not here. Line rounding and checked range arithmetic are computed
   for both aliases (distinct VAs, same backing). The earlier fixture
   used one address for both operations on a single mapping; this
   design does not promote that recipe — production code takes both
   ranges explicitly.
4. **Acquire the lease** via `StopControl`; all covered threads
   stopped at admitted PCs.
5. **Revalidate identity under the lease:** exact expected original
   word (recorded at `Site` construction, immediate included — a
   changed SVC immediate refuses), site address, mapping generation,
   permissions, and RW/RX shared-backing relation. A plain load
   suffices only because the lease already proves exclusivity; there
   is no CAS substitute for ownership.
6. **Store** the word from `patch_svc` (alignment/range already
   refused there) with one aligned 4-byte store through the RW alias.
   Strategy was chosen at request time: Branch when permitted and an
   island reaches, else Trap when permitted and armed, else refuse in
   step 1/2 — never discovered after the store.
7. **Sync and resume:** clean/invalidate the site line as in step 3,
   then resume each thread through its context-sync acknowledgement.

Failure custody (no state is just "error" after the store):

- Errors before step 6 are no-write: site stays `Unpatched`, lease
  releases, island may drop.
- The instant the store completes the site is `Flipped`, persistently
  recorded before any fallible step runs. Sync failure, lost resume
  acknowledgement, panic, or cancellation after that point transitions
  to `SyncPending`/`RetainedStop`: executable memory, handler
  registration, and stop authority stay alive; the API does not
  auto-resume and nothing unmaps. Recovery is an explicit
  `complete_sync`/`resume` retry from that state.
- Rollback (`rollback()`, only from `Flipped` under a fresh lease)
  re-stores the retained original word, syncs the restored site the
  same way, and retires the island only after proving no stopped PC
  and no in-flight or parked executor can still enter it. Slice 1
  chooses **permanent island retention until session teardown** after
  any rollback uncertainty, and says so here: retirement is deferred,
  never optimistic.
- `Drop` never unmaps an island or deregisters a trap route that a
  `Flipped` site still references; dropping a `Flipped` site without
  rollback leaks the island deliberately (documented, bounded by the
  session) rather than risk a live branch into unmapped memory.

## API and unsafe contracts (complete surface)

- `unsafe fn Site::from_aliases(rx_addr, rw_alias, original_word,
  generation)`: caller guarantees both aliases name the same physical
  word in one shared backing that outlives the site and any flip, the
  RX word initially equals `original_word`, and no other live `Site`
  or writer names this address. Fields are private; there is no safe
  constructor from integers. A patcher-side registry keyed by site
  address refuses a second live `Site` for the same word as a second
  line of defence (it detects, but cannot by itself prove, duplicates
  constructed outside the patcher — hence unsafe construction).
- `unsafe trait StopControl`: implementors guarantee the lease scope
  (every possible executor of site/island, frozen membership, mapping
  and writer exclusivity), admitted stop points, and per-thread
  context-sync on resume as defined above. Safe wrappers may exist
  only where the guarantee is structural (single-threaded harness).
- `flip(&mut self, site: &mut Site, request: FlipRequest, stop: &mut dyn StopControl)`
  with `FlipRequest { island: Option<&Island>, strategy:
  StrategyPreference (BranchOnly | TrapOnly | BranchThenTrap),
  brk_imm: u16, fallback: FallbackPermission }` — every protocol input
  is explicit; `PatchError` distinguishes pre-store refusals from
  post-store custody states and never reports post-store failure as
  "not flipped".
- Cache-op availability is an explicit environment precondition (EL0
  `DC CVAU`/`IC IVAU` permitted), plus an optional
  `probe_environment()` that forks a child performing the ops on its
  own buffer and reports `Unsupported` if the child dies by signal —
  detection that cannot kill the calling process. A same-core
  self-test alone never proves cross-core acknowledgement.

## Test plan

- Host (all targets): state-machine and refusal tests against fake
  store/stop: stop failure, stale word/mapping/generation, lost resume
  acknowledgement, sync failure after the store, rollback after failed
  sync, Drop in `Flipped`/`SyncPending` — each asserting retained
  custody, no resume, no unmap, not merely an `Err`. Second-executor
  negative (lease refuses an unaccounted executor) and duplicate-site
  negative (registry refusal). Mutants omitting the store, either
  barrier, or the acknowledgement must fail.
- AArch64 execution (`tests/`, target-gated): distinct RW/RX aliases
  throughout; a separately scheduled consuming thread with explicit
  sync acknowledgement (cooperative park + `isb` handshake) for
  SVC->B, SVC->BRK with owned handler, and rollback + delayed
  retirement; original-SVC behavior proven before the flip on the same
  stub. The existing single-thread fixture shapes remain positive
  controls, not concurrent-publication evidence. Run on 64 KiB metal
  and in the 4 KiB guest (same static-binary route); page size from
  `sysconf`, asserted never assumed.

Slices: (1) this note; (2) crate skeleton + cache/island RAII + host
state-machine tests; (3) flip/rollback protocol + execution proofs;
(4) trap-route registration + receipts. Signed local commits; push
only on museli-lt word.

Open gates carried forward: DDI0487 concurrent-modifiable primary
text (unlocks any non-stopped flip), `PROT_BTI` guarded-mapping
policy, foreign-text write channel, Hermit-backend EL0 cache-op
trapping behavior.
