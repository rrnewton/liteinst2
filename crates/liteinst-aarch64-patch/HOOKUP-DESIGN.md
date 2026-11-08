# Patcher hookup design (W3 S5b lazy trap-and-patch, for musearch)

Status: implemented in slice S5b (patch-crate seam on musearm2/arm-patcher-s5b-20261106; promoter in reverie-liteinst on the S5a stack). This note remains the contract; amendments from the coord7 Opus reviews are folded below. Inputs:
musearm1's S5b note (sha256 74cd5525…), musearm2's Q1–Q8 answers via
museli-lt, and the landed patcher design/slices 2–3 contracts.
Musearch's S5.2 decision, dispatched through museli-lt, is canonical:

> Promoted execution must be guest-visibly identical to the trap path
> (same syscall result, register, and memory effects), under Android
> platform constraints (W^X/SELinux, memfd exec policy, 16 KiB pages),
> with platform-policy denials degrading to permanent trap execution --
> never to policy circumvention.

The strategy matrix is owned by selection cells outside patcher code:

| Environment | Trap | SudTrap | TrapAndPatch | PatchEager |
|---|---|---|---|---|
| Linux userland | yes | x86_64-only, probed | yes; lazy default | where census is complete |
| Wine in-process | yes | refused | only FEX-JIT-excluded ranges; unknown ranges pass through unpatched | refused in v1 |
| Android app sandbox | yes | refused by name | only where a memfd dual mapping passes the execmem probe; otherwise permanent Trap | refused in v1 |

The patcher does not classify the environment, choose among Trap,
SudTrap, TrapAndPatch, or PatchEager, or encode this matrix. Its
`StrategyPreference` is the narrower choice a selector hands to an
already-selected TrapAndPatch operation: branch-island word, BRK trap
word, or branch with trap fallback. Selector cells supply the site set,
checkpoint, and platform-policy outcome; the patcher either executes the
bounded flip contract or refuses it without trying to bypass a denial.

## What is being hooked up

First trap at an AArch64 SVC site forwards normally (W3 S5a, landed).
A downstream promoter, called explicitly at a deterministic
ordinary-context checkpoint, drains FIFO pending addresses (ownership
transfer), qualifies each site's mapping, builds a two-word island
`[original SVC, B resume]`, and flips the site `SVC -> B island` with
the landed `Patcher::flip`. NOTE: the current island shape re-runs
the SVC, so later calls still trap once per call at the island;
this slice buys custody/plumbing, not trap avoidance (island
ranges are denylisted in S5a's pending table so those re-traps
consume no slots). An island entering dispatch directly is
future work. Branch only in
hookup slice 1; BRK fallback, far veneers, eager scanning, and handler-
context draining stay out (prior design non-goals carry over).

## API additions this requires (patch crate, slice H1)

1. A foreign-text construction path alongside today's managed one:
   `unsafe Site::from_rx(rx_addr, original_word, facts, store)`, where
   `store: Box<dyn SiteStore>` is the seam in item 3. Reads always use
   the RX address. The existing `from_aliases` remains for managed
   mappings and constructs the shipped dual-alias store internally; no
   generic parameter is added to `Site`.
2. `MappingFacts { page_span: (u64,u64), orig_prot: i32, provenance:
   Provenance, generation: u64, bti: bool }` (bti from smaps VmFlags) with `Provenance::{PrivateFile,
   PrivateAnon, Shared, Unknown}` and `qualify_mapping(addr)` parsing
   one gated `/proc/self/smaps` read (perms, pathname, VmFlags) (promoter ordinary context only). Refusals are
   named before construction: `PatchError::MappingRefused` for shared,
   unaligned, non-executable, or indeterminate mappings. `Site`
   stores the facts; flip refuses a generation mismatch when fresh
   facts are presented. (The `requalify` mutator was deleted in
   review: it could not update the store's captured span, so a
   generation advance constructs a fresh site against fresh facts
   qualified under the lease.)
3. Store seam: an `unsafe trait SiteStore` defined by the patch crate
   and implemented by reverie-liteinst for foreign text (owner
   correction: hookup builds inside reverie-liteinst, consuming this
   crate as its library; the patch crate ships only the `DualAlias`
   impl). `Site` holds `Box<dyn SiteStore>`; the trait contract
   mirrors `StopControl` (the store must name the same physical word
   the CPU executes at the site RX address for the qualified
   generation). Surface as built: `begin_write` / `store_word` / `finish_write`
   on the store itself (no guard type): mprotect minimal page
   span -> RWX recording exact original protections (incl. BTI);
   /proc/self/mem store: one pwrite64 of 4 bytes, partial writes
   are errors, never retried blindly; finish restores exact
   protections and is idempotent, as is begin. Musearch settles the transition:
   reuse `SyncPending`, with no restore-specific variant. In patcher
   terms, issuing the store records `SyncPending` with its pending
   word; only sync **and** protection restore succeeding (followed by
   the existing acknowledged resume) settles `Flipped` — the
   selection layer's Promoted outcome. If either sync or restore
   fails, the new word may be live and protections may be unrestored,
   so resume is forbidden and the site remains `SyncPending` (or
   `RetainedStop` on the existing partial-resume path). The only exits
   are a successful `complete_sync` retry — which must retry any
   outstanding restore as part of completion — or session abort. Try order: mprotect window first. A refused window (including
   platform-policy errnos: MDWE/SELinux execmem, W^X filters)
   means Refused with the site left trapping — never a fallback
   triggered by the refusal itself. The /proc/self/mem store may
   be selected only by explicit selector permission
   (StoreFallback::AllowProcMem), never as an errno-triggered
   bypass. (process_vm_writev was deleted: it cannot write R-X
   text on any architecture.) Fork guard: `Patcher` records `getpid()` at
   construction; flip/rollback/complete_sync refuse
   `PatchError::ForkedRegistry` on mismatch (existing flipped sites
   keep executing in the child; nobody rolls back there).
4. Emit facts: `svc_island_words(original, site, entry) ->
   Option<[u32; 2]>` plus a padded variant, in `liteinst-aarch64`
   (pure, host-tested). Downstream composes nothing from constants.
5. Nothing in the flip order changes: strategy pre-decided, island
   published while unreachable, lease, exact-word revalidation,
   custody transfer, one store, sync, acknowledged resume. The only
   new wrinkle is the mprotect window living inside that lease,
   spanning step "store..sync", restored before resume.

## Promoter placement and ownership (settled by owner correction)

PROMOTER = the draining/checkpoint object, living **inside the
reverie-liteinst AArch64 implementation** (the LiteInst in-process
backend; integration owner musepage), which also implements the
foreign `SiteStore` backends against its own mapping census. The
patch crate keeps the mechanism types, the `SiteStore` trait, and the
`DualAlias` impl. Arena status AS BUILT: there is no entry arena pool yet — the
promoter allocates one memfd island per flipped site, retained
for process lifetime (fd closed at reserve). The pooled-arena
geometry below remains the sizing plan for the follow-up, not
shipped behavior: one page = 256 entries at 16 B (4 KiB) / 1024
(16 KiB Android pages — page size is always queried); config cap
on arenas, exhaustion leaves sites trapped. Retirement stays
session-permanent; rollback reuses the site's retained entry.
Fork sealing of a future shared pool is likewise future work.

Determinism: shape A only for hookup slice 1 — flip eligibility is a
function of recorded first-trap order + checkpoint order + recorded
pool capacity. Shape B (scheduler-lock lease) is named in the
`StopControl` contract for whoever's backend proves it; the proof
obligations are already enumerated in the landed design note.

## Android correctness constraints to encode as refusals, not hopes

- W^X/SELinux: app-domain processes commonly cannot turn writable
  pages executable or vice versa, and `PROT_EXEC` memfd may be denied
  (never-execmem policies, `vm.memfd_noexec`). Per the matrix, the
  Android selection cell admits TrapAndPatch only where its memfd
  dual-mapping execmem probe passes; SudTrap is refused by name and
  PatchEager is refused in v1. Otherwise the outcome is permanent
  Trap, which is correct execution rather than an error path. No
  fallback may attempt to defeat platform policy, and the patcher does
  not perform the environment classification or probe itself.
- `mprotect` on linker/shared-library text: only `MAP_PRIVATE` text is
  ever windowed (COW keeps the file and other processes untouched);
  `MAP_SHARED` (incl. some Android shared RELRO-adjacent mappings) is
  refused by name. Sites in the runtime's own gate/handler text are
  additionally refused by promoter policy (denylist by mapping
  provenance), matching musearm1's non-goal.
- 16 KiB-page Android devices: page span of the mprotect window and
  arena geometry derive from the queried runtime page size only (AT_PAGESZ).
- Existing filters: the trap source is W3's own seccomp filter;
  promotion never installs/uninstalls filters and never runs inside
  the SIGSYS handler.

## Proof shape (slice H1, after this note is accepted)

Patch-crate mechanics proof in `liteinst-aarch64-patch/tests/` (store
seam against test-local backings), then the linked lazy-promotion
proof in reverie-liteinst's own tests once its foreign store lands:
one SVC helper trapped once, promoted at an ordinary checkpoint via
the mprotect backend, then: first result forwarded, results/register
effects identical across repeats (each repeat traps at the island
SVC with the current island shape), site word
is the expected branch, protections restored byte-exact (per maps),
rollback returns to the trap path. Controls: shared-mapping and
out-of-range sites stay trapped; the proc-mem backend (where the
selector permits it) repeats the happy
path, plus injected sync-failure and restore-failure
cases proving `SyncPending`, forbidden resume, and retry-to-settle.
Same static-binary metal (64 KiB) + guest (4 KiB) route as prior
slices; 16 KiB geometry covered by host unit tests until a 16 KiB
guest exists.

Musearch's two routed questions are closed above: §5.2 and its matrix
are canonical as quoted, and restore failure reuses `SyncPending`
with no new variant. Remaining work is routing/implementation, not a
design decision in this note.
