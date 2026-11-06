# Plans, leases, and receipts

LiteInst separates *deciding* a patch from *doing* it. Three types
carry that separation, and understanding them explains most of the
API's shape — including why so much of it is `unsafe` in small,
well-marked places rather than vaguely dangerous everywhere.

## Plans are pure

A `PatchPlan` is immutable and inspectable: exact original snapshots,
source edits, dependency ranges, entry obligations, generated images,
PC maps, allocation requests, and synchronization requirements.
Constructing or inspecting a plan writes no executable memory. An
unresolved obligation refuses publication, and requesting a fallback
does not install one.

Identity is part of the plan. A `CodeIdentity` combines an
original-content identifier, a mapping incarnation, and a generation.
The mapping owner advances the generation before changing bytes,
aliases, entries, or policy. An address or an ELF build ID alone is
not an identity — the same address can hold different code tomorrow,
and the plan must notice.

## Leases are proofs

A `QuiescenceLease` borrows an exclusive gate guard. It is neither
`Send` nor `Sync`, cannot be cloned, and is bound to one identity and
dependency set. Its `unsafe` constructor is the point where the caller
asserts: *for this lease's entire lifetime, I exclude instruction
fetches, data readers, writers, signal re-entry, and uncoordinated
aliases over these ranges, and I own every saved continuation into
them.* NX permissions alone do not establish that.

This is the library's answer to "who proves the program is still?" —
you do, at exactly one marked boundary, instead of the library
pretending to know.

## Receipts are evidence

Publication re-checks identity, dependency coverage, bytes, allocation,
and signal ownership before writing. Generated code and immutable
routes precede source edits. On success you receive a
`PublicationReceipt`: the exact plan and generation, the resolved
obligations, and instruction-stream completion. A receipt is evidence
from a trusted publisher — its constructor is `pub unsafe fn completed`,
so fabricating one is an explicit unsafe act by a would-be publisher,
not something a boolean can drift into; gates check
receipt identity and coverage before admitting that generation.

Failure is typed by timing:

* A **pre-write** failure leaves source bytes intact. Nothing happened;
  fix the plan and retry.
* A **post-write** failure *poisons* the lease: the gate must stay held
  until verified rollback and synchronization, or termination.
  Dropping the error — or the poisoned lease — does not authorize
  admission. This asymmetry is deliberate: after a partial write, "just
  continue" is how instrumentation corrupts programs.

## Lifetimes: install-once vs toggle

The `ApplicationProfile::InstallOnce` profile has no arm/disarm
operation; retirement requires a fresh generation-bound lease and
draining every executable and saved reference. The `ToggleProbe`
*trait* separately defines epoch-labelled arm/disarm with visibility
completion and close/drain. Raw eventual visibility never means
"activation completed" or "in-flight callbacks cancelled" — if your
logic needs those guarantees, wait for the completion the API names.
(These are the contract-layer profiles; the concrete `InstalledHook`
of [your first hook](first-hook.md) has the simpler
inactive → `activate()` → `deactivate()` lifecycle.)

## Composition

Real clients patch many sites across several generated images. The
`composition` and `bundle` modules build ordered virtual source images
with persistent byte locks and quiescent transactions spanning them:
staging, aggregate allocation limits, and retirement are transactional
rather than site-by-site improvisation.

> 🚧 **Under construction — plan inspection walkthrough.** TODO: a
> worked example that builds a plan, prints its obligations, forces
> each refusal kind (stale generation, uncovered dependency, interior
> entry), and publishes — as a doctest-grade listing.
> <!-- UC: contracts-walkthrough -->
> Tracking: [liteinst2#38](https://github.com/rrnewton/liteinst2/issues/38) (`contracts-walkthrough`).
>
### The bundle transaction lifecycle

`PlannedBundle` (`bundle` module) is that transaction as a value,
in five phases with different failure meanings:

1. **Compose** (`compose` / `compose_grouped`) is pure — no store
   has happened, so every refusal here is free. Members are
   `PlannedInstall` values from the tactic engine, never arbitrary
   structural `PatchPlan`s: this constructor is the only way in.
   Composition is *order-explicit* and *overlay-checked*: each
   member must have been planned against the bytes the preceding
   members produce, so a member planned against stale originals is
   refused even if its own writes are disjoint — replan it against
   the overlay. Grouping (`compose_grouped`) additionally seals
   images into immutable shared backing; sharing reduces *backing*
   bytes only, never virtual charges.
2. **Budget** is checked at composition, not publication:
   `BundleBudget` caps steps, mappings, virtual bytes, backing
   bytes, and total span, and `plan().memory()` reports the exact
   accounting (backing pages counted once across aliases) before
   anything is staged.
3. **Publish** (`publish` / `publish_with`, unsafe) stages
   *everything* before the first source store: lease and identity
   checks, host qualification, alias overlap and snapshot
   authentication, lock reservations, executable images, and entry
   routes. Only then does it poison the lease, write every source
   store, run the caller's permission finalizer, and issue one
   sync-core for the whole transaction. The failure type splits at
   exactly that boundary: `FailureStage::BeforeWrite` means nothing
   was published and a corrected transaction may retry;
   `FailureStage::KeepGated` means stores may have happened — the
   whole transaction stays behind the poisoned lease, permanently
   gated, and there is no resume.
4. **Installed** is deliberately boring: an `InstalledBundle` is
   permanently active (no arm/disarm sampling), owns its source
   writes, consumed pun bytes, store padding, routes, and
   trampolines, and its `BundleReceipt` — issued only after every
   store, permission operation, and the sync — names the exact
   completed `BundlePlan`, originals and final bytes included.
   Dropping the handle discharges nothing.
5. **Retire** (`retire` / `retire_with`, unsafe) is the mirror
   transaction: re-check the plan against a fresh lease (which must
   also cover the generated allocations), authenticate the *final*
   bytes, restore every store in reverse order, finalize
   permissions, one sync-core, deactivate routes, release
   reservations. A post-store failure is again `KeepGated` — never
   a half-restored bundle left executing. Retirement releases
   source ownership; generated code and metadata remain
   process-lifetime.

What this does not claim: the full A2 exit gate (enabled
IBT/shadow-stack fixtures, an Intel cross-check of the supported
subset) is still open in `A2-COMPOSITION.md`, and concurrent
toggle visibility remains A4 work. The lifecycle above is the
landed install-once transaction, no more and no less.
