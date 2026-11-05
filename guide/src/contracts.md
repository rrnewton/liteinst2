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
from a trusted publisher, not a boolean you can fabricate; gates check
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

`InstallOnce` exposes no arm/disarm operation; retirement requires a
fresh generation-bound lease and draining every executable and saved
reference. `ToggleProbe` separately exposes epoch-labelled arm/disarm
with visibility completion and close/drain. Raw eventual visibility
never means "activation completed" or "in-flight callbacks cancelled" —
if your logic needs those guarantees, wait for the completion the API
names.

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
> 🚧 **Under construction — composition depth.** TODO: expand the
> composition section with the bundle transaction lifecycle once the
> tactic-engine remainder noted in `A2-COMPOSITION.md` lands; today
> this section describes the staging model only.
> <!-- UC: contracts-composition -->
> Tracking: [liteinst2#38](https://github.com/rrnewton/liteinst2/issues/38) (`contracts-composition`).
