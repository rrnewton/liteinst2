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

## Worked example: inspect, refuse, publish

Listing CT-1 builds the smallest interesting plan — an install-once
relocation over eight authenticated bytes — and a mock publisher
over eight bytes of ordinary memory. The publisher is deliberately
a mock: a `PublicationReceipt` from it certifies *mock storage
only*, which is exactly the honesty the receipt type is designed to
make explicit.

<span class="filename">Listing CT-1: src/main.rs (`liteinst` only; part 1)</span>

```rust,ignore
use liteinst::contracts::*;

fn identity() -> CodeIdentity {
    CodeIdentity {
        source: SourceIdentity([7; 32]),
        mapping: 3,
        generation: 4,
    }
}

fn parts() -> PlanParts {
    let scope = AddressRange::new(0x1000, 8).unwrap();
    PlanParts {
        identity: identity(),
        profile: ApplicationProfile::InstallOnce,
        kind: PlanKind::Relocation,
        logical_pc: 0x1000,
        physical_pc: 0x1000,
        displaced: scope,
        reads: vec![ExpectedBytes {
            address: 0x1000,
            bytes: vec![0x90; 8],
        }],
        writes: vec![ByteEdit {
            address: 0x1000,
            bytes: vec![0x41; 8],
        }],
        dependencies: vec![scope],
        entries: LegalEntrySet {
            identity: identity(),
            scope,
            provenance: EntryProvenance::Declared("walkthrough fixture".into()),
            completeness: EntryCompleteness::Complete,
            entries: vec![LegalEntry {
                address: 0x1000,
                requires_endbr: false,
            }],
            resumes: ResumeObligation::NoneExist,
        },
        obligations: vec![EntryObligation::Preserved(0x1000)],
        allocations: vec![],
        generated: vec![],
        requirements: PublicationRequirements {
            quiescent: true,
            sync_core: true,
            sigill_router: false,
        },
    }
}

/// A publisher over eight bytes of mock storage at 0x1000. It honours
/// the contract for that storage only: check the lease, authenticate
/// every expected byte, apply the edits, then issue the receipt.
struct MockPublisher {
    storage: [u8; 8],
}

// SAFETY: this implementation checks the lease and expected bytes
// before its only writes, which touch mock storage it owns.
unsafe impl Publisher for MockPublisher {
    type Installed = ();

    fn publish_quiescent(
        &mut self,
        plan: &PatchPlan,
        lease: &mut QuiescenceLease<'_>,
    ) -> Result<(Self::Installed, PublicationReceipt), PublicationFailure> {
        lease.check(plan).map_err(|reason| PublicationFailure {
            reason,
            stage: FailureStage::BeforeWrite,
        })?;
        for read in &plan.parts().reads {
            let offset = (read.address - 0x1000) as usize;
            if self.storage[offset..offset + read.bytes.len()] != read.bytes {
                return Err(PublicationFailure {
                    reason: Refusal::ExpectedBytesChanged,
                    stage: FailureStage::BeforeWrite,
                });
            }
        }
        for edit in &plan.parts().writes {
            let offset = (edit.address - 0x1000) as usize;
            self.storage[offset..offset + edit.bytes.len()].copy_from_slice(&edit.bytes);
        }
        // SAFETY: every edit above was applied to the mock storage this
        // receipt certifies, under the held lease, for this identity.
        let receipt = unsafe { PublicationReceipt::completed(plan.clone()) };
        Ok(((), receipt))
    }
}

```

Listing CT-2 drives it: print the plan's obligation surface, force
the three refusal kinds this chapter names, then publish the
accepted plan. Note where each refusal fires — stale generation and
uncovered dependency are *structural* (`checked` refuses to build
the plan), while the interior entry is *semantic* (the plan builds,
then `check_entry_obligations` refuses it). That split is the
contract working as designed.

<span class="filename">Listing CT-2: src/main.rs (part 2)</span>

```rust,ignore
fn main() {
    let plan = PatchPlan::checked(parts()).expect("fixture plan is structural");
    let p = plan.parts();
    println!(
        "plan: identity mapping={} generation={} displaced={:#x}..{:#x}",
        p.identity.mapping,
        p.identity.generation,
        p.displaced.start(),
        p.displaced.end()
    );
    println!(
        "reads={} writes={} dependencies={} allocations={} generated={}",
        p.reads.len(),
        p.writes.len(),
        p.dependencies.len(),
        p.allocations.len(),
        p.generated.len()
    );
    println!("obligations: {:?}", p.obligations);
    plan.check_entry_obligations()
        .expect("entry obligations resolved");
    println!("entry obligations: resolved");

    // Refusal 1: the entry facts belong to the next generation.
    let mut stale = parts();
    stale.entries.identity.generation += 1;
    println!("stale generation -> {:?}", PatchPlan::checked(stale));

    // Refusal 2: one write escapes every held dependency range.
    let mut uncovered = parts();
    uncovered.writes[0].address += 8;
    println!(
        "uncovered dependency -> {:?}",
        PatchPlan::checked(uncovered)
    );

    // Refusal 3: an entry inside the displaced bytes is unresolved.
    // checked() accepts the structure; the obligation check refuses.
    let mut interior = parts();
    interior.obligations.push(EntryObligation::Unresolved {
        address: Some(0x1003),
        reason: "interior entry inside displaced bytes".into(),
    });
    let interior = PatchPlan::checked(interior).expect("structure still checks");
    println!("interior entry -> {:?}", interior.check_entry_obligations());

    // Publish the accepted plan into mock storage under a lease.
    let mut guard = ();
    // SAFETY: mock storage facts only; no live memory is published.
    let mut lease =
        unsafe { QuiescenceLease::new(&mut guard, identity(), plan.parts().dependencies.clone()) };
    let mut publisher = MockPublisher { storage: [0x90; 8] };
    let (_installed, receipt) = publisher
        .publish_quiescent(&plan, &mut lease)
        .expect("mock publication succeeds");
    println!(
        "published: receipt generation={} storage={:02x?}",
        receipt.plan().parts().identity.generation,
        publisher.storage
    );
}
```

Exact output:

```text
plan: identity mapping=3 generation=4 displaced=0x1000..0x1008
reads=1 writes=1 dependencies=1 allocations=0 generated=0
obligations: [Preserved(4096)]
entry obligations: resolved
stale generation -> Err(StaleGeneration)
uncovered dependency -> Err(DependencyNotHeld)
interior entry -> Err(UnresolvedEntry)
published: receipt generation=4 storage=[41, 41, 41, 41, 41, 41, 41, 41]
```
>
> 🚧 **Under construction — composition depth.** TODO: expand the
> composition section with the bundle transaction lifecycle once the
> tactic-engine remainder noted in `A2-COMPOSITION.md` lands; today
> this section describes the staging model only.
> <!-- UC: contracts-composition -->
> Tracking: [liteinst2#38](https://github.com/rrnewton/liteinst2/issues/38) (`contracts-composition`).
