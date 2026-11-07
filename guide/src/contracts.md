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

### Project stage: two sites, one bundle

The [first-hook project](first-hook.md) grows here — and changes
publication model as it does. Two copies of its six-byte body
(`xor eax,eax; inc eax; nop; ret`, no padding) sit in one
dual-mapped page. Each is planned as an install-once,
relocation-only `PlannedInstall`; both are composed into one
`PlannedBundle`, published under one lease, and retired as one
transaction. There is no `activate()`/`deactivate()` pair:
an `InstalledBundle` is permanently active until retired. The
callbacks only count, so both functions return 1 before, during,
and after the bundle — what changes is whether their counters move.

Listing FH-5 is the member construction. Both members share one
`CodeIdentity` for the page generation and plan against their
own six-byte ranges. The entry claim is deliberately narrow:
a closed body whose sole external entry is its first byte, with
no saved continuations. Interior instruction heads are reached
only by fallthrough inside that closed body. Generated placement
is pinned to a distinct one-page range per member, so the two
images are disjoint by construction rather than by search luck.

<span class="filename">Listing FH-5: plan each body as one bundle member</span>

```rust,ignore
    /// The first-hook function without its padding: return 1.
    pub const BODY: [u8; 6] = [0x31, 0xC0, 0xFF, 0xC0, 0x90, 0xC3];
    pub const OFFSETS: [usize; 2] = [128, 640];

    pub static FIRST_CALLBACKS: AtomicU64 = AtomicU64::new(0);
    pub static SECOND_CALLBACKS: AtomicU64 = AtomicU64::new(0);

    unsafe extern "C" fn record_first(_context: *mut HookContext) {
        FIRST_CALLBACKS.fetch_add(1, Ordering::Relaxed);
    }

    unsafe extern "C" fn record_second(_context: *mut HookContext) {
        SECOND_CALLBACKS.fetch_add(1, Ordering::Relaxed);
    }

    fn identity(mapping: &DualMapping) -> CodeIdentity {
        CodeIdentity {
            source: SourceIdentity([0xB0; 32]),
            mapping: mapping.executable_address(0),
            generation: 1,
        }
    }

    fn body_range(mapping: &DualMapping, body: usize) -> AddressRange {
        AddressRange::new(mapping.executable_address(OFFSETS[body]), BODY.len())
            .expect("body range is nonempty")
    }

    fn allocation(mapping: &DualMapping, body: usize) -> AllocationPolicy {
        let pc = mapping.executable_address(OFFSETS[body]);
        let target = mapping
            .executable_address(0)
            .checked_add(0x0400_0000 + body as u64 * 0x0010_0000)
            .expect("generated-image target is in range");
        let mut allocation = AllocationPolicy::near(pc).expect("near allocation policy");
        allocation.preferred_address = Some(target);
        allocation.ranges = vec![
            AddressRange::new(target, PAGE_BYTES).expect("generated-image page is nonempty"),
        ];
        allocation.max_candidates = 1;
        allocation.max_mapped_bytes = PAGE_BYTES;
        allocation
    }

    fn member(
        mapping: &DualMapping,
        identity: CodeIdentity,
        body: usize,
        hook: HookCallback,
    ) -> PlannedInstall {
        let range = body_range(mapping, body);
        let entries = LegalEntrySet {
            identity,
            scope: range,
            provenance: EntryProvenance::Declared(
                "closed six-byte proof function; sole external entry".into(),
            ),
            completeness: EntryCompleteness::Complete,
            entries: vec![LegalEntry {
                address: range.start(),
                requires_endbr: false,
            }],
            resumes: ResumeObligation::NoneExist,
        };
        let allocation = allocation(mapping, body);
        plan_install(&InstallRequest {
            identity,
            code: &BODY,
            base_address: range.start(),
            function: range,
            block: range,
            logical_pc: range.start(),
            entries: &entries,
            hook,
            semantics: HookSemantics::Observe,
            allocation: &allocation,
            search: SearchPolicy {
                tactics: TacticPolicy::RelocationOnly,
                max_upstream_bytes: 0,
                max_displaced_bytes: 5,
                max_sites: 1,
            },
        })
        .expect("each proof body plans as a relocation")
    }
```

Composition is where “two hooks” becomes one transaction.
The two members are disjoint, so neither needs replanning
against the other's edits; `compose` still authenticates each
step against the preceding virtual overlay, and both originals
stay byte-exact until publication. Publication holds one lease
over the whole source page and one `WritableAlias` for it.
The lease is not a formality in this code: the proof process is
single-threaded, owns both aliases, and calls neither body while
either lease is held. Retirement takes a *fresh* lease that also
covers every generated allocation, because generated code and
saved references must drain too — not only the source bytes.

<span class="filename">Listing FH-6: compose, publish, retire as one transaction</span>

```rust,ignore
    /// Writes two copies of the first-hook body, plans each one
    /// independently, and composes both members before any source store.
    pub fn compose(mapping: &DualMapping) -> PlannedBundle {
        for offset in OFFSETS {
            mapping.write(offset, &BODY);
        }
        let identity = identity(mapping);
        let members = vec![
            member(mapping, identity, 0, record_first),
            member(mapping, identity, 1, record_second),
        ];
        let originals = OFFSETS
            .iter()
            .map(|&offset| ExpectedBytes {
                address: mapping.executable_address(offset),
                bytes: BODY.to_vec(),
            })
            .collect();
        PlannedBundle::compose(originals, members, BundleBudget::default())
            .expect("two disjoint members compose")
    }

    /// Publishes both members as one transaction under a caller-held lease.
    pub fn publish(
        mapping: &DualMapping,
        bundle: &PlannedBundle,
    ) -> (InstalledBundle, BundleReceipt) {
        let page = AddressRange::new(mapping.executable_address(0), PAGE_BYTES)
            .expect("page range is nonempty");
        let mut guard = ();
        // SAFETY: this proof process is single-threaded, exclusively owns
        // both aliases, and admits no call into either body while the
        // lease is held.
        let mut lease = unsafe { QuiescenceLease::new(&mut guard, identity(mapping), vec![page]) };
        // SAFETY: the writable pointer is the same memfd page at the same
        // offsets as the executable alias and remains mapped for the
        // process lifetime.
        let alias = unsafe { WritableAlias::new(page, mapping.writable_address(0)) }
            .expect("page alias is in range");
        // SAFETY: the lease above supplies the exclusion this proof owns;
        // final RX permissions were established when the mapping was made.
        let installed = unsafe { bundle.publish(&[alias], &mut lease) }
            .expect("bundle publication succeeds");
        assert!(!lease.is_poisoned());
        installed
    }

    /// Retires both members under a fresh lease covering the source page
    /// and every generated allocation named by the installed plan.
    pub fn retire(mapping: &DualMapping, installed: &mut InstalledBundle) {
        let page = AddressRange::new(mapping.executable_address(0), PAGE_BYTES)
            .expect("page range is nonempty");
        let mut held = vec![page];
        held.extend(
            installed
                .plan()
                .steps()
                .iter()
                .flat_map(|step| step.parts().allocations.iter().map(|a| a.range)),
        );
        let mut guard = ();
        // SAFETY: the same single-threaded exclusion as publication, now
        // extended to every generated allocation that must drain.
        let mut lease = unsafe { QuiescenceLease::new(&mut guard, identity(mapping), held) };
        // SAFETY: no call is admitted during retirement and the original
        // aliases remain writable and mapped.
        unsafe { installed.retire(&mut lease) }.expect("bundle retirement succeeds");
        assert!(!lease.is_poisoned());
        assert!(installed.is_retired());
    }
```

The acceptance run is deliberately plain (1 test, with the
rapid stage's 2 tests as regression): both bodies return 1 with
zero callbacks before publication; after the one publish, each
call moves only its own counter; after the one retire, both
six-byte ranges are byte-identical to `BODY` again and the
counters stop. That is the observable difference between two
independent installs and one bundle — composition, publication,
and retirement each succeed or refuse for the transaction as
a whole, and a post-write failure would leave the whole bundle
`KeepGated`, never half of it executing.
