//! Versioned, policy-free boundary between planning, publication, and admission.
//!
//! See `INTERFACES.md` for the ownership and supported-platform contract.

use std::marker::PhantomData;
use std::rc::Rc;

/// Version of the in-memory standalone interface (not a serialized ABI).
pub const CONTRACT_VERSION: u32 = 1;

/// Original content and policy identity supplied by the mapping owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SourceIdentity(pub [u8; 32]);

/// One non-reusable mapping incarnation and byte/entry-policy generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct CodeIdentity {
    /// Authenticated original content and policy.
    pub source: SourceIdentity,
    /// Unique mapping incarnation, changed on address reuse.
    pub mapping: u64,
    /// Monotonically advancing generation within that incarnation.
    pub generation: u64,
}

/// Nonempty, checked half-open virtual address range.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct AddressRange {
    start: u64,
    end: u64,
}

impl AddressRange {
    /// Constructs a nonempty range without address wrapping.
    pub fn new(start: u64, len: usize) -> Result<Self, Refusal> {
        let end = start.checked_add(len as u64).ok_or(Refusal::InvalidRange)?;
        if start == end {
            return Err(Refusal::InvalidRange);
        }
        Ok(Self { start, end })
    }

    /// First byte.
    pub const fn start(self) -> u64 {
        self.start
    }
    /// First byte after the range.
    pub const fn end(self) -> u64 {
        self.end
    }
    /// Number of bytes.
    pub const fn len(self) -> u64 {
        self.end - self.start
    }
    /// Checked ranges are never empty.
    pub const fn is_empty(self) -> bool {
        false
    }
    /// Whether an address is contained.
    pub const fn contains(self, address: u64) -> bool {
        self.start <= address && address < self.end
    }
    /// Whether another entire range is contained.
    pub const fn covers(self, other: Self) -> bool {
        self.start <= other.start && other.end <= self.end
    }
    /// Whether two ranges share any byte.
    pub const fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// Evidence source for an entry fact; positive evidence is not completeness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EntryProvenance {
    /// Caller-controlled assembly or generated code.
    Declared(String),
    /// Symbols, unwind records, loader records, or other recovered facts.
    Recovered(String),
}

/// Whether all entries within the declared scope have been accounted for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryCompleteness {
    /// Enumerated entries are exhaustive, including indirect targets.
    Complete,
    /// Every verified instruction head may be entered; no overlapping stream.
    AllInstructionHeads,
    /// Unknown entries remain; cannot authorize a rewrite.
    Incomplete,
}

/// An entry with an architectural landing-pad requirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegalEntry {
    /// Original instruction address.
    pub address: u64,
    /// Indirect branch tracking requires ENDBR at this original address.
    pub requires_endbr: bool,
}

/// What a mapping owner has done about saved, non-static continuations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResumeObligation {
    /// No saved continuation can refer to this scope (for example a private image).
    NoneExist,
    /// Every saved PC is an enumerated verified instruction head and may be routed.
    Enumerated(Vec<u64>),
    /// Saved continuations are not yet accounted for.
    Unresolved,
}

/// Versioned legal-entry facts, separate from the instruction decoder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegalEntrySet {
    /// Identity for which these facts hold.
    pub identity: CodeIdentity,
    /// Complete extent of the claim.
    pub scope: AddressRange,
    /// Source of the claim.
    pub provenance: EntryProvenance,
    /// Whether unknown/overlapping entries remain.
    pub completeness: EntryCompleteness,
    /// Positive entry facts.
    pub entries: Vec<LegalEntry>,
    /// Dynamic continuation facts.
    pub resumes: ResumeObligation,
}

/// Instrumentation lifetime chosen independently of patch placement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationProfile {
    /// Always active for this mapping generation; no routine toggles.
    InstallOnce,
    /// Optional observations controlled by explicit sampling epochs.
    ToggleProfile(TogglePolicy),
}

/// Requested repeated-toggle mechanism; availability is separately qualified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TogglePolicy {
    /// Single opcode-byte exact pun.
    OpcodeByte,
    /// Whole-word code publication.
    WordRewrite,
    /// Data flag in an installed trampoline.
    DataFlag,
}

/// Exact source bytes authenticated during planning and before publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedBytes {
    /// First byte's executable address.
    pub address: u64,
    /// Original bytes, not a hash-only lookup hint.
    pub bytes: Vec<u8>,
}

/// One source edit; the complete original image remains in the read set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ByteEdit {
    /// First byte's executable address.
    pub address: u64,
    /// Exact new bytes.
    pub bytes: Vec<u8>,
}

/// Equivalent entry in generated code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntryRoute {
    /// Original instruction head.
    pub original: u64,
    /// Generated entry, including the hook if this is the logical hook PC.
    pub generated: u64,
}

/// Per-entry proof obligation carried through publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EntryObligation {
    /// Entry stays behaviorally unchanged at its original address.
    Preserved(u64),
    /// Entry will route through a pre-published router.
    Routed(EntryRoute),
    /// An explicit obligation remains unsatisfied.
    Unresolved {
        /// Original address, if known.
        address: Option<u64>,
        /// Diagnostic.
        reason: String,
    },
}

/// Exact allocation request; existing mappings must never be clobbered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationRequest {
    /// Complete page-aligned mapping extent.
    pub range: AddressRange,
    /// Required alignment in bytes.
    pub alignment: usize,
}

/// Immutable generated image and its executable-to-original PC mapping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedCode {
    /// First generated byte.
    pub address: u64,
    /// Complete image, including any non-executable literals.
    pub bytes: Vec<u8>,
    /// Authenticated executable ranges only (literals are excluded).
    pub program_counters: Vec<crate::trampoline::ProgramCounterMapping>,
}

/// Publication mechanisms required by a plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationRequirements {
    /// A held dependency lease is always required by version 1.
    pub quiescent: bool,
    /// Require Linux private expedited sync-core completion.
    pub sync_core: bool,
    /// Require the reserved SIGILL router and unblocked execution threads.
    pub sigill_router: bool,
}

/// Inspectable construction input. Construction proves structure, not admission.
#[derive(Clone, Debug)]
pub struct PlanParts {
    /// Source generation.
    pub identity: CodeIdentity,
    /// Application lifetime.
    pub profile: ApplicationProfile,
    /// Where instrumentation logically runs.
    pub logical_pc: u64,
    /// Where the redirect is written.
    pub physical_pc: u64,
    /// Original whole-instruction displaced interval.
    pub displaced: AddressRange,
    /// Every byte consulted by the planner.
    pub reads: Vec<ExpectedBytes>,
    /// Every byte modified in original code.
    pub writes: Vec<ByteEdit>,
    /// Full source dependency set, including unchanged consumed bytes.
    pub dependencies: Vec<AddressRange>,
    /// Entry facts authenticated by the caller.
    pub entries: LegalEntrySet,
    /// Explicit resolution for displaced entries.
    pub obligations: Vec<EntryObligation>,
    /// Non-clobbering allocation requests.
    pub allocations: Vec<AllocationRequest>,
    /// Generated code to initialize before redirects.
    pub generated: Vec<GeneratedCode>,
    /// Publication prerequisites.
    pub requirements: PublicationRequirements,
}

/// Immutable plan shared by private-image and live-memory emitters.
#[derive(Clone, Debug)]
pub struct PatchPlan(PlanParts);

impl PatchPlan {
    /// Checks structural bounds. A publisher must also verify semantic proofs.
    pub fn checked(parts: PlanParts) -> Result<Self, Refusal> {
        if parts.entries.identity != parts.identity {
            return Err(Refusal::StaleGeneration);
        }
        if !parts.displaced.contains(parts.logical_pc)
            || parts.displaced.start() != parts.physical_pc
            || !parts.entries.scope.covers(parts.displaced)
            || !parts.requirements.quiescent
            || !parts.requirements.sync_core
        {
            return Err(Refusal::InvalidPlan);
        }
        for (address, bytes) in parts
            .reads
            .iter()
            .map(|x| (x.address, &x.bytes))
            .chain(parts.writes.iter().map(|x| (x.address, &x.bytes)))
        {
            let range = AddressRange::new(address, bytes.len())?;
            if !parts.dependencies.iter().any(|held| held.covers(range)) {
                return Err(Refusal::DependencyNotHeld);
            }
        }
        for edit in &parts.writes {
            let range = AddressRange::new(edit.address, edit.bytes.len())?;
            if !parts.reads.iter().any(|read| {
                AddressRange::new(read.address, read.bytes.len())
                    .is_ok_and(|original| original.covers(range))
            }) {
                return Err(Refusal::InvalidPlan);
            }
        }
        for image in &parts.generated {
            let range = AddressRange::new(image.address, image.bytes.len())?;
            if !parts
                .allocations
                .iter()
                .any(|allocation| allocation.range.covers(range))
            {
                return Err(Refusal::InvalidPlan);
            }
        }
        Ok(Self(parts))
    }
    /// Read-only complete contract; no mutable access is exposed.
    pub const fn parts(&self) -> &PlanParts {
        &self.0
    }
    /// Checks facts which every publisher must refuse if unresolved.
    pub fn check_entry_obligations(&self) -> Result<(), Refusal> {
        if self.0.entries.completeness == EntryCompleteness::Incomplete
            || self.0.entries.resumes == ResumeObligation::Unresolved
            || self
                .0
                .obligations
                .iter()
                .any(|o| matches!(o, EntryObligation::Unresolved { .. }))
        {
            return Err(Refusal::UnresolvedEntry);
        }
        Ok(())
    }
}

/// Fail-closed refusal. A caller must never treat it as an installed fallback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// Empty or overflowing range.
    InvalidRange,
    /// Inconsistent plan structure.
    InvalidPlan,
    /// Mapping incarnation, generation, or entry identity differs.
    StaleGeneration,
    /// Source differs from the authenticated snapshot.
    ExpectedBytesChanged,
    /// Lease does not hold every required byte.
    DependencyNotHeld,
    /// A prior postwrite error has not been resolved.
    LeasePoisoned,
    /// Static or dynamic entries remain unproved.
    UnresolvedEntry,
    /// Requested instruction is not a verified head.
    NotInstructionHead,
    /// No complete same-block window exists within the search bound.
    NoPatchWindow,
    /// Supported ISA/ABI cannot preserve this instruction or entry.
    UnsupportedSemantics(String),
    /// No permitted mapping satisfies the displacement and resource budget.
    AllocationUnavailable,
    /// Another installed patch owns dependent bytes.
    OwnershipConflict,
    /// Signal disposition or mask violates the router contract.
    SignalContract,
    /// Instruction-stream synchronization is unavailable or failed.
    Synchronization,
    /// A bounded lower-level operation failed.
    Backend(String),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Refusal {}

/// Scoped, non-transferable evidence supplied by an admission/rendezvous owner.
pub struct QuiescenceLease<'a> {
    identity: CodeIdentity,
    ranges: Vec<AddressRange>,
    poisoned: bool,
    guard: PhantomData<&'a mut ()>,
    thread: PhantomData<Rc<()>>,
}

impl<'a> QuiescenceLease<'a> {
    /// Borrows an exclusive guard for one generation and dependency set.
    ///
    /// # Safety
    /// The guard owner must enforce all quiescence, identity, entry, alias, and
    /// saved-context obligations in `INTERFACES.md` for the entire borrow.
    /// Dropping a poisoned lease must leave admission held. The supplied guard
    /// must represent real exclusion, not an unrelated token or Boolean.
    pub unsafe fn new<G: ?Sized>(
        _guard: &'a mut G,
        identity: CodeIdentity,
        ranges: Vec<AddressRange>,
    ) -> Self {
        Self {
            identity,
            ranges,
            poisoned: false,
            guard: PhantomData,
            thread: PhantomData,
        }
    }
    /// Generation owned by this lease.
    pub const fn identity(&self) -> CodeIdentity {
        self.identity
    }
    /// Whether a postwrite failure requires rollback or termination.
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }
    /// Checks identity and full dependency coverage before any source write.
    pub fn check(&self, plan: &PatchPlan) -> Result<(), Refusal> {
        if self.poisoned {
            return Err(Refusal::LeasePoisoned);
        }
        if self.identity != plan.parts().identity {
            return Err(Refusal::StaleGeneration);
        }
        if !plan
            .parts()
            .dependencies
            .iter()
            .all(|range| self.ranges.iter().any(|held| held.covers(*range)))
        {
            return Err(Refusal::DependencyNotHeld);
        }
        plan.check_entry_obligations()
    }
    /// Marks publication as possibly written; admission must remain held.
    pub fn poison(&mut self) {
        self.poisoned = true;
    }
    /// Clears poison only after byte-for-byte rollback and instruction synchronization.
    ///
    /// # Safety
    /// The publisher must verify every original byte, remove all reachable new
    /// routes, and complete sync-core before calling this method.
    pub unsafe fn rollback_verified(&mut self) {
        self.poisoned = false;
    }
}

/// Stage determining whether an error can safely release a held region.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureStage {
    /// No source byte was written.
    BeforeWrite,
    /// Source may have changed; the lease remains poisoned and held.
    KeepGated,
    /// Source and instruction visibility were restored and verified.
    RolledBack,
}

/// Publication failure with an explicit admission consequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationFailure {
    /// Named cause.
    pub reason: Refusal,
    /// Whether source bytes may still differ.
    pub stage: FailureStage,
}

/// Completed publication evidence; contains the exact immutable plan.
#[derive(Clone, Debug)]
pub struct PublicationReceipt {
    plan: PatchPlan,
}

impl PublicationReceipt {
    /// Creates evidence only after a trusted publisher completed the full contract.
    ///
    /// # Safety
    /// Every edit, route, allocation and entry obligation must be verified;
    /// sync-core must have completed, permissions must be final, and the
    /// identity must still be current. Mock receipts may certify only mock storage.
    pub unsafe fn completed(plan: PatchPlan) -> Self {
        Self { plan }
    }
    /// Exact published plan and generation.
    pub const fn plan(&self) -> &PatchPlan {
        &self.plan
    }
}

/// Trusted publisher boundary used by an admission library or private-image client.
///
/// # Safety
/// Implementations must honor expected bytes, identity, all dependencies,
/// lease poisoning, signal and allocation ownership, and receipt semantics.
pub unsafe trait Publisher {
    /// Handle retaining the generated code and routing lifetime.
    type Installed;
    /// Publishes an already verified plan while its full lease remains held.
    fn publish_quiescent(
        &mut self,
        plan: &PatchPlan,
        lease: &mut QuiescenceLease<'_>,
    ) -> Result<(Self::Installed, PublicationReceipt), PublicationFailure>;
}

/// Sampling epoch identity, distinct from the code generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Epoch(pub u64);

/// Whether an update is merely queued or visible to every executor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Visibility {
    /// Raw state update; prior entry observations may still occur.
    Eventual,
    /// Qualified code/data visibility synchronization completed.
    Complete,
}

/// Separate interface for qualified repeated profiling, never mandatory interception.
pub trait ToggleProbe {
    /// Opaque completion/drain token owned by this probe implementation.
    type Ticket;
    /// Enables new samples in an epoch.
    fn arm(&mut self, epoch: Epoch) -> Result<Self::Ticket, Refusal>;
    /// Disables new samples without cancelling admitted intervals.
    fn disarm(&mut self, epoch: Epoch) -> Result<Self::Ticket, Refusal>;
    /// Completes visibility of an earlier state update.
    fn complete(&mut self, ticket: &Self::Ticket) -> Result<Visibility, Refusal>;
    /// Closes the epoch and waits for all admitted intervals before reclamation.
    fn close_and_drain(&mut self, epoch: Epoch) -> Result<(), Refusal>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> CodeIdentity {
        CodeIdentity {
            source: SourceIdentity([7; 32]),
            mapping: 3,
            generation: 4,
        }
    }

    fn plan() -> PatchPlan {
        let scope = AddressRange::new(0x1000, 8).unwrap();
        PatchPlan::checked(PlanParts {
            identity: identity(),
            profile: ApplicationProfile::InstallOnce,
            logical_pc: 0x1000,
            physical_pc: 0x1000,
            displaced: scope,
            reads: vec![ExpectedBytes {
                address: 0x1000,
                bytes: vec![0x90; 8],
            }],
            writes: vec![ByteEdit {
                address: 0x1000,
                bytes: vec![0x90; 8],
            }],
            dependencies: vec![scope],
            entries: LegalEntrySet {
                identity: identity(),
                scope,
                provenance: EntryProvenance::Declared("private fixture".into()),
                completeness: EntryCompleteness::Complete,
                entries: vec![],
                resumes: ResumeObligation::NoneExist,
            },
            obligations: vec![],
            allocations: vec![],
            generated: vec![],
            requirements: PublicationRequirements {
                quiescent: true,
                sync_core: true,
                sigill_router: false,
            },
        })
        .unwrap()
    }

    #[test]
    fn ranges_never_wrap_or_accept_empty_input() {
        assert_eq!(AddressRange::new(0, 0), Err(Refusal::InvalidRange));
        assert_eq!(AddressRange::new(u64::MAX, 1), Err(Refusal::InvalidRange));
        let a = AddressRange::new(10, 5).unwrap();
        assert!(a.contains(14));
        assert!(!a.contains(15));
        assert!(!a.overlaps(AddressRange::new(15, 1).unwrap()));
    }

    #[test]
    fn lease_rejects_wrong_generation_missing_dependency_and_poison() {
        let plan = plan();
        let mut guard = ();
        let mut stale = identity();
        stale.generation += 1;
        // SAFETY: these are mock storage facts; no live memory is published.
        let mut lease =
            unsafe { QuiescenceLease::new(&mut guard, stale, plan.parts().dependencies.clone()) };
        assert_eq!(lease.check(&plan), Err(Refusal::StaleGeneration));
        lease.identity = identity();
        lease.ranges.clear();
        assert_eq!(lease.check(&plan), Err(Refusal::DependencyNotHeld));
        lease.ranges = plan.parts().dependencies.clone();
        assert_eq!(lease.check(&plan), Ok(()));
        lease.poison();
        assert_eq!(lease.check(&plan), Err(Refusal::LeasePoisoned));
    }

    #[test]
    fn static_completeness_does_not_discharge_dynamic_resumes() {
        let mut parts = plan().parts().clone();
        parts.entries.resumes = ResumeObligation::Unresolved;
        assert_eq!(
            PatchPlan::checked(parts).unwrap().check_entry_obligations(),
            Err(Refusal::UnresolvedEntry)
        );
        let mut parts = plan().parts().clone();
        parts.entries.completeness = EntryCompleteness::Incomplete;
        assert_eq!(
            PatchPlan::checked(parts).unwrap().check_entry_obligations(),
            Err(Refusal::UnresolvedEntry)
        );
    }

    #[test]
    fn edits_must_be_held_and_authenticated() {
        let mut parts = plan().parts().clone();
        parts.writes[0].address += 8;
        assert!(matches!(
            PatchPlan::checked(parts),
            Err(Refusal::DependencyNotHeld)
        ));
        let mut parts = plan().parts().clone();
        parts.reads.clear();
        assert!(matches!(
            PatchPlan::checked(parts),
            Err(Refusal::InvalidPlan)
        ));
    }
}
