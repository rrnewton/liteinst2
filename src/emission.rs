//! Explicit target and symbolic-hook context for shared offline planning.
//!
//! Artifact outputs retain unresolved runtime requirements and expose no live
//! publication method. Structural planning is not CPU, loader or ABI admission.

use crate::contracts::{AddressRange, CodeIdentity, LegalEntrySet, PatchPlan, Refusal};
use crate::planner::HookSemantics;
use crate::quiescent::{AllocationPolicy, InstallRequest, PlannedInstall, SearchPolicy};
use crate::scanner::ScanResult;
use crate::trampoline::{
    HookCallback, SavedExtendedStateLayout, TrampolineError, TrampolineImage, TrampolinePlan,
};

/// Source facts independent of a build-process callback pointer.
#[derive(Clone, Copy, Debug)]
pub struct PlanningSite<'a> {
    /// Source generation in the shared core planning namespace.
    pub identity: CodeIdentity,
    /// Exact immutable source snapshot.
    pub code: &'a [u8],
    /// Coordinate corresponding to code[0].
    pub base_address: u64,
    /// Authenticated containing function.
    pub function: AddressRange,
    /// Authenticated containing basic block.
    pub block: AddressRange,
    /// Original selected instruction head.
    pub logical_pc: u64,
    /// Complete entry and saved-resume facts in the same namespace.
    pub entries: &'a LegalEntrySet,
    /// Observe or replace the selected instruction.
    pub semantics: HookSemantics,
    /// Complete candidate-placement policy.
    pub allocation: &'a AllocationPolicy,
    /// Existing bounded tactic/site search policy.
    pub search: SearchPolicy,
}

impl<'a> From<&InstallRequest<'a>> for PlanningSite<'a> {
    fn from(request: &InstallRequest<'a>) -> Self {
        Self {
            identity: request.identity,
            code: request.code,
            base_address: request.base_address,
            function: request.function,
            block: request.block,
            logical_pc: request.logical_pc,
            entries: request.entries,
            semantics: request.semantics,
            allocation: request.allocation,
            search: request.search,
        }
    }
}

/// A resolved symbolic callback address in the module's common-bias coordinates.
/// The target is not a Rust function pointer and its ABI/readiness remains owed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SymbolicHook {
    /// Stable portable binding identity supplied by the artifact frontend.
    pub identity: u64,
    /// Same-module planning coordinate, or an explicitly unresolved binding.
    /// Unresolved targets produce a typed emission refusal, never address zero.
    pub address: Option<u64>,
}

/// Checked target-description shape; it does not attest the eventual CPU.
#[derive(Clone, Debug)]
pub struct TargetProfile {
    pub(crate) state: SavedExtendedStateLayout,
    pub(crate) bias_domain: u64,
}

impl TargetProfile {
    /// Declares the existing Linux/x86-64, 4KiB, legacy/EVEX, no-CET envelope.
    /// The supplied layout must have been built by the checked description API.
    /// Runtime CPU/XCR0 and ISA qualification remain explicit image requirements.
    pub fn linux_x86_64_legacy_evex(
        state: SavedExtendedStateLayout,
        bias_domain: u64,
    ) -> Result<Self, Refusal> {
        if state.is_empty() {
            return Err(Refusal::UnsupportedSemantics(
                "artifact target state is unavailable".into(),
            ));
        }
        Ok(Self { state, bias_domain })
    }

    /// Exact target saved-state description used in every generated hook frame.
    pub const fn saved_state(&self) -> SavedExtendedStateLayout {
        self.state
    }
    /// Namespace whose references share one runtime load bias.
    pub const fn bias_domain(&self) -> u64 {
        self.bias_domain
    }
}

/// Explicit target-side inputs; no host CPUID or /proc maps are consulted.
#[derive(Clone, Debug)]
pub struct ArtifactEmission {
    profile: TargetProfile,
    hook: SymbolicHook,
    occupied: Vec<AddressRange>,
}

impl ArtifactEmission {
    /// Retains authenticated target occupancy and a symbolic binding. The
    /// frontend must include all original PT_LOAD/reserved extents; this pure
    /// constructor cannot discover omitted ownership or certify callback code.
    pub fn new(profile: TargetProfile, hook: SymbolicHook, occupied: Vec<AddressRange>) -> Self {
        Self {
            profile,
            hook,
            occupied,
        }
    }
    /// Target profile, never inferred from the compiler's process.
    pub const fn profile(&self) -> &TargetProfile {
        &self.profile
    }
    /// Resolved symbolic hook identity and coordinate.
    pub const fn hook(&self) -> SymbolicHook {
        self.hook
    }
    /// All authenticated pre-existing occupied target intervals.
    pub fn occupied(&self) -> &[AddressRange] {
        &self.occupied
    }
}

/// Artifact planning request with no dummy or converted HookCallback.
#[derive(Clone, Copy, Debug)]
pub struct ArtifactRequest<'a> {
    /// Original source and bounded search facts.
    pub site: PlanningSite<'a>,
    /// Explicit target profile, hook binding and address occupancy.
    pub emission: &'a ArtifactEmission,
}

#[derive(Clone, Copy)]
pub(crate) enum EmissionContext<'a> {
    Live(HookCallback),
    Artifact(&'a ArtifactEmission),
}

#[derive(Clone, Copy)]
pub(crate) struct PlanningRequest<'a> {
    pub(crate) site: PlanningSite<'a>,
    pub(crate) emission: EmissionContext<'a>,
}

impl<'a> std::ops::Deref for PlanningRequest<'a> {
    type Target = PlanningSite<'a>;
    fn deref(&self) -> &Self::Target {
        &self.site
    }
}

impl<'a> PlanningRequest<'a> {
    pub(crate) fn live(request: &InstallRequest<'a>) -> Self {
        Self {
            site: request.into(),
            emission: EmissionContext::Live(request.hook),
        }
    }
    pub(crate) fn artifact(request: &ArtifactRequest<'a>) -> Self {
        Self {
            site: request.site,
            emission: EmissionContext::Artifact(request.emission),
        }
    }
    pub(crate) fn with_code<'b>(&'b self, code: &'b [u8]) -> PlanningRequest<'b> {
        PlanningRequest {
            site: PlanningSite { code, ..self.site },
            emission: self.emission,
        }
    }
    pub(crate) fn with_search(&self, search: SearchPolicy) -> Self {
        Self {
            site: PlanningSite {
                search,
                ..self.site
            },
            ..*self
        }
    }
}

impl EmissionContext<'_> {
    pub(crate) fn qualify(self) -> Result<(), Refusal> {
        match self {
            Self::Live(_) => crate::quiescent::qualify_host(),
            Self::Artifact(_) => Ok(()),
        }
    }
    pub(crate) fn occupied(self) -> Result<Vec<AddressRange>, Refusal> {
        match self {
            Self::Live(_) => crate::quiescent::occupied_ranges(),
            Self::Artifact(input) => Ok(input.occupied.clone()),
        }
    }
    pub(crate) fn window(
        self,
        scan: &ScanResult,
        physical: u64,
        logical: u64,
        end: u64,
        replace: bool,
    ) -> Result<TrampolinePlan, TrampolineError> {
        match self {
            Self::Live(hook) => {
                TrampolinePlan::from_window(scan, physical, logical, end, hook, replace)
            }
            Self::Artifact(_) => {
                TrampolinePlan::from_symbolic_window(scan, physical, logical, end, replace)
            }
        }
    }
    pub(crate) fn short(
        self,
        scan: &ScanResult,
        physical: u64,
        replace: bool,
    ) -> Result<TrampolinePlan, TrampolineError> {
        match self {
            Self::Live(hook) => {
                TrampolinePlan::from_short_instruction(scan, physical, hook, replace)
            }
            Self::Artifact(_) => {
                TrampolinePlan::from_symbolic_short_instruction(scan, physical, replace)
            }
        }
    }
    pub(crate) fn emit(
        self,
        plan: &TrampolinePlan,
        address: u64,
    ) -> Result<TrampolineImage, TrampolineError> {
        match self {
            Self::Live(_) => plan.emit_at(address),
            Self::Artifact(input) => plan.emit_artifact_at(address, input),
        }
    }
}

/// Known operand-field encoding in a provisional artifact image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactFieldEncoding {
    /// Signed PC-relative field using the recorded real next instruction.
    Relative,
    /// Signed invariant difference from the recorded in-image RIP anchor.
    Delta,
}

/// Stable reason classes for provisional artifact emission refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactRefusalKind {
    /// An original or generated encoding has no implemented provenance proof.
    UnmodelledEncoding,
    /// A proven relative field cannot reach its required target.
    OutOfRange,
    /// An absolute runtime pointer needs a loader fixup not provided here.
    RuntimeAbsoluteFixup,
    /// A symbol or common-bias target binding is unresolved or inconsistent.
    TargetBinding,
    /// Field offsets, producer bytes, bounds or overlap checks failed.
    InvalidFieldLedger,
}

/// Exact known address operand, captured from its producer rather than a scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactField {
    /// Offset of the encoded field inside this image.
    pub offset: u64,
    /// Number of field bytes.
    pub width: usize,
    /// Arithmetic applied to the field.
    pub encoding: ArtifactFieldEncoding,
    /// Next-instruction or anchor offset inside this image.
    pub origin: u64,
    /// Exact resolved target in the module planning domain.
    pub target: i128,
    /// Common-bias namespace.
    pub bias_domain: u64,
    /// Exact producer role, including an original instruction PC when relevant.
    pub role: String,
}

/// Unresolved artifact qualification; none is silently marked satisfied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactRequirement {
    /// Bind the core generation/coordinates to authenticated artifact identity.
    ArtifactIdentityAndAddressBinding,
    /// Validate target CPU/ISA/XCR0 before any generated instruction needs it.
    TargetCpuAndStateAtEntry,
    /// Audit loader writes and relocated source operand fields.
    OriginalDynamicRelocationOwnership,
    /// Classify source immediates that may carry pointer values; integer-looking
    /// constants are never inferred to be load-bias invariant by this emitter.
    OriginalImmediatePointerProvenance,
    /// Qualify callback ABI, code/data readiness and its own relocation fields.
    HookAbiAndReadiness(#[doc = "Portable callback binding identity."] u64),
    /// Establish router readiness before any displaced interior entry executes.
    EntryRouterBootstrap,
    /// Supply and qualify generated CFI/FDE/LSDA, not just reverse-PC maps.
    GeneratedUnwindInformation,
    /// Exclude application code-as-data behavior or implement its preservation.
    OriginalCodeAsDataContract,
}

/// Provisional known-field inventory and exact outstanding qualification work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactImageMetadata {
    pub(crate) fields: Vec<ArtifactField>,
    pub(crate) requirements: Vec<ArtifactRequirement>,
}
impl ArtifactImageMetadata {
    /// Known emitted address operands, including their exact field origins.
    pub fn fields(&self) -> &[ArtifactField] {
        &self.fields
    }
    /// Requirements remaining before an executable artifact can be admitted.
    pub fn requirements(&self) -> &[ArtifactRequirement] {
        &self.requirements
    }
    /// This draft never claims whole-artifact provenance completeness.
    pub const fn qualification_complete(&self) -> bool {
        false
    }
}

/// Read-only artifact bytes/maps. It cannot be converted to a live image handle.
pub struct ArtifactImageView<'a> {
    image: &'a TrampolineImage,
}
impl ArtifactImageView<'_> {
    /// Planning coordinate of the first image byte.
    pub fn address(&self) -> u64 {
        self.image.address()
    }
    /// Exact provisional image bytes.
    pub fn bytes(&self) -> &[u8] {
        self.image.bytes()
    }
    /// Original heads and generated hook-entry routes.
    pub fn entry_routes(&self) -> &[(u64, u64)] {
        self.image.entry_routes()
    }
    /// Restored architectural comparison boundaries.
    pub fn instruction_boundaries(&self) -> &[(u64, u64)] {
        self.image.instruction_boundaries()
    }
    /// Executable ranges and corresponding original PCs.
    pub fn program_counter_mappings(&self) -> &[crate::trampoline::ProgramCounterMapping] {
        self.image.program_counter_mappings()
    }
    /// Known address fields and unresolved target requirements.
    pub fn metadata(&self) -> &ArtifactImageMetadata {
        self.image
            .artifact_metadata()
            .expect("opaque artifact plans contain only artifact images")
    }
}

/// Artifact-only structural output. No publish, retire, or live-member conversion.
#[derive(Clone, Debug)]
pub struct ArtifactPlan {
    steps: Vec<PatchPlan>,
    images: Vec<TrampolineImage>,
    metrics: ArtifactMetrics,
}

/// Preserved leaf/engine metrics, including raw bounded refusal inventory.
#[derive(Clone, Debug)]
pub enum ArtifactMetrics {
    /// B1/B2/T1 result.
    Single(crate::quiescent::PlanMetrics),
    /// T2 result.
    Successor(crate::eviction::EvictionMetrics),
    /// T3 result and exact private source relay geometry.
    Neighbor(
        crate::neighbor::NeighborGeometry,
        crate::neighbor::NeighborMetrics,
    ),
    /// Winning engine tactic, leaf metrics, and every outer attempt.
    Engine(
        crate::engine::Tactic,
        crate::engine::SelectedMetrics,
        Vec<crate::engine::EngineAttempt>,
    ),
}

impl ArtifactPlan {
    pub(crate) fn single(member: PlannedInstall) -> Self {
        let mut result = Self {
            steps: vec![member.plan],
            images: vec![member.image],
            metrics: ArtifactMetrics::Single(member.metrics),
        };
        result.record_router_requirement();
        result
    }
    pub(crate) fn bundle(bundle: &crate::bundle::PlannedBundle, metrics: ArtifactMetrics) -> Self {
        let mut result = Self {
            steps: bundle.plan().steps().to_vec(),
            images: bundle.images().to_vec(),
            metrics,
        };
        result.record_router_requirement();
        result
    }
    fn record_router_requirement(&mut self) {
        if self.steps.iter().any(|step| {
            step.parts().obligations.iter().any(|obligation| {
                matches!(obligation, crate::contracts::EntryObligation::Routed(_))
            })
        }) {
            for image in &mut self.images {
                image.require_artifact_router();
            }
        }
    }
    /// Source transformations. Quiescence/sync-core fields remain live
    /// prerequisites and do not assert that a lease or publication happened.
    pub fn source_steps(&self) -> &[PatchPlan] {
        &self.steps
    }
    /// Read-only artifact image views, with no live allocator capability.
    pub fn images(&self) -> impl Iterator<Item = ArtifactImageView<'_>> {
        self.images.iter().map(|image| ArtifactImageView { image })
    }
    /// Exact preserved planning outcomes.
    pub const fn metrics(&self) -> &ArtifactMetrics {
        &self.metrics
    }
    /// Structural success is deliberately not executable-artifact admission.
    pub const fn qualification_complete(&self) -> bool {
        false
    }
}
