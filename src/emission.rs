//! Explicit target and symbolic-hook context for shared offline planning.
//!
//! Artifact outputs retain unresolved runtime requirements and expose no live
//! publication method. Structural planning is not CPU, loader or ABI admission.

use crate::contracts::{AddressRange, CodeIdentity, LegalEntrySet, PatchPlan, Refusal};
use crate::frame_trace::{FrameTrace, FrameTraceLimits, FrameTraceRefusal};
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
    /// Authenticated containing function for live/function-based frontends.
    /// A distinct artifact-only frontend may instead bind a contiguous original
    /// code region: complete trusted nonoverlapping disassembly, every verified
    /// head a legal entry, no code-as-data, and private-image saved resumes.
    /// In that contract this field bounds source/eviction ownership; it does not
    /// certify a recovered function, ABI, call graph or whole-function controls.
    /// Such a frontend must not use foreign-function/whole-function APIs.
    pub function: AddressRange,
    /// Authenticated containing basic block (or a conservative artifact interval
    /// cut at every non-Next instruction and known direct target).
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
    // Instruction identity is immutable even when an earlier source edit is
    // present in site.code. Only the latter is a current read expectation.
    pub(crate) original_code: &'a [u8],
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
            original_code: request.code,
            emission: EmissionContext::Live(request.hook),
        }
    }
    pub(crate) fn artifact(request: &ArtifactRequest<'a>) -> Self {
        Self {
            site: request.site,
            original_code: request.site.code,
            emission: EmissionContext::Artifact(request.emission),
        }
    }
    pub(crate) fn with_code<'b>(&'b self, code: &'b [u8]) -> PlanningRequest<'b> {
        PlanningRequest {
            site: PlanningSite { code, ..self.site },
            original_code: self.original_code,
            emission: self.emission,
        }
    }
    /// A displaced original operation must not bypass an earlier redirect or
    /// hook. Padding and consumed successor bytes use separate current reads.
    pub(crate) fn require_original(&self, range: AddressRange) -> Result<(), Refusal> {
        if self.code.len() != self.original_code.len() {
            return Err(Refusal::InvalidRange);
        }
        let source = AddressRange::new(self.base_address, self.original_code.len())?;
        if !source.covers(range) {
            return Err(Refusal::InvalidRange);
        }
        let start =
            usize::try_from(range.start() - source.start()).map_err(|_| Refusal::InvalidRange)?;
        let end =
            usize::try_from(range.end() - source.start()).map_err(|_| Refusal::InvalidRange)?;
        if self.code[start..end] != self.original_code[start..end] {
            return Err(Refusal::ExpectedBytesChanged);
        }
        Ok(())
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

/// Independent refusal of optional artifact frame metadata.
/// The ordinary artifact plan and every outstanding qualification survive it.
#[derive(Debug)]
pub enum ArtifactFrameTraceRefusal {
    /// The plan is outside the single, observing, route-free NOP5 envelope.
    UnsupportedPlan,
    /// Exact source read expectations do not authenticate the literal NOP5.
    SourceSnapshot,
    /// The symbolic constructor could not reproduce an ordinary image.
    Reemission(TrampolineError),
    /// Producer metadata failed its independent shape or resource checks.
    Metadata(FrameTraceRefusal),
    /// Re-emitted bytes, maps, state profile or artifact bindings differ.
    ImageMismatch,
}

/// Producer frame facts for one exact opaque artifact image.
///
/// This value has no live conversion, registration or publication capability.
/// Original CFI, a frame-preserving symbolic hook, loader/consumer behavior and
/// all other artifact qualifications remain owed.
#[derive(Clone, Debug)]
pub struct ArtifactFrameTrace {
    source_step: PatchPlan,
    hook: SymbolicHook,
    bias_domain: u64,
    trace: FrameTrace,
}

impl ArtifactFrameTrace {
    /// Exact original source generation from the retained patch contract.
    pub const fn identity(&self) -> CodeIdentity {
        self.source_step.parts().identity
    }
    /// Complete original read expectations and source obligations, retained
    /// even after the ordinary ArtifactPlan owner is dropped.
    pub const fn source_step(&self) -> &PatchPlan {
        &self.source_step
    }
    /// Exact symbolic observer identity and resolved same-module coordinate.
    pub const fn symbolic_hook(&self) -> SymbolicHook {
        self.hook
    }
    /// Common-bias namespace used by the final linked image.
    pub const fn bias_domain(&self) -> u64 {
        self.bias_domain
    }
    /// Immutable producer facts; these do not certify source CFI or the hook.
    pub const fn trace(&self) -> &FrameTrace {
        &self.trace
    }
    /// Read-only final image; no live image ownership can be extracted.
    pub fn image(&self) -> ArtifactImageView<'_> {
        ArtifactImageView {
            image: self.exact_image(),
        }
    }
    pub(crate) const fn exact_image(&self) -> &TrampolineImage {
        self.trace.exact_image()
    }
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
    /// Reconstructs the single observing NOP5 producer and authenticates its
    /// complete final image before returning optional frame facts.
    ///
    /// Only a Legacy128 relocation at the logical head, with no interior-entry
    /// router, is admitted. Supplied target/hook inputs must reproduce every
    /// byte, layout, map and artifact field/requirement. No host CPU, mapping,
    /// callback pointer or original-CFI authority is inferred. Failure leaves
    /// this ordinary artifact plan unchanged.
    pub fn frame_trace_nop5(
        &self,
        emission: &ArtifactEmission,
        limits: FrameTraceLimits,
    ) -> Result<ArtifactFrameTrace, ArtifactFrameTraceRefusal> {
        use crate::contracts::PlanKind;
        use crate::trampoline::ObservationStackProfile;
        use ArtifactFrameTraceRefusal as Failure;

        let ([step], [image]) = (self.steps.as_slice(), self.images.as_slice()) else {
            return Err(Failure::UnsupportedPlan);
        };
        let parts = step.parts();
        if parts.kind != PlanKind::Relocation
            || parts.physical_pc != parts.logical_pc
            || parts.displaced.start() != parts.logical_pc
            || parts.displaced.len() != 5
            || parts.requirements.sigill_router
            || image.layout().observation_stack_profile != ObservationStackProfile::Legacy128
            || image.artifact_metadata().is_none_or(|metadata| {
                metadata
                    .requirements()
                    .contains(&ArtifactRequirement::EntryRouterBootstrap)
            })
        {
            return Err(Failure::UnsupportedPlan);
        }
        const NOP5: [u8; 5] = [0x0f, 0x1f, 0x44, 0, 0];
        let mut covered = false;
        for read in &parts.reads {
            let end = read
                .address
                .checked_add(read.bytes.len() as u64)
                .ok_or(Failure::SourceSnapshot)?;
            let start = read.address.max(parts.logical_pc);
            let until = end.min(parts.displaced.end());
            if start < until {
                let at =
                    usize::try_from(start - read.address).map_err(|_| Failure::SourceSnapshot)?;
                let offset = usize::try_from(start - parts.logical_pc)
                    .map_err(|_| Failure::SourceSnapshot)?;
                let len = usize::try_from(until - start).map_err(|_| Failure::SourceSnapshot)?;
                if read.bytes.get(at..at + len) != NOP5.get(offset..offset + len) {
                    return Err(Failure::SourceSnapshot);
                }
            }
            covered |= read.address <= parts.logical_pc && end >= parts.displaced.end();
        }
        if !covered {
            return Err(Failure::SourceSnapshot);
        }
        let scan = crate::scanner::InstructionScanner::default()
            .scan(&NOP5, parts.logical_pc)
            .map_err(|_| Failure::SourceSnapshot)?;
        let producer = TrampolinePlan::from_symbolic_window(
            &scan,
            parts.logical_pc,
            parts.logical_pc,
            parts.displaced.end(),
            false,
        )
        .map_err(Failure::Reemission)?;
        let emitted = producer
            .emit_artifact_with_frame_trace_at(image.address(), emission, limits)
            .map_err(Failure::Reemission)?;
        if emitted.image() != image {
            return Err(Failure::ImageMismatch);
        }
        let trace = emitted.trace().map_err(Failure::Metadata)?.clone();
        Ok(ArtifactFrameTrace {
            source_step: step.clone(),
            hook: emission.hook(),
            bias_domain: emission.profile().bias_domain(),
            trace,
        })
    }
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
    // Rewrap checked artifact diagnostics without changing steps, images or authority.
    pub(crate) fn with_metrics(mut self, metrics: ArtifactMetrics) -> Self {
        self.metrics = metrics;
        self
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

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
pub(crate) mod artifact_frame_tests;
