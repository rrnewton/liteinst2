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

pub(crate) mod placement;

/// Source facts independent of a build-process callback pointer.
#[derive(Clone, Copy, Debug)]
pub struct PlanningSite<'a> {
    /// Source generation in the shared core planning namespace.
    pub identity: CodeIdentity,
    /// Exact immutable source snapshot.
    pub code: &'a [u8],
    /// Coordinate corresponding to `code[0]`.
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

/// An explicit fixed-image declaration, not evidence about a live loader.
/// The artifact frontend must join this exact source generation to an ET_EXEC
/// file and preserve its original LOAD addresses. Execution still owes zero
/// load bias; declaring it never grants admission or clears other requirements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedImageBinding {
    identity: CodeIdentity,
    domain: u64,
}
impl FixedImageBinding {
    /// Declare the only supported fixed-address obligation: zero load bias.
    pub fn zero_bias(identity: CodeIdentity, domain: u64) -> Result<Self, Refusal> {
        if identity.mapping != domain {
            return Err(Refusal::StaleGeneration);
        }
        Ok(Self { identity, domain })
    }
    /// Exact original source, mapping and generation; never just an address.
    pub const fn identity(self) -> CodeIdentity {
        self.identity
    }
    /// Domain shared by relative and fixed address fields.
    pub const fn domain(self) -> u64 {
        self.domain
    }
    /// This profile cannot be relocated by a nonzero runtime load bias.
    pub const fn required_load_bias(self) -> i128 {
        0
    }
    /// Check a supplied binding; this does not observe or authenticate a loader.
    pub fn verify(
        self,
        identity: CodeIdentity,
        domain: u64,
        load_bias: i128,
    ) -> Result<(), Refusal> {
        if self.identity != identity || self.domain != domain || load_bias != 0 {
            return Err(Refusal::StaleGeneration);
        }
        Ok(())
    }
}

/// Explicit target-side inputs; no host CPUID or /proc maps are consulted.
#[derive(Clone, Debug)]
pub struct ArtifactEmission {
    profile: TargetProfile,
    hook: SymbolicHook,
    occupied: Vec<AddressRange>,
    fixed_image: Option<FixedImageBinding>,
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
            fixed_image: None,
        }
    }
    /// Opt into the fixed-image obligation. The default constructor and all
    /// common-bias refusals remain unchanged. Source identity is checked again
    /// at the existing request-qualification boundary.
    pub fn with_fixed_image(mut self, binding: FixedImageBinding) -> Result<Self, Refusal> {
        binding.verify(binding.identity(), self.profile.bias_domain(), 0)?;
        self.fixed_image = Some(binding);
        Ok(self)
    }
    /// Fixed-address obligation retained by every generated image, if selected.
    pub const fn fixed_image(&self) -> Option<FixedImageBinding> {
        self.fixed_image
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
    CurrentPlacement(&'a ArtifactEmission),
    Fitting(&'a ArtifactEmission),
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
    pub(crate) fn with_fitting_placement(&self) -> Self {
        Self {
            emission: match self.emission {
                EmissionContext::Artifact(input) => EmissionContext::Fitting(input),
                other => other,
            },
            ..*self
        }
    }

    pub(crate) fn with_current_placement(&self) -> Self {
        Self {
            emission: match self.emission {
                EmissionContext::Artifact(input) => EmissionContext::CurrentPlacement(input),
                other => other,
            },
            ..*self
        }
    }
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
    pub(crate) const fn fitting_placement(self) -> bool {
        matches!(self, Self::Fitting(_))
    }
    pub(crate) fn prepare_fitting(
        self,
        plan: &TrampolinePlan,
    ) -> Result<Option<crate::trampoline::PreparedArtifact>, TrampolineError> {
        match self {
            Self::Fitting(input) => crate::trampoline::PreparedArtifact::new(plan, input).map(Some),
            _ => Ok(None),
        }
    }

    pub(crate) const fn current_placement(self) -> bool {
        matches!(self, Self::CurrentPlacement(_))
    }
    pub(crate) fn qualify(self) -> Result<(), Refusal> {
        match self {
            Self::Live(_) => crate::quiescent::qualify_host(),
            Self::Artifact(_) | Self::CurrentPlacement(_) | Self::Fitting(_) => Ok(()),
        }
    }
    pub(crate) fn qualify_source(self, identity: CodeIdentity) -> Result<(), Refusal> {
        self.qualify()?;
        let fixed = match self {
            Self::Artifact(input) | Self::CurrentPlacement(input) | Self::Fitting(input) => input
                .fixed_image()
                .map(|binding| (binding, input.profile().bias_domain())),
            Self::Live(_) => None,
        };
        if let Some((binding, domain)) = fixed {
            binding.verify(identity, domain, 0)?;
        }
        Ok(())
    }
    pub(crate) fn occupied(self) -> Result<Vec<AddressRange>, Refusal> {
        match self {
            Self::Live(_) => crate::quiescent::occupied_ranges(),
            Self::Artifact(input) | Self::CurrentPlacement(input) | Self::Fitting(input) => {
                Ok(input.occupied.clone())
            }
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
            Self::Artifact(_) | Self::CurrentPlacement(_) | Self::Fitting(_) => {
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
            Self::Artifact(_) | Self::CurrentPlacement(_) | Self::Fitting(_) => {
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
            Self::Artifact(input) | Self::CurrentPlacement(input) => {
                plan.emit_artifact_at(address, input)
            }
            Self::Fitting(_) => Err(TrampolineError::Artifact {
                reason: ArtifactRefusalKind::InvalidFieldLedger,
                message: "fitting emission requires its prepared artifact".into(),
            }),
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
    /// A producer-owned signed disp32 address contribution, valid only under
    /// the exact fixed-image zero-bias obligation. This is not PIC.
    FixedSigned32,
}

/// Producer-owned source spans for one fixed signed32 operand. The instruction
/// and its final four displacement bytes are joined to original ELF bytes by
/// the fixed writer; neither span asserts absence of loader writes by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedOperandSource {
    pub(crate) instruction: AddressRange,
    pub(crate) displacement: AddressRange,
}
impl FixedOperandSource {
    /// Exact original decoded instruction, including any retained REX prefix.
    pub const fn instruction(self) -> AddressRange {
        self.instruction
    }
    /// Original signed32 bytes; final encoder offset is recorded separately.
    pub const fn displacement(self) -> AddressRange {
        self.displacement
    }
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
    /// Original fixed-operand provenance; absent for common-bias fields.
    pub fixed_source: Option<FixedOperandSource>,
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
    pub(crate) fixed_image: Option<FixedImageBinding>,
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
    /// Additional unresolved loader obligation; no live-loader proof is implied.
    pub const fn fixed_image(&self) -> Option<FixedImageBinding> {
        self.fixed_image
    }
    /// Independent final-byte readback using the producer's complete field ledger.
    /// The caller must separately bind the original ELF and all LOAD mappings.
    pub fn validate_fixed_image(
        &self,
        identity: CodeIdentity,
        domain: u64,
        load_bias: i128,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), TrampolineError> {
        let binding = self.fixed_image.ok_or_else(|| TrampolineError::Artifact {
            reason: ArtifactRefusalKind::InvalidFieldLedger,
            message: "fixed image lacks its source/zero-bias obligation".into(),
        })?;
        binding
            .verify(identity, domain, load_bias)
            .map_err(|error| TrampolineError::Artifact {
                reason: ArtifactRefusalKind::InvalidFieldLedger,
                message: format!("fixed image binding mismatch: {error:?}"),
            })?;
        crate::trampoline::validate_artifact_fields(bytes, address, domain, self)
    }
    /// This draft never claims whole-artifact provenance completeness.
    pub const fn qualification_complete(&self) -> bool {
        false
    }
}

/// Read-only artifact bytes/maps. It cannot be converted to a live image handle.
pub struct ArtifactImageView<'a> {
    image: ArtifactImageRef<'a>,
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
            image: ArtifactImageRef::Direct(self.exact_image()),
        }
    }
    pub(crate) const fn exact_image(&self) -> &TrampolineImage {
        self.trace.exact_image()
    }
}
impl<'a> ArtifactImageView<'a> {
    // Internal read-only borrowing; this adds no live image ownership conversion.
    pub(crate) const fn from_direct(image: &'a TrampolineImage) -> Self {
        Self {
            image: ArtifactImageRef::Direct(image),
        }
    }
}
impl ArtifactImageView<'_> {
    /// Canonical external entry; for an ordinary direct image this is address().
    pub fn entry_address(&self) -> u64 {
        self.image.entry_address()
    }
    /// Explicit same-page envelope layout, absent for all old direct images.
    pub fn entry_veneer(&self) -> Option<ArtifactEntryVeneerLayout> {
        self.image.entry_veneer()
    }

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
    images: Vec<ArtifactStoredImage>,
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

        let ([step], [ArtifactStoredImage::Direct(image)]) =
            (self.steps.as_slice(), self.images.as_slice())
        else {
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
                // The optional frame/unwind export has no fixed-image binding
                // field yet. Do not erase the new unresolved obligation.
                metadata.fixed_image().is_some()
                    || metadata
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
            images: vec![ArtifactStoredImage::Direct(member.image)],
            metrics: ArtifactMetrics::Single(member.metrics),
        };
        result.record_router_requirement();
        result
    }
    pub(crate) fn bundle(bundle: &crate::bundle::PlannedBundle, metrics: ArtifactMetrics) -> Self {
        let mut result = Self {
            steps: bundle.plan().steps().to_vec(),
            images: bundle
                .images()
                .iter()
                .cloned()
                .map(ArtifactStoredImage::Direct)
                .collect(),
            metrics,
        };
        result.record_router_requirement();
        result
    }
    pub(crate) fn checked_pair(
        pair: crate::bundle::CheckedArtifactPair,
        metrics: ArtifactMetrics,
    ) -> Self {
        let mut result = Self {
            steps: pair.plan.steps().to_vec(),
            images: pair.images,
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
        self.images.iter().map(ArtifactStoredImage::view)
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

/// Read-only layout of one artifact entry veneer. This is not allocation,
/// executable-entry, frame-trace, CPU/ABI or publication authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactEntryVeneerLayout {
    storage: u64,
    entry: u64,
    body_len: usize,
    size_bound: usize,
}
impl ArtifactEntryVeneerLayout {
    /// First stored byte (the body base), unchanged image-address semantics.
    pub const fn storage_address(self) -> u64 {
        self.storage
    }
    /// Separately checked external E9 entry to the body.
    pub const fn entry_address(self) -> u64 {
        self.entry
    }
    /// Exact body bytes, excluding owned padding and entry veneer.
    pub const fn body_len(self) -> usize {
        self.body_len
    }
    /// Conservative certificate of the single encoded body.
    pub const fn size_bound(self) -> usize {
        self.size_bound
    }
    /// Half-open padding range. Empty padding is represented by equal endpoints.
    pub const fn padding_range(self) -> (u64, u64) {
        (self.storage + self.body_len as u64, self.entry)
    }
    /// Half-open five-byte entry veneer range.
    pub const fn veneer_range(self) -> (u64, u64) {
        (self.entry, self.entry + 5)
    }
}

#[derive(Clone, Copy)]
enum ArtifactImageRef<'a> {
    Direct(&'a TrampolineImage),
    EntryVeneer(&'a crate::trampoline::ArtifactTrampolineAllocation),
}
impl ArtifactImageRef<'_> {
    fn address(self) -> u64 {
        match self {
            Self::Direct(i) => i.address(),
            Self::EntryVeneer(i) => i.storage_address(),
        }
    }
    fn entry_address(self) -> u64 {
        match self {
            Self::Direct(i) => i.address(),
            Self::EntryVeneer(i) => i.entry_transfer().0,
        }
    }
    fn entry_veneer(self) -> Option<ArtifactEntryVeneerLayout> {
        match self {
            Self::Direct(_) => None,
            Self::EntryVeneer(i) => Some(ArtifactEntryVeneerLayout {
                storage: i.storage_address(),
                entry: i.entry_address(),
                body_len: i.body_len(),
                size_bound: i.placement().size_bound(),
            }),
        }
    }
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Direct(i) => i.bytes(),
            Self::EntryVeneer(i) => i.bytes(),
        }
    }
    fn entry_routes(&self) -> &[(u64, u64)] {
        match self {
            Self::Direct(i) => i.entry_routes(),
            Self::EntryVeneer(i) => i.entry_routes(),
        }
    }
    fn instruction_boundaries(&self) -> &[(u64, u64)] {
        match self {
            Self::Direct(i) => i.instruction_boundaries(),
            Self::EntryVeneer(i) => i.instruction_boundaries(),
        }
    }
    fn program_counter_mappings(&self) -> &[crate::trampoline::ProgramCounterMapping] {
        match self {
            Self::Direct(i) => i.program_counter_mappings(),
            Self::EntryVeneer(i) => i.program_counter_mappings(),
        }
    }
    fn artifact_metadata(&self) -> Option<&ArtifactImageMetadata> {
        match self {
            Self::Direct(i) => i.artifact_metadata(),
            Self::EntryVeneer(i) => Some(i.artifact_metadata()),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) enum ArtifactStoredImage {
    Direct(TrampolineImage),
    EntryVeneer(crate::trampoline::ArtifactTrampolineAllocation),
}
// Preserve ordinary ArtifactPlan debug output despite its private storage adapter.
impl std::fmt::Debug for ArtifactStoredImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct(image) => std::fmt::Debug::fmt(image, f),
            Self::EntryVeneer(image) => f.debug_tuple("EntryVeneer").field(image).finish(),
        }
    }
}
impl ArtifactStoredImage {
    pub(crate) fn view(&self) -> ArtifactImageView<'_> {
        ArtifactImageView {
            image: match self {
                Self::Direct(i) => ArtifactImageRef::Direct(i),
                Self::EntryVeneer(i) => ArtifactImageRef::EntryVeneer(i),
            },
        }
    }
    pub(crate) fn require_artifact_router(&mut self) {
        match self {
            Self::Direct(i) => i.require_artifact_router(),
            Self::EntryVeneer(i) => i.require_artifact_router(),
        }
    }
    pub(crate) fn into_direct(self) -> Result<TrampolineImage, Refusal> {
        match self {
            Self::Direct(i) => Ok(i),
            Self::EntryVeneer(_) => Err(Refusal::InvalidPlan),
        }
    }
}

/// Private checked structural member; never a live PlannedInstall.
#[derive(Clone, Debug)]
pub(crate) struct ArtifactMember {
    pub(crate) plan: PatchPlan,
    pub(crate) image: ArtifactStoredImage,
}
impl ArtifactMember {
    pub(crate) fn checked(plan: PatchPlan, image: ArtifactStoredImage) -> Result<Self, Refusal> {
        let member = Self { plan, image };
        member.validate()?;
        Ok(member)
    }
    pub(crate) fn validate(&self) -> Result<(), Refusal> {
        if let ArtifactStoredImage::EntryVeneer(image) = &self.image {
            image
                .validate()
                .map_err(|error| Refusal::Backend(error.to_string()))?;
            let parts = self.plan.parts();
            if image.body_layout().total_len() != Some(image.body_len())
                || parts.kind != crate::contracts::PlanKind::Relocation
                || parts.physical_pc != parts.logical_pc
                || image.entry_routes() != [(parts.logical_pc, image.storage_address())]
                || !image.artifact_metadata().fields().iter().any(|field| {
                    field.role == "Return" && field.target == i128::from(parts.displaced.end())
                })
            {
                return Err(Refusal::InvalidPlan);
            }
        }
        let view = self.image.view();
        let parts = self.plan.parts();
        let ([generated], [allocation]) =
            (parts.generated.as_slice(), parts.allocations.as_slice())
        else {
            return Err(Refusal::InvalidPlan);
        };
        let start = view.address() & !4095;
        let end = view
            .address()
            .checked_add(view.bytes().len() as u64)
            .and_then(|end| end.checked_add(4095))
            .map(|end| end & !4095)
            .ok_or(Refusal::InvalidRange)?;
        let range = AddressRange::new(start, (end - start) as usize)?;
        if view.image.artifact_metadata().is_none()
            || generated.address != view.address()
            || generated.bytes != view.bytes()
            || generated.program_counters != view.program_counter_mappings()
            || allocation.range != range
            || allocation.alignment != 4096
        {
            return Err(Refusal::InvalidPlan);
        }
        Ok(())
    }
}
