//! Explicit artifact-only search for two adjacent observing, forward two-byte Jccs.
//! Original instruction identity and actual inherited composition remain separate.

use super::{
    PlannedInstall, PunContext, TacticPolicy, plan_pun_with_context_core, pun_candidates,
    validated_source_core,
};
use crate::bundle::{BundleBudget, BundleMemory, PlannedBundle};
use crate::composition::Composition;
use crate::contracts::{AddressRange, EntryCompleteness, Refusal, ResumeObligation};
use crate::emission::{
    ArtifactEmission, ArtifactPlan, EmissionContext, PlanningRequest, PlanningSite,
};
use crate::planner::HookSemantics;
use crate::scanner::ScanResult;
use crate::search::{CandidateProof, SearchEvidence, SearchScope};

/// Separate pair limits; existing site allocation policies retain their meanings.
#[derive(Clone, Copy, Debug)]
pub struct AdjacentB2Budget {
    /// Maximum admitted-upper lower-search scopes, including empty schedules.
    pub max_continuations: usize,
    /// Aggregate limits for the two NEW members only, excluding the predecessor.
    pub bundle: BundleBudget,
}

/// Cumulative exact-target image calls and upper-conditioned lower scopes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PairCounts {
    /// Upper exact-target kernel calls, including refusals.
    pub upper: usize,
    /// Lower exact-target kernel calls, never reset between upper targets.
    pub lower: usize,
    /// Admitted-upper lower scopes, charged before deriving the lower window.
    pub joint: usize,
}

/// Exact decision location; no legacy leaf or engine stage is reinterpreted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairStage {
    /// Input qualification before candidate calls.
    Preflight,
    /// Upper window derivation or actual exact-target kernel; `search` distinguishes them.
    UpperLeaf,
    /// Actual inherited upper append.
    UpperAppend,
    /// Remaining pending ownership after upper append.
    UpperPending,
    /// Current-byte lower window and original-policy candidate schedule.
    LowerSchedule,
    /// Actual lower exact-target kernel.
    LowerLeaf,
    /// Actual inherited lower append.
    LowerAppend,
    /// Final external pending ownership.
    LowerPending,
    /// Existing two-member bundle checks.
    Aggregate,
}

/// Ordered input-domain refusal, separate from its unchanged core reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairEligibility {
    /// Lower original identity and bytes against actual predecessor.
    OriginalAuthentication,
    /// Upper code identity differs.
    CommonIdentity,
    /// Common original, base, region or entry facts differ.
    IncompatibleView,
    /// Checked adjacency, exact source scope or two-byte block differs.
    PairGeometry,
    /// Existing scanner and entry validation refused.
    OriginalQualification,
    /// Explicit all-head contract required.
    AllHeadDomain,
    /// Exact ordered complete head list required.
    AllHeadPopulation,
    /// This initial API excludes ENDBR obligations.
    CetDomain,
    /// Saved resume list must be canonical.
    ResumeShape,
    /// Observe is required.
    ObservingDomain,
    /// Explicit forced-B2 search fields are required, including max_sites=1.
    SearchDomain,
    /// Only forward ordinary two-byte Jccs targeting beyond the pair are admitted.
    BranchDomain,
    /// Selected branch target is not an original verified head.
    BranchHead,
    /// Complete five-byte fetch and cache-line-contained two-byte store required.
    FetchStoreDomain,
    /// Shared symbolic hook must be resolved.
    HookBinding,
    /// Each site's mapping capacity must permit at least one page.
    SiteResource,
    /// External pending intervals must be canonical and exclude the pair.
    PendingShape,
    /// Actual initial pending coverage or ownership refused.
    PendingInitial,
    /// Checked bound arithmetic overflowed.
    BudgetShape,
}

/// Terminal classification, never inferred from a local successful image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairStop {
    /// First failed input-domain guard.
    Eligibility(PairEligibility),
    /// Zero upper image allowance.
    UpperImagesBudget,
    /// The original upper schedule proves an omitted target.
    UpperScheduleBudget,
    /// Cumulative lower allowance omitted a target or prevented another upper scope.
    LowerImagesBudget,
    /// Another upper scope would exceed its independent continuation allowance.
    JointContinuationsBudget,
    /// Continuation allowance exceeds the upper image allowance.
    InvalidBudgetRelation,
    /// The declared search ended without a pair, retaining the last local refusal.
    Exhausted,
    /// Structural or checked-arithmetic failure; no candidate retry.
    TerminalInvariant,
}

/// Local observation; only the final PairEvidence can declare pair acceptance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PairOutcome {
    /// This stage accepted locally, not necessarily the pair.
    LocalAccepted,
    /// Actual unchanged core refusal.
    Refused(Refusal),
    /// A charged lower scope had no scheduled target.
    EmptySchedule,
}

/// One actual ordered stage, with no reconstructed finer backend substage.
#[derive(Clone, Debug)]
pub struct PairEvent {
    /// Decision actually reached.
    pub stage: PairStage,
    /// Local result.
    pub outcome: PairOutcome,
    /// Counts before the stage's debit, if any.
    pub counters_before: PairCounts,
    /// Counts after the stage.
    pub counters_after: PairCounts,
    /// Original upper schedule position, when entered.
    pub upper_ordinal: Option<usize>,
    /// Original current-scope lower schedule position, when entered.
    pub lower_ordinal: Option<usize>,
    /// Actual upper target, when entered.
    pub upper_target: Option<u64>,
    /// Actual lower target, when entered.
    pub lower_target: Option<u64>,
    /// Exact existing kernel evidence; absent for non-kernel stages.
    pub search: Option<SearchEvidence>,
}

/// Original-policy candidate order and proof for one actual source overlay.
#[derive(Clone, Debug)]
pub struct PairSchedule {
    /// None for the upper schedule; otherwise the conditioning upper ordinal.
    pub upper_ordinal: Option<usize>,
    /// None for the upper schedule; otherwise the conditioning upper target.
    pub upper_target: Option<u64>,
    /// Exact current-byte window.
    pub window: AddressRange,
    /// Unchanged deduplicated generator output, before cumulative debit limits.
    pub targets: Vec<u64>,
    /// Original page-walk work and omission proof.
    pub proof: CandidateProof,
}

/// Pair-specific search evidence; no completeness or performance inference.
#[derive(Clone, Debug)]
pub struct PairEvidence {
    /// Original lower selected PC.
    pub lower_pc: u64,
    /// Original upper selected PC.
    pub upper_pc: u64,
    /// Final cumulative counts.
    pub counts: PairCounts,
    /// Chronological actual stage observations, including rejected candidates.
    pub events: Vec<PairEvent>,
    /// Upper original-policy schedule, if derivation was reached.
    pub upper_schedule: Option<PairSchedule>,
    /// Conditioned lower schedules, including empty ones.
    pub lower_schedules: Vec<PairSchedule>,
    /// Set only after inherited and aggregate pair checks all succeed.
    pub accepted: bool,
    /// Always false: bounded schedule facts do not prove global impossibility.
    pub classification_complete: bool,
}

/// Failure retains the complete pair inventory and never returns a partial plan.
#[derive(Clone, Debug)]
pub struct AdjacentB2Failure {
    /// Exact core reason, or AllocationUnavailable for a typed budget stop.
    pub reason: Refusal,
    /// Independent terminal discriminator.
    pub stop: PairStop,
    /// Guard location; an unvisited target is not an executed leaf.
    pub stage: PairStage,
    /// All prior actual stages and original schedules, boxed to keep errors small.
    pub evidence: Box<PairEvidence>,
    /// Actual next returned or proven omitted target at a budget stop.
    pub unvisited_target: Option<u64>,
}

/// Two opaque artifact members. There is no live conversion or publication API.
#[derive(Clone, Debug)]
pub struct AdjacentB2ArtifactPlan {
    members: [ArtifactPlan; 2],
    logical_pcs: [u64; 2],
    memory: BundleMemory,
    evidence: PairEvidence,
}
impl AdjacentB2ArtifactPlan {
    /// Members in actual append order: upper, then lower.
    pub const fn members(&self) -> &[ArtifactPlan; 2] {
        &self.members
    }
    /// Original selected PCs in that same upper/lower order.
    pub const fn logical_pcs(&self) -> [u64; 2] {
        self.logical_pcs
    }
    /// Exact new-pair memory, excluding predecessor resources.
    pub const fn memory(&self) -> BundleMemory {
        self.memory
    }
    /// Complete bounded pair search.
    pub const fn evidence(&self) -> &PairEvidence {
        &self.evidence
    }
    /// Structural planning grants no CPU, ABI, loader, lease or native authority.
    pub const fn qualification_complete(&self) -> bool {
        false
    }
}

struct Terminal {
    reason: Refusal,
    stop: PairStop,
    stage: PairStage,
    target: Option<u64>,
}
struct State {
    evidence: PairEvidence,
    upper: Option<(usize, u64)>,
    lower: Option<(usize, u64)>,
    last: Option<(PairStage, Refusal)>,
}
impl State {
    fn record(
        &mut self,
        stage: PairStage,
        outcome: PairOutcome,
        before: PairCounts,
        search: Option<SearchEvidence>,
    ) {
        self.evidence.events.push(PairEvent {
            stage,
            outcome,
            counters_before: before,
            counters_after: self.evidence.counts,
            upper_ordinal: self.upper.map(|x| x.0),
            upper_target: self.upper.map(|x| x.1),
            lower_ordinal: self.lower.map(|x| x.0),
            lower_target: self.lower.map(|x| x.1),
            search,
        });
    }
    fn reject(
        &mut self,
        stage: PairStage,
        reason: Refusal,
        before: PairCounts,
        search: Option<SearchEvidence>,
    ) -> Result<(), Terminal> {
        self.record(stage, PairOutcome::Refused(reason.clone()), before, search);
        self.last = Some((stage, reason.clone()));
        if matches!(reason, Refusal::InvalidRange | Refusal::InvalidPlan) {
            return Err(Terminal {
                reason,
                stop: PairStop::TerminalInvariant,
                stage,
                target: None,
            });
        }
        Ok(())
    }
    fn accept(&mut self, stage: PairStage, before: PairCounts, search: Option<SearchEvidence>) {
        self.record(stage, PairOutcome::LocalAccepted, before, search);
    }
    fn debit(&mut self, stage: PairStage) -> Result<PairCounts, Terminal> {
        let before = self.evidence.counts;
        let count = match stage {
            PairStage::UpperLeaf => &mut self.evidence.counts.upper,
            PairStage::LowerLeaf => &mut self.evidence.counts.lower,
            PairStage::LowerSchedule => &mut self.evidence.counts.joint,
            _ => {
                return Err(Terminal {
                    reason: Refusal::InvalidPlan,
                    stop: PairStop::TerminalInvariant,
                    stage,
                    target: None,
                });
            }
        };
        *count = count.checked_add(1).ok_or(Terminal {
            reason: Refusal::InvalidRange,
            stop: PairStop::TerminalInvariant,
            stage,
            target: None,
        })?;
        Ok(before)
    }
}

fn budget_stop(stop: PairStop, stage: PairStage, target: Option<u64>) -> Terminal {
    Terminal {
        reason: Refusal::AllocationUnavailable,
        stop,
        stage,
        target,
    }
}
fn eligibility(kind: PairEligibility, reason: Refusal) -> Terminal {
    Terminal {
        reason,
        stop: PairStop::Eligibility(kind),
        stage: PairStage::Preflight,
        target: None,
    }
}
fn unsupported(kind: PairEligibility, text: &str) -> Terminal {
    eligibility(kind, Refusal::UnsupportedSemantics(text.into()))
}
fn omitted(proof: &CandidateProof) -> Option<u64> {
    match proof {
        CandidateProof::PageBoundary { omitted, .. } => *omitted,
        CandidateProof::Indexed { omitted, .. } => omitted.map(|item| item.target),
    }
}

fn validate_site(
    request: &PlanningRequest<'_>,
    upper_end: u64,
) -> Result<(AddressRange, ScanResult, AddressRange), Terminal> {
    use PairEligibility as E;
    let (source, scan) =
        validated_source_core(request).map_err(|e| eligibility(E::OriginalQualification, e))?;
    let displaced =
        AddressRange::new(request.logical_pc, 2).map_err(|e| eligibility(E::PairGeometry, e))?;
    if request.function != source || request.entries.scope != source || request.block != displaced {
        return Err(eligibility(E::PairGeometry, Refusal::InvalidRange));
    }
    if request.entries.completeness != EntryCompleteness::AllInstructionHeads {
        return Err(unsupported(
            E::AllHeadDomain,
            "adjacent B2 requires all-head entry contract",
        ));
    }
    if request.entries.entries.len() != scan.instructions().len()
        || request
            .entries
            .entries
            .iter()
            .zip(scan.instructions())
            .any(|(entry, instruction)| entry.address != instruction.address())
    {
        return Err(eligibility(E::AllHeadPopulation, Refusal::UnresolvedEntry));
    }
    if request
        .entries
        .entries
        .iter()
        .any(|entry| entry.requires_endbr)
    {
        return Err(unsupported(
            E::CetDomain,
            "adjacent B2 excludes CET entry requirements",
        ));
    }
    if let ResumeObligation::Enumerated(pcs) = &request.entries.resumes {
        if pcs.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(eligibility(E::ResumeShape, Refusal::InvalidRange));
        }
    }
    if request.semantics != HookSemantics::Observe {
        return Err(unsupported(
            E::ObservingDomain,
            "adjacent B2 requires observing hooks",
        ));
    }
    if request.search.tactics != TacticPolicy::GeneralizedPunOnly
        || request.search.max_upstream_bytes != 0
        || request.search.max_displaced_bytes != 2
        || request.search.max_sites != 1
    {
        return Err(unsupported(
            E::SearchDomain,
            "adjacent B2 exact search contract",
        ));
    }
    let instruction = scan
        .instructions()
        .iter()
        .find(|item| item.address() == request.logical_pc)
        .ok_or_else(|| eligibility(E::OriginalQualification, Refusal::NotInstructionHead))?;
    let offset = usize::try_from(request.logical_pc - source.start())
        .map_err(|_| eligibility(E::PairGeometry, Refusal::InvalidRange))?;
    if instruction.len() != 2
        || !(0x70..=0x7f).contains(&request.original_code[offset])
        || instruction.instruction().flow_control() != iced_x86::FlowControl::ConditionalBranch
    {
        return Err(unsupported(
            E::BranchDomain,
            "adjacent B2 requires forward two-byte Jcc",
        ));
    }
    let target = instruction.instruction().near_branch_target();
    if target < upper_end || !source.contains(target) {
        return Err(unsupported(
            E::BranchDomain,
            "adjacent B2 requires forward two-byte Jcc",
        ));
    }
    if scan.site(target).is_none() {
        return Err(eligibility(E::BranchHead, Refusal::NotInstructionHead));
    }
    let consumed = AddressRange::new(request.logical_pc, 5)
        .map_err(|e| eligibility(E::FetchStoreDomain, e))?;
    if !source.covers(consumed) || request.logical_pc / 64 != (displaced.end() - 1) / 64 {
        return Err(eligibility(E::FetchStoreDomain, Refusal::NoPatchWindow));
    }
    Ok((source, scan, displaced))
}

struct Prepared {
    current: Vec<u8>,
    source: AddressRange,
    scans: [ScanResult; 2],
    lower_pending: Vec<AddressRange>,
}
fn preflight(
    requests: &[PlanningRequest<'_>; 2],
    emission: &ArtifactEmission,
    predecessor: &Composition,
    pending: &[AddressRange],
    budget: AdjacentB2Budget,
) -> Result<Prepared, Terminal> {
    use PairEligibility as E;
    let [lower, upper] = requests;
    let current = predecessor
        .planning_overlay(lower.identity, lower.base_address, lower.original_code)
        .map_err(|e| eligibility(E::OriginalAuthentication, e))?;
    if upper.identity != lower.identity {
        return Err(eligibility(E::CommonIdentity, Refusal::StaleGeneration));
    }
    if upper.base_address != lower.base_address
        || upper.original_code != lower.original_code
        || upper.function != lower.function
        || upper.entries != lower.entries
    {
        return Err(eligibility(E::IncompatibleView, Refusal::InvalidPlan));
    }
    if lower.logical_pc.checked_add(2) != Some(upper.logical_pc) {
        return Err(eligibility(E::PairGeometry, Refusal::InvalidRange));
    }
    let upper_end = upper
        .logical_pc
        .checked_add(2)
        .ok_or_else(|| eligibility(E::PairGeometry, Refusal::InvalidRange))?;
    let (source, lower_scan, lower_range) = validate_site(lower, upper_end)?;
    let (_, upper_scan, upper_range) = validate_site(upper, upper_end)?;
    if emission.hook().address.is_none() {
        return Err(unsupported(
            E::HookBinding,
            "adjacent B2 requires resolved symbolic hook",
        ));
    }
    for request in requests {
        if request.allocation.max_mappings == 0 || request.allocation.max_mapped_bytes < 4096 {
            return Err(eligibility(E::SiteResource, Refusal::AllocationUnavailable));
        }
    }
    if pending
        .windows(2)
        .any(|pair| pair[0].end() > pair[1].start())
        || pending
            .iter()
            .any(|range| range.overlaps(lower_range) || range.overlaps(upper_range))
    {
        return Err(eligibility(E::PendingShape, Refusal::InvalidRange));
    }
    pending
        .len()
        .checked_add(2)
        .ok_or_else(|| eligibility(E::PendingShape, Refusal::InvalidRange))?;
    let mut initial = pending.to_vec();
    initial.extend([lower_range, upper_range]);
    initial.sort_unstable_by_key(|range| range.start());
    predecessor
        .require_unclaimed_ranges(&initial)
        .map_err(|e| eligibility(E::PendingInitial, e))?;
    let (u, l, j) = (
        upper.allocation.max_candidates,
        lower.allocation.max_candidates,
        budget.max_continuations,
    );
    if j > u {
        return Err(Terminal {
            reason: Refusal::InvalidRange,
            stop: PairStop::InvalidBudgetRelation,
            stage: PairStage::Preflight,
            target: None,
        });
    }
    let arithmetic = || -> Option<()> {
        u.checked_mul(upper.allocation.ranges.len())?;
        j.checked_mul(l)?.checked_mul(std::mem::size_of::<u64>())?;
        j.checked_mul(lower.allocation.ranges.len())?
            .checked_mul(l)?;
        u.checked_mul(3)?
            .checked_add(l.checked_mul(4)?)?
            .checked_add(j)?
            .checked_add(1)?
            .checked_mul(std::mem::size_of::<PairEvent>())?;
        Some(())
    };
    arithmetic().ok_or_else(|| eligibility(E::BudgetShape, Refusal::InvalidRange))?;
    if u == 0 {
        return Err(budget_stop(
            PairStop::UpperImagesBudget,
            PairStage::Preflight,
            None,
        ));
    }
    if l == 0 {
        return Err(budget_stop(
            PairStop::LowerImagesBudget,
            PairStage::Preflight,
            None,
        ));
    }
    if j == 0 {
        return Err(budget_stop(
            PairStop::JointContinuationsBudget,
            PairStage::Preflight,
            None,
        ));
    }
    let mut lower_pending = pending.to_vec();
    lower_pending.push(lower_range);
    lower_pending.sort_unstable_by_key(|range| range.start());
    Ok(Prepared {
        current,
        source,
        scans: [lower_scan, upper_scan],
        lower_pending,
    })
}

// Exact two-byte specialization of the existing kernel's current-suffix window.
// Called only after complete fetch qualification; still use checked arithmetic.
fn window(request: &PlanningRequest<'_>, current: &[u8]) -> Result<AddressRange, Refusal> {
    let offset = usize::try_from(
        request
            .logical_pc
            .checked_sub(request.base_address)
            .ok_or(Refusal::InvalidRange)?,
    )
    .map_err(|_| Refusal::InvalidRange)?;
    let start = offset.checked_add(2).ok_or(Refusal::InvalidRange)?;
    let end = offset.checked_add(5).ok_or(Refusal::InvalidRange)?;
    let suffix = current.get(start..end).ok_or(Refusal::InvalidRange)?;
    let displacement = i32::from_le_bytes([0, suffix[0], suffix[1], suffix[2]]);
    let low = u64::try_from(i128::from(request.logical_pc) + 5 + i128::from(displacement))
        .map_err(|_| Refusal::AllocationUnavailable)?;
    AddressRange::new(low, 256)
}

fn leaf(
    request: &PlanningRequest<'_>,
    current: &[u8],
    scan: &ScanResult,
    source: AddressRange,
    emission: &ArtifactEmission,
    target: u64,
) -> (Result<PlannedInstall, Refusal>, SearchEvidence) {
    let mut search = SearchEvidence::default();
    let mut result = plan_pun_with_context_core(
        &request.with_code(current),
        scan,
        source,
        emission.occupied(),
        0,
        &mut search,
        PunContext {
            scope: SearchScope::default(),
            callback_free: false,
            exact_target: Some(target),
        },
    );
    if let Ok(member) = &mut result {
        search.accepted = true;
        member.metrics.search = search.clone();
    }
    (result, search)
}

/// Plans two adjacent observing forward two-byte Jccs using only B2.
///
/// Supply lower then upper, identical immutable source/entry facts, exact two-byte
/// blocks and GeneralizedPunOnly/0-upstream/2-displaced/1-site search policies.
/// One shared artifact emission binds the declared target, symbolic hook and
/// supplied pre-existing occupancy. Original source/entry/occupancy completeness,
/// CPU, ABI and callback-code authority remain caller obligations.
///
/// Upper/lower image calls are cumulative under their existing max_candidates;
/// lower schedules retain the ORIGINAL cap/order, never the remaining allowance.
/// A continuation is charged even if its lower schedule is empty. Actual private
/// clone/append/pending and pair BundleBudget checks must all accept. The supplied
/// predecessor is never mutated. This returns two opaque artifacts, not a live
/// bundle or a frontend two-row transaction. Caller aggregate limits must still
/// include the predecessor; all legacy APIs and profile caps remain unchanged.
pub fn plan_adjacent_b2_with_emission_after(
    sites: [PlanningSite<'_>; 2],
    emission: &ArtifactEmission,
    predecessor: &Composition,
    external_pending: &[AddressRange],
    budget: AdjacentB2Budget,
) -> Result<AdjacentB2ArtifactPlan, AdjacentB2Failure> {
    let [lower, upper] = sites;
    let requests = sites.map(|site| PlanningRequest {
        site,
        original_code: site.code,
        emission: EmissionContext::Artifact(emission),
    });
    let mut state = State {
        evidence: PairEvidence {
            lower_pc: lower.logical_pc,
            upper_pc: upper.logical_pc,
            counts: PairCounts::default(),
            events: Vec::new(),
            upper_schedule: None,
            lower_schedules: Vec::new(),
            accepted: false,
            classification_complete: false,
        },
        upper: None,
        lower: None,
        last: None,
    };
    let result = (|| -> Result<([ArtifactPlan; 2], BundleMemory), Terminal> {
        let prepared = match preflight(&requests, emission, predecessor, external_pending, budget) {
            Ok(value) => value,
            Err(error) => {
                state.record(
                    PairStage::Preflight,
                    PairOutcome::Refused(error.reason.clone()),
                    state.evidence.counts,
                    None,
                );
                return Err(error);
            }
        };
        state.accept(PairStage::Preflight, state.evidence.counts, None);
        let upper_window = match window(&requests[1], &prepared.current) {
            Ok(value) => value,
            Err(reason) => {
                state.reject(
                    PairStage::UpperLeaf,
                    reason.clone(),
                    state.evidence.counts,
                    None,
                )?;
                return Err(Terminal {
                    reason,
                    stop: PairStop::Exhausted,
                    stage: PairStage::UpperLeaf,
                    target: None,
                });
            }
        };
        let upper_candidates = pun_candidates(upper_window, upper.allocation);
        state.evidence.upper_schedule = Some(PairSchedule {
            upper_ordinal: None,
            upper_target: None,
            window: upper_window,
            targets: upper_candidates.addresses.clone(),
            proof: upper_candidates.proof.clone(),
        });
        for (ui, ut) in upper_candidates.addresses.into_iter().enumerate() {
            if state.evidence.counts.joint == budget.max_continuations {
                return Err(budget_stop(
                    PairStop::JointContinuationsBudget,
                    PairStage::UpperLeaf,
                    Some(ut),
                ));
            }
            if state.evidence.counts.lower == lower.allocation.max_candidates {
                return Err(budget_stop(
                    PairStop::LowerImagesBudget,
                    PairStage::UpperLeaf,
                    Some(ut),
                ));
            }
            state.upper = Some((ui, ut));
            state.lower = None;
            let before = state.debit(PairStage::UpperLeaf)?;
            let (result, search) = leaf(
                &requests[1],
                &prepared.current,
                &prepared.scans[1],
                prepared.source,
                emission,
                ut,
            );
            let upper_member = match result {
                Ok(member) => {
                    state.accept(PairStage::UpperLeaf, before, Some(search));
                    member
                }
                Err(reason) => {
                    state.reject(PairStage::UpperLeaf, reason, before, Some(search))?;
                    continue;
                }
            };
            let mut after_upper = predecessor.clone();
            if let Err(reason) = after_upper.append(upper_member.plan()) {
                state.reject(PairStage::UpperAppend, reason, state.evidence.counts, None)?;
                continue;
            }
            state.accept(PairStage::UpperAppend, state.evidence.counts, None);
            if let Err(reason) = after_upper.require_unclaimed_ranges(&prepared.lower_pending) {
                state.reject(PairStage::UpperPending, reason, state.evidence.counts, None)?;
                continue;
            }
            state.accept(PairStage::UpperPending, state.evidence.counts, None);
            let before_scope = state.debit(PairStage::LowerSchedule)?;
            let current = match after_upper.planning_overlay(
                lower.identity,
                lower.base_address,
                lower.code,
            ) {
                Ok(value) => value,
                Err(reason) => {
                    state.record(
                        PairStage::LowerSchedule,
                        PairOutcome::Refused(reason.clone()),
                        before_scope,
                        None,
                    );
                    return Err(Terminal {
                        reason,
                        stop: PairStop::TerminalInvariant,
                        stage: PairStage::LowerSchedule,
                        target: None,
                    });
                }
            };
            let lower_window = match window(&requests[0], &current) {
                Ok(value) => value,
                Err(reason) => {
                    state.reject(PairStage::LowerSchedule, reason, before_scope, None)?;
                    continue;
                }
            };
            let lower_candidates = pun_candidates(lower_window, lower.allocation);
            state.evidence.lower_schedules.push(PairSchedule {
                upper_ordinal: Some(ui),
                upper_target: Some(ut),
                window: lower_window,
                targets: lower_candidates.addresses.clone(),
                proof: lower_candidates.proof.clone(),
            });
            if lower_candidates.addresses.is_empty() {
                state.record(
                    PairStage::LowerSchedule,
                    PairOutcome::EmptySchedule,
                    before_scope,
                    None,
                );
                state.last = Some((PairStage::LowerSchedule, Refusal::AllocationUnavailable));
            } else {
                state.accept(PairStage::LowerSchedule, before_scope, None);
            }
            for (li, lt) in lower_candidates.addresses.into_iter().enumerate() {
                if state.evidence.counts.lower == lower.allocation.max_candidates {
                    return Err(budget_stop(
                        PairStop::LowerImagesBudget,
                        PairStage::LowerLeaf,
                        Some(lt),
                    ));
                }
                state.lower = Some((li, lt));
                let before = state.debit(PairStage::LowerLeaf)?;
                let (result, search) = leaf(
                    &requests[0],
                    &current,
                    &prepared.scans[0],
                    prepared.source,
                    emission,
                    lt,
                );
                let lower_member = match result {
                    Ok(member) => {
                        state.accept(PairStage::LowerLeaf, before, Some(search));
                        member
                    }
                    Err(reason) => {
                        state.reject(PairStage::LowerLeaf, reason, before, Some(search))?;
                        continue;
                    }
                };
                let mut pair = after_upper.clone();
                if let Err(reason) = pair.append(lower_member.plan()) {
                    state.reject(PairStage::LowerAppend, reason, state.evidence.counts, None)?;
                    continue;
                }
                state.accept(PairStage::LowerAppend, state.evidence.counts, None);
                // Retained even though this exact two-byte domain adds no new
                // external lock after UpperPending: [L,L+5) outside [L,L+2)
                // is already inside the upper [L+2,L+7) lock.
                if let Err(reason) = pair.require_unclaimed_ranges(external_pending) {
                    state.reject(PairStage::LowerPending, reason, state.evidence.counts, None)?;
                    continue;
                }
                state.accept(PairStage::LowerPending, state.evidence.counts, None);
                let bundle = match PlannedBundle::compose(
                    predecessor.final_bytes().to_vec(),
                    vec![upper_member.clone(), lower_member.clone()],
                    budget.bundle,
                ) {
                    Ok(value) => value,
                    Err(reason) => {
                        state.reject(PairStage::Aggregate, reason, state.evidence.counts, None)?;
                        continue;
                    }
                };
                state.accept(PairStage::Aggregate, state.evidence.counts, None);
                state.evidence.accepted = true;
                return Ok((
                    [
                        ArtifactPlan::single(upper_member),
                        ArtifactPlan::single(lower_member),
                    ],
                    bundle.plan().memory(),
                ));
            }
            if let Some(target) = omitted(&lower_candidates.proof) {
                return Err(budget_stop(
                    PairStop::LowerImagesBudget,
                    PairStage::LowerSchedule,
                    Some(target),
                ));
            }
        }
        if let Some(target) = omitted(&upper_candidates.proof) {
            return Err(budget_stop(
                PairStop::UpperScheduleBudget,
                PairStage::UpperLeaf,
                Some(target),
            ));
        }
        let (stage, reason) = state
            .last
            .clone()
            .unwrap_or((PairStage::UpperLeaf, Refusal::AllocationUnavailable));
        Err(Terminal {
            reason,
            stop: PairStop::Exhausted,
            stage,
            target: None,
        })
    })();
    match result {
        Ok((members, memory)) => Ok(AdjacentB2ArtifactPlan {
            members,
            memory,
            logical_pcs: [upper.logical_pc, lower.logical_pc],
            evidence: state.evidence,
        }),
        Err(error) => Err(AdjacentB2Failure {
            reason: error.reason,
            stop: error.stop,
            stage: error.stage,
            evidence: Box::new(state.evidence),
            unvisited_target: error.target,
        }),
    }
}

#[cfg(test)]
mod tests;
