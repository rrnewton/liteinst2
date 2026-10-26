//! Generation-bound install-once rewriting of caller-certified basic blocks.
//!
//! This path uses a scoped quiescence lease and Linux sync-core. It never uses
//! the legacy concurrent publisher's empirical staleness budget. See
//! `INTERFACES.md` for the caller's mapping, entry, signal, and ABI obligations.

use std::io::Read;

use iced_x86::{FlowControl, Mnemonic};

use crate::contracts::*;
use crate::emission::{ArtifactPlan, ArtifactRequest, PlanningRequest};
use crate::planner::HookSemantics;
use crate::scanner::{InstructionScanner, ScanResult};
use crate::search::{RefusalClass, SearchDomain, SearchEvidence, SearchScope};
use crate::trampoline::{ExecutableTrampoline, HookCallback, TrampolineImage, TrampolinePlan};

/// Install-once ordering, with explicit modes for forced tactic qualification.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TacticPolicy {
    /// Try the generalized instruction pun before any relocation window.
    #[default]
    PreferGeneralizedPun,
    /// Require a generalized pun; never substitute relocation for a refusal.
    GeneralizedPunOnly,
    /// Require T1 prefix padding; never substitute an ordinary pun or relocation.
    PrefixPunOnly,
    /// Require the same-site/upstream relocation engine.
    RelocationOnly,
}

/// Tactic associated with one successful or refused candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PatchTactic {
    /// Change the original instruction while consuming unchanged successor bytes.
    GeneralizedPun,
    /// T1: redundant CS prefixes shift the fixed successor displacement bytes.
    PrefixPun,
    /// Relocate a whole-instruction redirect window.
    Relocation,
}

/// Bounded same-block search. Bounds are refusals, never permission to skip sites.
#[derive(Clone, Copy, Debug)]
pub struct SearchPolicy {
    /// Tactic ordering; forced modes retain required-positive coverage.
    pub tactics: TacticPolicy,
    /// Maximum backward distance from logical to physical PC.
    pub max_upstream_bytes: usize,
    /// Maximum whole-instruction displaced interval.
    pub max_displaced_bytes: usize,
    /// Maximum physical instruction heads considered.
    pub max_sites: usize,
}
impl Default for SearchPolicy {
    fn default() -> Self {
        Self {
            tactics: TacticPolicy::PreferGeneralizedPun,
            max_upstream_bytes: 64,
            max_displaced_bytes: 80,
            max_sites: 65,
        }
    }
}

/// Permitted executable placement and explicit search/memory budgets.
#[derive(Clone, Debug)]
pub struct AllocationPolicy {
    /// Every complete allocated page must lie in one of these ranges.
    pub ranges: Vec<AddressRange>,
    /// First target to try (constraints may change its displacement bytes).
    pub preferred_address: Option<u64>,
    /// Bound on generated addresses per tactic candidate (one site and, for
    /// T1, one prefix count). A search tries at most `max_sites` relocation
    /// candidates, one generalized pun and three prefixed puns.
    pub max_candidates: usize,
    /// Maximum new executable mappings; this implementation needs one.
    pub max_mappings: usize,
    /// Maximum newly allocated executable backing bytes.
    pub max_mapped_bytes: usize,
}
impl AllocationPolicy {
    /// Permits an ordinary near mapping within signed rel32 reach.
    pub fn near(address: u64) -> Result<Self, Refusal> {
        let next = address.checked_add(5).ok_or(Refusal::InvalidRange)?;
        let low = next.saturating_sub(1 << 31).max(0x1_0000);
        let high = next
            .checked_add(i32::MAX as u64)
            .ok_or(Refusal::InvalidRange)?;
        Ok(Self {
            ranges: vec![AddressRange::new(low, (high - low) as usize)?],
            preferred_address: None,
            max_candidates: 256,
            max_mappings: 1,
            max_mapped_bytes: 8192,
        })
    }
}

/// Authenticated snapshot and facts needed by the quiescent planner.
pub struct InstallRequest<'a> {
    /// Non-reusable original mapping identity.
    pub identity: CodeIdentity,
    /// Exact bytes; the entire supplied range becomes a read dependency.
    pub code: &'a [u8],
    /// Executable address corresponding to code[0].
    pub base_address: u64,
    /// Caller-certified containing function.
    pub function: AddressRange,
    /// Caller-certified containing basic block; upstream search cannot leave it.
    pub block: AddressRange,
    /// Original instruction at which the callback belongs.
    pub logical_pc: u64,
    /// Exhaustive static and dynamic entry facts.
    pub entries: &'a LegalEntrySet,
    /// Non-unwinding System V callback, under the documented state contract.
    pub hook: HookCallback,
    /// Observe, or replace the logical instruction only.
    pub semantics: HookSemantics,
    /// Permitted allocations and resource limits.
    pub allocation: &'a AllocationPolicy,
    /// Bounded site search.
    pub search: SearchPolicy,
}

/// One bounded physical-site search result.
#[derive(Clone, Debug)]
pub struct SiteAttempt {
    /// Explicit attempted tactic, including attempts at the same physical PC.
    pub tactic: PatchTactic,
    /// Candidate physical PC.
    pub physical_pc: u64,
    /// None means this physical site was selected.
    pub refusal: Option<Refusal>,
}

/// Measured plan shape (no host-dependent performance claim).
#[derive(Clone, Debug)]
pub struct PlanMetrics {
    /// Explicit bounded-search evidence; incomplete proofs remain marked.
    pub search: SearchEvidence,
    /// Logical minus physical PC.
    pub upstream_bytes: usize,
    /// Whole original instruction bytes displaced.
    pub displaced_bytes: usize,
    /// Instructions executed before the logical hook.
    pub prefix_instructions: usize,
    /// Candidate-search iterations for the selected physical site.
    pub allocation_attempts: usize,
    /// Ordered site attempts including refusals.
    pub attempts: Vec<SiteAttempt>,
}

/// Pure plan and emitted image; no executable mapping has been changed.
#[derive(Clone, Debug)]
pub struct PlannedInstall {
    pub(crate) plan: PatchPlan,
    pub(crate) image: TrampolineImage,
    pub(crate) metrics: PlanMetrics,
}
impl PlannedInstall {
    /// Shared immutable contract consumed by admission.
    pub const fn plan(&self) -> &PatchPlan {
        &self.plan
    }
    /// Generated image, exact entry routes, and architectural comparison boundaries.
    pub const fn image(&self) -> &TrampolineImage {
        &self.image
    }
    /// Search outcomes and displaced shape.
    pub const fn metrics(&self) -> &PlanMetrics {
        &self.metrics
    }

    /// Publishes this permanent interception under a held dependency lease.
    ///
    /// # Safety
    /// `writable_base` must alias the complete original read snapshot and remain
    /// valid through retirement. The lease owner enforces all documented
    /// quiescence, alias, saved-context and signal contracts. Execution must
    /// meet the declared System V/no-CET ABI and have sufficient writable stack
    /// below the red zone for the callback and extended-state image.
    /// A pun requires executable fetch permissions for its entire `consumed`
    /// range (five bytes, or 5+P with T1 prefixes), including unchanged successors.
    pub unsafe fn publish(
        &self,
        writable_base: *mut u8,
        lease: &mut QuiescenceLease<'_>,
    ) -> Result<(InstalledOnce, PublicationReceipt), PublicationFailure> {
        // SAFETY: forwarded from this entrypoint's contract.
        let mut publisher = unsafe { LivePublisher::new(self, writable_base) };
        publisher.publish_quiescent(&self.plan, lease)
    }
}

/// Failed planning with the attempted-site inventory retained.
#[derive(Clone, Debug)]
pub struct PlanningFailure {
    /// Explicit bounded-search evidence; incomplete proofs remain marked.
    pub search: SearchEvidence,
    /// Final fail-closed reason.
    pub reason: Refusal,
    /// Ordered candidates and their precise failure reasons.
    pub attempts: Vec<SiteAttempt>,
}

/// Plans installation without writing source bytes or reserving executable memory.
pub fn plan_install(request: &InstallRequest<'_>) -> Result<PlannedInstall, Refusal> {
    plan_install_detailed(request).map_err(|failure| failure.reason)
}

/// Planning entrypoint retaining all bounded candidate refusal evidence.
pub fn plan_install_detailed(
    request: &InstallRequest<'_>,
) -> Result<PlannedInstall, PlanningFailure> {
    plan_install_core(&PlanningRequest::live(request))
}

/// Plans B1/B2/T1 with an explicit symbolic target. The returned artifact
/// retains unresolved CPU/loader/provenance/ABI requirements and cannot publish.
pub fn plan_install_with_emission(
    request: &ArtifactRequest<'_>,
) -> Result<ArtifactPlan, PlanningFailure> {
    plan_install_core(&PlanningRequest::artifact(request)).map(ArtifactPlan::single)
}

pub(crate) fn plan_install_core(
    request: &PlanningRequest<'_>,
) -> Result<PlannedInstall, PlanningFailure> {
    let mut attempts = Vec::new();
    let mut search_evidence = SearchEvidence::default();
    let result = (|| {
        let (source, scan) = validated_source_core(request).inspect_err(|reason| {
            search_evidence.qualification(SearchScope::default(), reason);
        })?;
        let occupied = request.emission.occupied()?;
        if request.search.max_sites == 0 {
            let id =
                search_evidence.begin(SearchDomain::PhysicalSites, SearchScope::default(), 0, None);
            if request.search.tactics == TacticPolicy::PrefixPunOnly {
                // This gate precedes the length-dependent prefix domain. A
                // validated head alone does not prove any T1 prefix exists.
                search_evidence.finish(id);
            } else {
                search_evidence.known_limit_hit(id, 1);
            }
            return Err(Refusal::NoPatchWindow);
        }
        if matches!(
            request.search.tactics,
            TacticPolicy::PreferGeneralizedPun | TacticPolicy::GeneralizedPunOnly
        ) {
            match plan_pun(
                request,
                &scan,
                source,
                &occupied,
                0,
                &mut search_evidence,
                SearchScope::default(),
            ) {
                Ok(mut plan) => {
                    attempts.push(SiteAttempt {
                        tactic: PatchTactic::GeneralizedPun,
                        physical_pc: request.logical_pc,
                        refusal: None,
                    });
                    plan.metrics.attempts = attempts.clone();
                    return Ok(plan);
                }
                Err(reason) => {
                    attempts.push(SiteAttempt {
                        tactic: PatchTactic::GeneralizedPun,
                        physical_pc: request.logical_pc,
                        refusal: Some(reason.clone()),
                    });
                    if request.search.tactics == TacticPolicy::GeneralizedPunOnly {
                        return Err(reason);
                    }
                }
            }
        }
        let mut candidates: Vec<_> = scan
            .instructions()
            .iter()
            .filter(|i| {
                request.block.contains(i.address())
                    && i.address() <= request.logical_pc
                    && request.logical_pc - i.address() <= request.search.max_upstream_bytes as u64
            })
            .map(|i| i.address())
            .collect();
        candidates.reverse();
        // Same-site first; otherwise favor a single-cache-line store, then the
        // nearest upstream head. Quiescence is required for every placement.
        candidates.sort_by_key(|&pc| {
            (
                pc != request.logical_pc,
                pc % 64 > 56,
                request.logical_pc - pc,
            )
        });
        if request.search.tactics == TacticPolicy::PrefixPunOnly {
            candidates.clear();
        }
        let sites = search_evidence.begin(
            SearchDomain::PhysicalSites,
            SearchScope::default(),
            request.search.max_sites,
            Some(candidates.len()),
        );
        for physical in candidates.into_iter().take(request.search.max_sites) {
            search_evidence.visit(sites);
            match plan_at(
                request,
                &scan,
                source,
                physical,
                &occupied,
                &mut search_evidence,
            ) {
                Ok(mut plan) => {
                    search_evidence.accept(sites);
                    attempts.push(SiteAttempt {
                        tactic: PatchTactic::Relocation,
                        physical_pc: physical,
                        refusal: None,
                    });
                    plan.metrics.attempts = attempts.clone();
                    return Ok(plan);
                }
                Err(reason) => attempts.push(SiteAttempt {
                    tactic: PatchTactic::Relocation,
                    physical_pc: physical,
                    refusal: Some(reason),
                }),
            }
        }
        search_evidence.finish(sites);
        if matches!(
            request.search.tactics,
            TacticPolicy::PreferGeneralizedPun | TacticPolicy::PrefixPunOnly
        ) {
            let len = scan
                .instructions()
                .iter()
                .find(|item| item.address() == request.logical_pc)
                .ok_or(Refusal::NotInstructionHead)?
                .len();
            if (2..=4).contains(&len) {
                for prefix_count in 1..len {
                    match plan_pun(
                        request,
                        &scan,
                        source,
                        &occupied,
                        prefix_count,
                        &mut search_evidence,
                        SearchScope::default(),
                    ) {
                        Ok(mut plan) => {
                            attempts.push(SiteAttempt {
                                tactic: PatchTactic::PrefixPun,
                                physical_pc: request.logical_pc,
                                refusal: None,
                            });
                            plan.metrics.attempts = attempts.clone();
                            return Ok(plan);
                        }
                        Err(reason) => attempts.push(SiteAttempt {
                            tactic: PatchTactic::PrefixPun,
                            physical_pc: request.logical_pc,
                            refusal: Some(reason),
                        }),
                    }
                }
            }
        }
        Err(attempts
            .last()
            .and_then(|attempt| attempt.refusal.clone())
            .unwrap_or(Refusal::NoPatchWindow))
    })();
    match result {
        Ok(mut plan) => {
            search_evidence.accepted = true;
            plan.metrics.search = search_evidence;
            Ok(plan)
        }
        Err(reason) => Err(PlanningFailure {
            reason,
            attempts,
            search: search_evidence,
        }),
    }
}

/// Plans one shared relocation window with independent observing controls.
///
/// Controls name strictly increasing, distinct original heads; their handles
/// must be distinct too. The first head is request.logical_pc. All controls and
/// displaced instructions remain inside the certified basic block and the existing
/// byte/search/allocation bounds. Existing source-entry and publication proofs
/// apply. This forced coalesced path does not select a pun or evict a victim.
/// The request must use Observe semantics; conditional replacement is separate.
/// This API retains the ordinary no-interior-control-transfer rule. The action
/// controls supply callbacks; request.hook and request.search.tactics are unused.
pub fn plan_coalesced(
    request: &InstallRequest<'_>,
    actions: &[crate::controls::ControlledAction],
) -> Result<PlannedInstall, Refusal> {
    plan_coalesced_detailed(request, actions).map_err(|failure| failure.reason)
}

/// Coalesced planning with the complete bounded physical-site inventory.
pub fn plan_coalesced_detailed(
    request: &InstallRequest<'_>,
    actions: &[crate::controls::ControlledAction],
) -> Result<PlannedInstall, PlanningFailure> {
    plan_coalesced_core(&PlanningRequest::live(request), actions)
}

fn plan_coalesced_core(
    request: &PlanningRequest<'_>,
    actions: &[crate::controls::ControlledAction],
) -> Result<PlannedInstall, PlanningFailure> {
    let mut attempts = Vec::new();
    let mut search_evidence = SearchEvidence::default();
    let result = (|| {
        if request.semantics != HookSemantics::Observe {
            return Err(Refusal::UnsupportedSemantics(
                "runtime coalesced controls currently require observing hooks".into(),
            ));
        }
        if actions.first().map(|action| action.logical_pc) != Some(request.logical_pc)
            || actions.iter().enumerate().any(|(index, action)| {
                (index > 0 && actions[index - 1].logical_pc >= action.logical_pc)
                    || actions[..index]
                        .iter()
                        .any(|prior| prior.control == action.control)
            })
        {
            return Err(Refusal::InvalidPlan);
        }
        let (source, scan) = validated_source_core(request)
            .inspect_err(|reason| search_evidence.qualification(SearchScope::default(), reason))?;
        for action in actions {
            if !request.block.contains(action.logical_pc) {
                return Err(Refusal::InvalidRange);
            }
            if scan.site(action.logical_pc).is_none() {
                return Err(Refusal::NotInstructionHead);
            }
        }
        if request.search.max_sites == 0 {
            let id =
                search_evidence.begin(SearchDomain::PhysicalSites, SearchScope::default(), 0, None);
            search_evidence.known_limit_hit(id, 1);
            return Err(Refusal::NoPatchWindow);
        }
        let occupied = request.emission.occupied()?;
        let mut candidates: Vec<_> = scan
            .instructions()
            .iter()
            .filter(|item| {
                request.block.contains(item.address())
                    && item.address() <= request.logical_pc
                    && request.logical_pc - item.address()
                        <= request.search.max_upstream_bytes as u64
            })
            .map(|item| item.address())
            .collect();
        candidates.sort_by_key(|&pc| {
            (
                pc != request.logical_pc,
                pc % 64 > 56,
                request.logical_pc - pc,
            )
        });
        let sites = search_evidence.begin(
            SearchDomain::PhysicalSites,
            SearchScope::default(),
            request.search.max_sites,
            Some(candidates.len()),
        );
        for physical in candidates.into_iter().take(request.search.max_sites) {
            search_evidence.visit(sites);
            match plan_at_with_controls(
                request,
                &scan,
                source,
                physical,
                &occupied,
                Some(actions),
                &mut search_evidence,
            ) {
                Ok(mut plan) => {
                    search_evidence.accept(sites);
                    attempts.push(SiteAttempt {
                        tactic: PatchTactic::Relocation,
                        physical_pc: physical,
                        refusal: None,
                    });
                    plan.metrics.attempts = attempts.clone();
                    return Ok(plan);
                }
                Err(reason) => attempts.push(SiteAttempt {
                    tactic: PatchTactic::Relocation,
                    physical_pc: physical,
                    refusal: Some(reason),
                }),
            }
        }
        search_evidence.finish(sites);
        Err(attempts
            .last()
            .and_then(|attempt| attempt.refusal.clone())
            .unwrap_or(Refusal::NoPatchWindow))
    })();
    match result {
        Ok(mut plan) => {
            search_evidence.accepted = true;
            plan.metrics.search = search_evidence;
            Ok(plan)
        }
        Err(reason) => Err(PlanningFailure {
            reason,
            attempts,
            search: search_evidence,
        }),
    }
}

pub(crate) fn validated_source(
    request: &InstallRequest<'_>,
) -> Result<(AddressRange, ScanResult), Refusal> {
    validated_source_core(&PlanningRequest::live(request))
}

pub(crate) fn validated_source_core(
    request: &PlanningRequest<'_>,
) -> Result<(AddressRange, ScanResult), Refusal> {
    let source = AddressRange::new(request.base_address, request.code.len())?;
    if request.entries.identity != request.identity {
        return Err(Refusal::StaleGeneration);
    }
    if request.entries.completeness == EntryCompleteness::Incomplete
        || request.entries.resumes == ResumeObligation::Unresolved
    {
        return Err(Refusal::UnresolvedEntry);
    }
    if !source.covers(request.function)
        || !request.function.covers(request.block)
        || !request.block.contains(request.logical_pc)
        || !request.entries.scope.covers(request.block)
    {
        return Err(Refusal::InvalidRange);
    }
    request.emission.qualify()?;
    let scan = InstructionScanner::default()
        .scan(request.code, request.base_address)
        .map_err(|e| Refusal::Backend(e.to_string()))?;
    if scan.site(request.logical_pc).is_none()
        || scan.site(request.block.start()).is_none()
        || (request.block.end() != source.end() && scan.site(request.block.end()).is_none())
    {
        return Err(Refusal::NotInstructionHead);
    }
    for entry in &request.entries.entries {
        if !request.entries.scope.contains(entry.address)
            || (source.contains(entry.address) && scan.site(entry.address).is_none())
        {
            return Err(Refusal::NotInstructionHead);
        }
    }
    if let ResumeObligation::Enumerated(pcs) = &request.entries.resumes {
        for &pc in pcs {
            if !request.entries.scope.contains(pc)
                || (source.contains(pc) && scan.site(pc).is_none())
            {
                return Err(Refusal::NotInstructionHead);
            }
        }
    }
    Ok((source, scan))
}

pub(crate) fn plan_pun(
    request: &PlanningRequest<'_>,
    scan: &ScanResult,
    source: AddressRange,
    occupied: &[AddressRange],
    prefixes: usize,
    search_evidence: &mut SearchEvidence,
    parent_scope: SearchScope,
) -> Result<PlannedInstall, Refusal> {
    plan_pun_with_context_core(
        request,
        scan,
        source,
        occupied,
        prefixes,
        search_evidence,
        PunContext {
            scope: parent_scope,
            callback_free: false,
            exact_target: None,
        },
    )
}

/// Internal composition only. The original public planner uses the unchanged
/// schedule and observing/replacing constructor through the wrapper above.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PunContext {
    pub(crate) scope: SearchScope,
    pub(crate) callback_free: bool,
    pub(crate) exact_target: Option<u64>,
}

pub(crate) fn plan_pun_with_context(
    request: &InstallRequest<'_>,
    scan: &ScanResult,
    source: AddressRange,
    occupied: &[AddressRange],
    prefixes: usize,
    search_evidence: &mut SearchEvidence,
    context: PunContext,
) -> Result<PlannedInstall, Refusal> {
    plan_pun_with_context_core(
        &PlanningRequest::live(request),
        scan,
        source,
        occupied,
        prefixes,
        search_evidence,
        context,
    )
}

fn plan_pun_with_context_core(
    request: &PlanningRequest<'_>,
    scan: &ScanResult,
    source: AddressRange,
    occupied: &[AddressRange],
    prefixes: usize,
    search_evidence: &mut SearchEvidence,
    context: PunContext,
) -> Result<PlannedInstall, Refusal> {
    let parent_scope = context.scope;
    let physical = request.logical_pc;
    let scope = SearchScope {
        physical_pc: Some(physical),
        prefix_count: Some(prefixes),
        ..parent_scope
    };
    let instruction = scan
        .instructions()
        .iter()
        .find(|item| item.address() == physical)
        .ok_or(Refusal::NotInstructionHead)?;
    let len = instruction.len();
    let displaced = AddressRange::new(physical, len)?;
    let consumed = AddressRange::new(physical, 5 + prefixes)?;
    if !(1..=4).contains(&len)
        || prefixes >= len
        || len > request.search.max_displaced_bytes
        || !request.block.covers(displaced)
        || !source.covers(consumed)
        || physical / 64 != (displaced.end() - 1) / 64
    {
        search_evidence.qualification(scope, &Refusal::NoPatchWindow);
        return Err(Refusal::NoPatchWindow);
    }
    if context.callback_free || request.semantics != HookSemantics::ReplaceFirst {
        qualify_instruction(instruction.instruction())
            .inspect_err(|reason| search_evidence.qualification(scope, reason))?;
    }
    if request
        .entries
        .entries
        .iter()
        .any(|entry| displaced.contains(entry.address) && entry.requires_endbr)
    {
        return Err(Refusal::UnsupportedSemantics(
            "CET IBT landing pad in pun".into(),
        ));
    }
    // A direct branch into the middle of the original instruction is positive
    // evidence against the caller's non-overlapping stream claim.
    if scan.instructions().iter().any(|item| {
        matches!(
            item.instruction().op0_kind(),
            iced_x86::OpKind::NearBranch16
                | iced_x86::OpKind::NearBranch32
                | iced_x86::OpKind::NearBranch64
        ) && displaced.contains(item.instruction().near_branch_target())
            && item.instruction().near_branch_target() != physical
    }) {
        return Err(Refusal::NotInstructionHead);
    }
    let store_len = len.next_power_of_two();
    // x86 has no three-byte MOV. Keep a four-byte store in this cache line by
    // preserving the successor byte, or the preceding byte at offset 61.
    let store_address = physical.min((physical | 63) - (store_len as u64 - 1));
    let store_range = AddressRange::new(store_address, store_len)?;
    if !source.covers(store_range) {
        search_evidence.qualification(scope, &Refusal::NoPatchWindow);
        return Err(Refusal::NoPatchWindow);
    }
    let offset = (physical - source.start()) as usize;
    let mut fixed = [0_u8; 4];
    let free = len - prefixes - 1;
    fixed[free..].copy_from_slice(&request.code[offset + len..offset + 5 + prefixes]);
    let next = i128::from(physical) + 5 + prefixes as i128;
    let low = u64::try_from(next + i128::from(i32::from_le_bytes(fixed)))
        .map_err(|_| Refusal::AllocationUnavailable)?;
    let window = AddressRange::new(low, 1_usize << (8 * free))?;
    let policy = request.allocation;
    if policy.max_mappings == 0 || policy.max_mapped_bytes < 4096 {
        search_evidence.refusal(
            scope,
            RefusalClass::ResourceCapacity,
            &Refusal::AllocationUnavailable,
        );
        return Err(Refusal::AllocationUnavailable);
    }
    let trampoline = if context.callback_free {
        TrampolinePlan::from_instruction(scan, physical)
    } else {
        request.emission.short(
            scan,
            physical,
            request.semantics == HookSemantics::ReplaceFirst,
        )
    }
    .map_err(|e| Refusal::Backend(e.to_string()))?;
    let candidates = if let Some(target) = context.exact_target {
        if policy.max_candidates == 0 || !window.contains(target) {
            return Err(Refusal::AllocationUnavailable);
        }
        PunCandidates {
            addresses: vec![target],
            proof: crate::search::CandidateProof::Indexed {
                permanent_end_exclusive: Some(1),
                omitted: None,
            },
        }
    } else {
        pun_candidates(window, policy)
    };
    let mut last_error = Refusal::AllocationUnavailable;
    let image_search = search_evidence.begin(
        SearchDomain::SelectedImages,
        scope,
        policy.max_candidates,
        None,
    );
    for (attempt, target) in candidates.addresses.into_iter().enumerate() {
        search_evidence.visit(image_search);
        let image = match request.emission.emit(&trampoline, target) {
            Ok(image) => image,
            Err(error) => {
                last_error = Refusal::Backend(error.to_string());
                continue;
            }
        };
        let page_start = target & !4095;
        let page_end = target
            .checked_add(image.bytes().len() as u64)
            .and_then(|end| end.checked_add(4095))
            .map(|end| end & !4095)
            .ok_or(Refusal::InvalidRange)?;
        let allocation = AddressRange::new(page_start, (page_end - page_start) as usize)?;
        if allocation.len() > policy.max_mapped_bytes as u64
            || !policy.ranges.iter().any(|range| range.covers(allocation))
            || occupied.iter().any(|range| range.overlaps(allocation))
        {
            let class = if allocation.len() > policy.max_mapped_bytes as u64 {
                RefusalClass::ResourceCapacity
            } else {
                RefusalClass::AddressPolicy
            };
            search_evidence.refusal(scope, class, &Refusal::AllocationUnavailable);
            continue;
        }
        let displacement = i32::try_from(i128::from(target) - next)
            .map_err(|_| Refusal::AllocationUnavailable)?
            .to_le_bytes();
        debug_assert_eq!(&displacement[free..], &fixed[free..]);
        let mut bytes = vec![0x2e; prefixes];
        bytes.push(0xe9);
        bytes.extend_from_slice(&displacement[..free]);
        if prefixes != 0 {
            // Qualify the exact consumed encoding under the supported legacy/
            // EVEX no-CET envelope; only redundant CS prefixes are admitted.
            let mut fetch = request.code[offset..offset + 5 + prefixes].to_vec();
            fetch[..len].copy_from_slice(&bytes);
            let mut decoder =
                iced_x86::Decoder::with_ip(64, &fetch, physical, iced_x86::DecoderOptions::NONE);
            let jump = decoder.decode();
            if jump.code() != iced_x86::Code::Jmp_rel32_64
                || jump.len() != fetch.len()
                || jump.near_branch_target() != target
                || decoder.can_decode()
            {
                return Err(Refusal::UnsupportedSemantics(
                    "unqualified prefixed E9 encoding".into(),
                ));
            }
        }
        let store_offset = (store_address - source.start()) as usize;
        let mut stored = request.code[store_offset..store_offset + store_len].to_vec();
        let within_store = (physical - store_address) as usize;
        stored[within_store..within_store + len].copy_from_slice(&bytes);
        // Successor entries remain at their original addresses and need no router.
        let mut preserved = vec![physical];
        preserved.extend(
            scan.instructions()
                .iter()
                .filter(|item| consumed.contains(item.address()))
                .map(|item| item.address()),
        );
        preserved.sort_unstable();
        preserved.dedup();
        let store = ByteEdit {
            address: store_address,
            bytes: stored,
        };
        let kind = if prefixes == 0 {
            PlanKind::GeneralizedPun(GeneralizedPun {
                instruction_len: len as u8,
                consumed,
                target_window: window,
                store,
            })
        } else {
            PlanKind::PrefixedPun(PrefixedPun {
                instruction_len: len as u8,
                prefix_count: prefixes as u8,
                consumed,
                target_window: window,
                store,
            })
        };
        let plan = PatchPlan::checked(PlanParts {
            identity: request.identity,
            profile: ApplicationProfile::InstallOnce,
            kind,
            logical_pc: physical,
            physical_pc: physical,
            displaced,
            reads: vec![ExpectedBytes {
                address: source.start(),
                bytes: request.code.to_vec(),
            }],
            writes: vec![ByteEdit {
                address: physical,
                bytes,
            }],
            dependencies: vec![source],
            entries: request.entries.clone(),
            obligations: preserved
                .into_iter()
                .map(EntryObligation::Preserved)
                .collect(),
            allocations: vec![AllocationRequest {
                range: allocation,
                alignment: 4096,
            }],
            generated: vec![GeneratedCode {
                address: target,
                bytes: image.bytes().to_vec(),
                program_counters: image.program_counter_mappings().to_vec(),
            }],
            requirements: PublicationRequirements {
                quiescent: true,
                sync_core: true,
                sigill_router: false,
            },
        })?;
        search_evidence.accept(image_search);
        return Ok(PlannedInstall {
            plan,
            image,
            metrics: PlanMetrics {
                search: SearchEvidence::default(),
                upstream_bytes: 0,
                displaced_bytes: len,
                prefix_instructions: 0,
                allocation_attempts: attempt + 1,
                attempts: vec![],
            },
        });
    }
    search_evidence.finish_candidates(image_search, candidates.proof);
    Err(last_error)
}

pub(crate) fn pun_candidates(window: AddressRange, policy: &AllocationPolicy) -> PunCandidates {
    let mut addresses = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut add = |address| {
        if addresses.len() < policy.max_candidates && seen.insert(address) {
            addresses.push(address);
        }
    };
    if let Some(preferred) = policy.preferred_address.filter(|&pc| window.contains(pc)) {
        add(preferred);
    }
    for range in &policy.ranges {
        let Some(first_page) = range.start().checked_add(4095).map(|x| x & !4095) else {
            continue;
        };
        let mut address = window.start().max(first_page);
        let end = window.end().min(range.end());
        // At most one candidate per mapping boundary, plus the preferred target.
        // Avoid work proportional to a caller's arbitrarily broad address range.
        for _ in 0..policy.max_candidates {
            if address >= end {
                break;
            }
            add(address);
            let Some(next) = (address | 4095).checked_add(1) else {
                break;
            };
            address = next;
        }
    }
    let proof = pun_candidate_proof(window, policy, &addresses);
    PunCandidates { addresses, proof }
}

fn plan_at(
    request: &PlanningRequest<'_>,
    scan: &ScanResult,
    source: AddressRange,
    physical: u64,
    occupied: &[AddressRange],
    search_evidence: &mut SearchEvidence,
) -> Result<PlannedInstall, Refusal> {
    plan_at_with_controls(
        request,
        scan,
        source,
        physical,
        occupied,
        None,
        search_evidence,
    )
}

fn plan_at_with_controls(
    request: &PlanningRequest<'_>,
    scan: &ScanResult,
    source: AddressRange,
    physical: u64,
    occupied: &[AddressRange],
    controls: Option<&[crate::controls::ControlledAction]>,
    search_evidence: &mut SearchEvidence,
) -> Result<PlannedInstall, Refusal> {
    let scope = SearchScope {
        physical_pc: Some(physical),
        ..SearchScope::default()
    };
    let last_logical = controls
        .and_then(|actions| actions.last())
        .map_or(request.logical_pc, |action| action.logical_pc);
    let mut end = physical;
    let mut instructions = Vec::new();
    for item in scan
        .instructions()
        .iter()
        .filter(|i| i.address() >= physical)
    {
        if item.address() >= request.block.end() {
            break;
        }
        end = item.address() + item.len() as u64;
        if end > request.block.end() || end - physical > request.search.max_displaced_bytes as u64 {
            search_evidence.qualification(scope, &Refusal::NoPatchWindow);
            return Err(Refusal::NoPatchWindow);
        }
        instructions.push(item);
        if end - physical >= 5 && end > last_logical {
            break;
        }
    }
    if end - physical < 5 || end <= last_logical {
        search_evidence.qualification(scope, &Refusal::NoPatchWindow);
        return Err(Refusal::NoPatchWindow);
    }
    let displaced = AddressRange::new(physical, (end - physical) as usize)?;
    for item in &instructions {
        let replaced = item.address() == request.logical_pc
            && request.semantics == HookSemantics::ReplaceFirst;
        if !replaced {
            qualify_instruction(item.instruction())
                .inspect_err(|reason| search_evidence.qualification(scope, reason))?;
            if item.instruction().flow_control() != FlowControl::Next
                && item.address() + item.len() as u64 != end
            {
                return Err(Refusal::UnsupportedSemantics(
                    "control transfer before displaced end".into(),
                ));
            }
        }
    }
    // Positive direct targets in the supplied snapshot cannot be omitted even
    // by an erroneous Complete entry list. Alternate streams remain refused.
    let mut heads: Vec<u64> = request.entries.entries.iter().map(|e| e.address).collect();
    if request.entries.completeness == EntryCompleteness::AllInstructionHeads {
        heads.extend(instructions.iter().map(|i| i.address()));
    }
    if let ResumeObligation::Enumerated(pcs) = &request.entries.resumes {
        heads.extend(pcs);
    }
    for item in scan.instructions() {
        if matches!(
            item.instruction().op0_kind(),
            iced_x86::OpKind::NearBranch16
                | iced_x86::OpKind::NearBranch32
                | iced_x86::OpKind::NearBranch64
        ) {
            heads.push(item.instruction().near_branch_target());
        }
    }
    heads.retain(|&pc| displaced.contains(pc) && pc != physical);
    heads.sort_unstable();
    heads.dedup();
    if heads.iter().any(|&pc| scan.site(pc).is_none()) {
        return Err(Refusal::NotInstructionHead);
    }
    if request
        .entries
        .entries
        .iter()
        .any(|entry| displaced.contains(entry.address) && entry.requires_endbr)
    {
        return Err(Refusal::UnsupportedSemantics(
            "CET IBT landing pad in displaced range".into(),
        ));
    }
    let trampoline = match controls {
        Some(actions) => TrampolinePlan::from_controlled_actions(scan, physical, end, actions),
        None => request.emission.window(
            scan,
            physical,
            request.logical_pc,
            end,
            request.semantics == HookSemantics::ReplaceFirst,
        ),
    }
    .map_err(|e| Refusal::Backend(e.to_string()))?;
    let mut mask = [false; 4];
    for &head in &heads {
        if head < physical + 5 {
            mask[(head - physical - 1) as usize] = true;
        }
    }
    let policy = request.allocation;
    if policy.max_mappings == 0 || policy.max_mapped_bytes < 4096 {
        search_evidence.refusal(
            scope,
            RefusalClass::ResourceCapacity,
            &Refusal::AllocationUnavailable,
        );
        return Err(Refusal::AllocationUnavailable);
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut last_error = Refusal::AllocationUnavailable;
    let image_search = search_evidence.begin(
        SearchDomain::SelectedImages,
        scope,
        policy.max_candidates,
        None,
    );
    for attempt in 0..policy.max_candidates {
        search_evidence.visit(image_search);
        let Some(target) = candidate_target(physical, mask, policy.preferred_address, attempt)
        else {
            continue;
        };
        if !seen.insert(target) {
            continue;
        }
        let image = match request.emission.emit(&trampoline, target) {
            Ok(image) => image,
            Err(e) => {
                last_error = Refusal::Backend(e.to_string());
                continue;
            }
        };
        let page_start = target & !4095;
        let page_end = target
            .checked_add(image.bytes().len() as u64)
            .and_then(|x| x.checked_add(4095))
            .map(|x| x & !4095)
            .ok_or(Refusal::InvalidRange)?;
        let allocation = AddressRange::new(page_start, (page_end - page_start) as usize)?;
        if allocation.len() > policy.max_mapped_bytes as u64
            || !policy.ranges.iter().any(|range| range.covers(allocation))
            || occupied.iter().any(|range| range.overlaps(allocation))
        {
            let class = if allocation.len() > policy.max_mapped_bytes as u64 {
                RefusalClass::ResourceCapacity
            } else {
                RefusalClass::AddressPolicy
            };
            search_evidence.refusal(scope, class, &Refusal::AllocationUnavailable);
            continue;
        }
        let offset = (physical - source.start()) as usize;
        let mut patch = request.code[offset..offset + displaced.len() as usize].to_vec();
        patch[0] = 0xe9;
        let displacement = i32::try_from(i128::from(target) - i128::from(physical + 5))
            .map_err(|_| Refusal::AllocationUnavailable)?;
        patch[1..5].copy_from_slice(&displacement.to_le_bytes());
        // First choose the displacement. Interior head bytes are already illegal
        // opcodes encoded in that displacement and must never be overwritten.
        for &head in heads.iter().rev() {
            if head >= physical + 5 {
                let at = (head - physical) as usize;
                patch[at] = 0x62;
                let following = |delta: usize| {
                    patch.get(at + delta).copied().or_else(|| {
                        request
                            .code
                            .get((head - source.start()) as usize + delta)
                            .copied()
                    })
                };
                // In the declared legacy/EVEX envelope P1 bit 2 must be one.
                // Invalid EVEX may still fetch later bytes before raising #UD.
                // Keep its full architectural 15-byte fetch envelope in one
                // executable page and inside the authenticated snapshot; a
                // short suffix at a page boundary can otherwise raise #PF.
                if head % 4096 > 4096 - 15
                    || source.end() - head < 15
                    || following(1).is_none()
                    || !following(2).is_some_and(|p1| p1 & 4 == 0)
                {
                    patch[at] = 0x60; // PUSHA is unconditionally #UD in 64-bit mode.
                }
            }
        }
        let routes: Vec<_> = heads
            .iter()
            .map(|&head| {
                image
                    .entry_routes()
                    .iter()
                    .find(|&&(original, _)| original == head)
                    .map(|&(_, generated)| EntryRoute {
                        original: head,
                        generated,
                    })
                    .ok_or(Refusal::InvalidPlan)
            })
            .collect::<Result<_, _>>()?;
        let mut obligations = vec![EntryObligation::Preserved(physical)];
        obligations.extend(routes.iter().copied().map(EntryObligation::Routed));
        let plan = PatchPlan::checked(PlanParts {
            identity: request.identity,
            profile: ApplicationProfile::InstallOnce,
            kind: PlanKind::Relocation,
            logical_pc: request.logical_pc,
            physical_pc: physical,
            displaced,
            reads: vec![ExpectedBytes {
                address: source.start(),
                bytes: request.code.to_vec(),
            }],
            writes: vec![ByteEdit {
                address: physical,
                bytes: patch,
            }],
            dependencies: vec![source],
            entries: request.entries.clone(),
            obligations,
            allocations: vec![AllocationRequest {
                range: allocation,
                alignment: 4096,
            }],
            generated: vec![GeneratedCode {
                address: target,
                bytes: image.bytes().to_vec(),
                program_counters: image.program_counter_mappings().to_vec(),
            }],
            requirements: PublicationRequirements {
                quiescent: true,
                sync_core: true,
                sigill_router: !routes.is_empty(),
            },
        })?;
        search_evidence.accept(image_search);
        return Ok(PlannedInstall {
            plan,
            image,
            metrics: PlanMetrics {
                search: SearchEvidence::default(),
                upstream_bytes: (request.logical_pc - physical) as usize,
                displaced_bytes: displaced.len() as usize,
                prefix_instructions: instructions
                    .iter()
                    .filter(|i| i.address() < request.logical_pc)
                    .count(),
                allocation_attempts: attempt + 1,
                attempts: vec![],
            },
        });
    }
    search_evidence.finish_candidates(
        image_search,
        candidate_target_proof(
            physical,
            mask,
            policy.preferred_address,
            policy.max_candidates,
        ),
    );
    Err(last_error)
}

// These single-byte opcodes are architecturally invalid in 64-bit mode. Do not
// add D4/D5: newer ISAs may assign prefixes to historically illegal opcodes.
const ILLEGAL: [u8; 14] = [
    0x06, 0x07, 0x0e, 0x16, 0x17, 0x1e, 0x1f, 0x27, 0x2f, 0x37, 0x3f, 0x60, 0x61, 0xce,
];
pub(crate) fn candidate_target(
    physical: u64,
    mask: [bool; 4],
    preferred: Option<u64>,
    attempt: usize,
) -> Option<u64> {
    let next = physical.checked_add(5)?;
    let combinations = ILLEGAL
        .len()
        .checked_pow(mask.iter().filter(|&&v| v).count() as u32)?;
    let seed = preferred.unwrap_or(next.checked_add(0x1_0000)?);
    let seed = seed.checked_add(((attempt / combinations) as u64).checked_mul(0x1_0000)?)?;
    let mut bytes = i32::try_from(i128::from(seed) - i128::from(next))
        .ok()?
        .to_le_bytes();
    let mut choice = attempt % combinations;
    for (byte, constrained) in bytes.iter_mut().zip(mask) {
        if constrained {
            *byte = ILLEGAL[choice % ILLEGAL.len()];
            choice /= ILLEGAL.len();
        }
    }
    u64::try_from(i128::from(next) + i128::from(i32::from_le_bytes(bytes))).ok()
}

/// Additive proof; it never shortens the existing loop or changes a target.
pub(crate) fn candidate_target_proof(
    physical: u64,
    mask: [bool; 4],
    preferred: Option<u64>,
    examined: usize,
) -> crate::search::CandidateProof {
    use crate::search::{CandidateProof, CandidateWitness};
    let empty = || CandidateProof::Indexed {
        permanent_end_exclusive: Some(0),
        omitted: None,
    };
    let Some(next) = physical.checked_add(5) else {
        return empty();
    };
    // Preserve the original eager unwrap_or argument: even Some(preferred)
    // evaluates the default's checked_add and can return None here.
    let Some(default_seed) = next.checked_add(0x1_0000) else {
        return empty();
    };
    let seed = preferred.unwrap_or(default_seed);
    let combinations = ILLEGAL
        .len()
        .pow(mask.iter().filter(|&&value| value).count() as u32);
    let step = 0x1_0000_u128;
    let upper = (u128::from(next) + i32::MAX as u128).min(u128::from(u64::MAX));
    let lower = i128::from(next) + i128::from(i32::MIN);
    if u128::from(seed) > upper {
        return empty();
    }
    let first = if i128::from(seed) >= lower {
        0
    } else {
        u128::try_from(lower - i128::from(seed))
            .unwrap()
            .div_ceil(step)
    };
    let last = (upper - u128::from(seed)) / step;
    if first > last {
        return empty();
    }
    let end = usize::try_from((last + 1) * combinations as u128).ok();
    if end.is_some_and(|end| examined >= end) {
        return CandidateProof::Indexed {
            permanent_end_exclusive: end,
            omitted: None,
        };
    }
    // Three fixed group probes are independent of the caller's range widths.
    // Failure of these probes remains unclassified; no absence proof is inferred.
    let group = (examined / combinations) as u128;
    let first_probe = group.max(first);
    let mut witness = None;
    for probe in [first_probe, first_probe + 1, last] {
        if probe < first_probe || probe > last {
            continue;
        }
        let start_choice = if probe == group {
            examined % combinations
        } else {
            0
        };
        let seed_at = u64::try_from(u128::from(seed) + probe * step).unwrap();
        let displacement = i32::try_from(i128::from(seed_at) - i128::from(next)).unwrap();
        // Choice order is monotone in the UNSIGNED displacement word, because
        // constrained low bytes are the least-significant base-14 choice digits.
        // The valid signed-target range becomes at most two unsigned intervals.
        let signed_low = (-i128::from(next)).max(i128::from(i32::MIN)) as i32;
        let signed_high =
            (i128::from(u64::MAX) - i128::from(next)).min(i128::from(i32::MAX)) as u32;
        let intervals = [(0, signed_high), (signed_low as u32, u32::MAX)];
        for (low, high) in intervals {
            let mut left = start_choice;
            let mut right = combinations;
            while left < right {
                let mid = left + (right - left) / 2;
                if candidate_word(displacement, mask, mid) < low {
                    left = mid + 1;
                } else {
                    right = mid;
                }
            }
            if left == combinations || candidate_word(displacement, mask, left) > high {
                continue;
            }
            let Some(slot) = usize::try_from(probe * combinations as u128 + left as u128).ok()
            else {
                continue;
            };
            let Some(target) = candidate_target(physical, mask, preferred, slot) else {
                continue;
            };
            let found = CandidateWitness { slot, target };
            if witness.is_none_or(|prior: CandidateWitness| found.slot < prior.slot) {
                witness = Some(found);
            }
        }
    }
    CandidateProof::Indexed {
        permanent_end_exclusive: end,
        omitted: witness,
    }
}

fn candidate_word(displacement: i32, mask: [bool; 4], mut choice: usize) -> u32 {
    let mut bytes = displacement.to_le_bytes();
    for (byte, constrained) in bytes.iter_mut().zip(mask) {
        if constrained {
            *byte = ILLEGAL[choice % ILLEGAL.len()];
            choice /= ILLEGAL.len();
        }
    }
    u32::from_le_bytes(bytes)
}

pub(crate) struct PunCandidates {
    pub(crate) addresses: Vec<u64>,
    pub(crate) proof: crate::search::CandidateProof,
}

fn pun_candidate_proof(
    window: AddressRange,
    policy: &AllocationPolicy,
    addresses: &[u64],
) -> crate::search::CandidateProof {
    use crate::search::{CandidateProof, PageWalkEvidence};
    let returned: std::collections::BTreeSet<_> = addresses.iter().copied().collect();
    let mut omitted = policy
        .preferred_address
        .filter(|&pc| window.contains(pc) && !returned.contains(&pc));
    let mut walks = Vec::with_capacity(policy.ranges.len());
    for (range_index, range) in policy.ranges.iter().enumerate() {
        let Some(first_page) = range.start().checked_add(4095).map(|value| value & !4095) else {
            walks.push(PageWalkEvidence {
                range_index,
                finite_slots: 0,
                examined: 0,
            });
            continue;
        };
        let start = window.start().max(first_page);
        let end = window.end().min(range.end());
        let finite_slots = if start >= end {
            0
        } else {
            let next = (u128::from(start) | 4095) + 1;
            1 + if next >= u128::from(end) {
                0
            } else {
                ((u128::from(end) - 1 - next) / 4096 + 1) as u64
            }
        };
        walks.push(PageWalkEvidence {
            range_index,
            finite_slots,
            examined: usize::try_from(finite_slots)
                .unwrap_or(usize::MAX)
                .min(policy.max_candidates),
        });
        if omitted.is_some() {
            continue;
        }
        let mut address = start;
        // Each range is strictly increasing. Among returned.len()+1 distinct
        // items one must be missing; a shorter fully checked range is complete.
        // This is bounded by already returned work, not the range's byte width.
        for _ in 0..=addresses.len() {
            if address >= end {
                break;
            }
            if !returned.contains(&address) {
                omitted = Some(address);
                break;
            }
            let Some(next) = (address | 4095).checked_add(1) else {
                break;
            };
            address = next;
        }
    }
    CandidateProof::PageBoundary {
        returned: addresses.len(),
        omitted,
        walks,
    }
}

/// Initial four-byte legacy SSE/SSE2 move forms only. Length excludes extra
/// legacy/address/REX prefixes; explicit operands exclude other forms sharing
/// these iced Codes. Wider encodings need their own native qualification.
fn qualify_mandatory_prefix_move(instruction: &iced_x86::Instruction) -> bool {
    use iced_x86::{Code, OpKind, Register};
    let low_xmm = |index| {
        instruction.op_kind(index) == OpKind::Register
            && matches!(
                instruction.op_register(index),
                Register::XMM0
                    | Register::XMM1
                    | Register::XMM2
                    | Register::XMM3
                    | Register::XMM4
                    | Register::XMM5
                    | Register::XMM6
                    | Register::XMM7
            )
    };
    let plain_memory = |index| {
        instruction.op_kind(index) == OpKind::Memory
            && matches!(
                instruction.memory_base(),
                Register::RAX
                    | Register::RCX
                    | Register::RDX
                    | Register::RBX
                    | Register::RSI
                    | Register::RDI
            )
            && instruction.memory_index() == Register::None
            && instruction.memory_displ_size() == 0
            && instruction.memory_displacement64() == 0
    };
    instruction.len() == 4
        && instruction.op_count() == 2
        && instruction.segment_prefix() == Register::None
        && !instruction.has_lock_prefix()
        && !instruction.has_rep_prefix()
        && !instruction.has_repne_prefix()
        && match instruction.code() {
            Code::Movss_xmm_xmmm32 | Code::Movsd_xmm_xmmm64 | Code::Movdqa_xmm_xmmm128 => {
                low_xmm(0) && low_xmm(1)
            }
            Code::Movdqu_xmm_xmmm128 => low_xmm(0) && plain_memory(1),
            Code::Movdqu_xmmm128_xmm => plain_memory(0) && low_xmm(1),
            _ => false,
        }
}

pub(crate) fn qualify_instruction(instruction: &iced_x86::Instruction) -> Result<(), Refusal> {
    // The exact initial legacy mandatory-prefix move envelope has independent
    // native normal/fault fixtures. This is separate from the unchanged GPR
    // envelope below: no mnemonic-wide SIMD/string or VEX/EVEX admission.
    if qualify_mandatory_prefix_move(instruction) {
        return Ok(());
    }
    use Mnemonic::*;
    // Deliberately explicit initial ABI envelope. Expanding it requires a
    // forced puzzle and independent state/fault evidence, not just decoding.
    if matches!(
        instruction.mnemonic(),
        Mov | Movzx
            | Movsx
            | Movsxd
            | Lea
            | Nop
            | Add
            | Adc
            | Sub
            | Sbb
            | And
            | Or
            | Xor
            | Cmp
            | Test
            | Inc
            | Dec
            | Neg
            | Not
            | Shl
            | Shr
            | Sar
            | Rol
            | Ror
            | Rcl
            | Rcr
            | Imul
            | Mul
            | Idiv
            | Div
            | Push
            | Pop
            | Pushfq
            | Ret
            | Jmp
            | Ja
            | Jae
            | Jb
            | Jbe
            | Je
            | Jne
            | Jg
            | Jge
            | Jl
            | Jle
            | Jo
            | Jno
            | Js
            | Jns
            | Jp
            | Jnp
            | Jrcxz
            | Loop
            | Loope
            | Loopne
    ) && !instruction.is_privileged()
        && !instruction.is_jmp_far_indirect()
        && (0..instruction.op_count()).all(|index| {
            instruction.op_kind(index) != iced_x86::OpKind::Register
                || instruction.op_register(index).is_gpr()
        })
        && !instruction.has_lock_prefix()
        && !instruction.has_rep_prefix()
        && !instruction.has_repne_prefix()
        && !matches!(
            instruction.op0_kind(),
            iced_x86::OpKind::FarBranch16 | iced_x86::OpKind::FarBranch32
        )
    {
        Ok(())
    } else {
        Err(Refusal::UnsupportedSemantics(format!(
            "{:?} has no qualified A1 relocation contract",
            instruction.mnemonic()
        )))
    }
}

#[allow(unused_unsafe)] // CPUID intrinsics are unsafe on the minimum supported Rust.
pub(crate) fn qualify_host() -> Result<(), Refusal> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        // A1 freezes the legacy+EVEX decoder envelope. APX and MIC's MVEX are
        // not silently treated as the same encoding space.
        // SAFETY: CPUID is available in long mode.
        let leaf = unsafe { core::arch::x86_64::__cpuid_count(7, 1) };
        if leaf.edx & (1 << 21) != 0 {
            return Err(Refusal::UnsupportedSemantics("APX ISA profile".into()));
        }
        let cpu = unsafe { core::arch::x86_64::__cpuid(1) }.eax;
        let model = ((cpu >> 4) & 15) | ((cpu >> 12) & 0xf0);
        if ((cpu >> 8) & 15) == 6 && matches!(model, 0x57 | 0x85) {
            return Err(Refusal::UnsupportedSemantics("MVEX ISA profile".into()));
        }
        // Linux ARCH_SHSTK_STATUS. Unknown/unsupported kernels return EINVAL;
        // the unsafe embedding contract also excludes active CET/IBT.
        let mut status = 0_u64;
        let result = unsafe { libc::syscall(libc::SYS_arch_prctl, 0x5005, &mut status) };
        if result == 0 && status != 0 {
            return Err(Refusal::UnsupportedSemantics(
                "active CET shadow stack".into(),
            ));
        }
        if unsafe { libc::sysconf(libc::_SC_PAGESIZE) } != 4096 {
            return Err(Refusal::UnsupportedSemantics("non-4KiB page size".into()));
        }
        Ok(())
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        Err(Refusal::UnsupportedSemantics(
            "requires Linux x86-64".into(),
        ))
    }
}

pub(crate) fn occupied_ranges() -> Result<Vec<AddressRange>, Refusal> {
    let file =
        std::fs::File::open("/proc/self/maps").map_err(|e| Refusal::Backend(e.to_string()))?;
    let mut text = String::new();
    file.take(2 * 1024 * 1024 + 1)
        .read_to_string(&mut text)
        .map_err(|e| Refusal::Backend(e.to_string()))?;
    if text.len() > 2 * 1024 * 1024 {
        return Err(Refusal::AllocationUnavailable);
    }
    text.lines()
        .map(|line| {
            let addresses = line
                .split_whitespace()
                .next()
                .ok_or(Refusal::InvalidRange)?;
            let (start, end) = addresses.split_once('-').ok_or(Refusal::InvalidRange)?;
            let start = u64::from_str_radix(start, 16).map_err(|_| Refusal::InvalidRange)?;
            let end = u64::from_str_radix(end, 16).map_err(|_| Refusal::InvalidRange)?;
            let len = end.checked_sub(start).ok_or(Refusal::InvalidRange)?;
            AddressRange::new(
                start,
                usize::try_from(len).map_err(|_| Refusal::InvalidRange)?,
            )
        })
        .collect()
}

/// Binds a verified core plan to a caller-owned writable source alias.
pub struct LivePublisher<'a> {
    prepared: &'a PlannedInstall,
    writable_base: *mut u8,
}
impl<'a> LivePublisher<'a> {
    /// Creates a publisher without modifying source bytes.
    ///
    /// # Safety
    /// The pointer aliases the complete plan snapshot and remains valid through
    /// retirement. The embedding runtime owns all mappings, aliases, signals,
    /// continuations, and the no-CET System V execution envelope.
    pub unsafe fn new(prepared: &'a PlannedInstall, writable_base: *mut u8) -> Self {
        Self {
            prepared,
            writable_base,
        }
    }
}

// SAFETY: this implementation authenticates the original trusted plan, checks
// every read and lease, stages allocations/routes, and completes sync-core
// before issuing a receipt. Pointer validity is required at construction.
unsafe impl Publisher for LivePublisher<'_> {
    type Installed = InstalledOnce;
    fn publish_quiescent(
        &mut self,
        plan: &PatchPlan,
        lease: &mut QuiescenceLease<'_>,
    ) -> Result<(InstalledOnce, PublicationReceipt), PublicationFailure> {
        if plan != &self.prepared.plan {
            return Err(before(Refusal::InvalidPlan));
        }
        self.prepared
            .publish_inner(self.writable_base, lease, || Ok(()))
    }
}

impl PlannedInstall {
    /// Publishes with a caller-supplied final-permissions operation.
    ///
    /// The operation runs after stores and before sync-core/receipt. Its failure
    /// keeps the lease poisoned and all possibly reachable resources alive.
    ///
    /// # Safety
    /// Same mapping and exclusion contract as [`Self::publish`]. `finalize` must
    /// establish final executable permissions, must not admit execution or
    /// change bytes/identity, and must not panic or unwind.
    pub unsafe fn publish_with(
        &self,
        writable_base: *mut u8,
        lease: &mut QuiescenceLease<'_>,
        finalize: impl FnMut() -> Result<(), Refusal>,
    ) -> Result<(InstalledOnce, PublicationReceipt), PublicationFailure> {
        self.publish_inner(writable_base, lease, finalize)
    }

    fn publish_inner(
        &self,
        writable_base: *mut u8,
        lease: &mut QuiescenceLease<'_>,
        mut finalize: impl FnMut() -> Result<(), Refusal>,
    ) -> Result<(InstalledOnce, PublicationReceipt), PublicationFailure> {
        if self.image.artifact_metadata().is_some() {
            return Err(before(Refusal::InvalidPlan));
        }
        lease.check(&self.plan).map_err(before)?;
        if writable_base.is_null() {
            return Err(before(Refusal::InvalidRange));
        }
        qualify_host().map_err(before)?;
        let current_state = crate::trampoline::SavedExtendedStateLayout::detect()
            .map_err(|error| before(Refusal::Backend(error.to_string())))?;
        if current_state != self.image.layout().saved_extended_state {
            return Err(before(Refusal::UnsupportedSemantics(
                "extended-state layout changed since planning".into(),
            )));
        }
        prepare_sync_core().map_err(before)?;
        let source = &self.plan.parts().reads[0];
        if matches!(
            self.plan.parts().kind,
            PlanKind::GeneralizedPun(_) | PlanKind::PrefixedPun(_)
        ) && writable_base as usize % 64 != source.address as usize % 64
        {
            return Err(before(Refusal::InvalidRange));
        }
        check_bytes(writable_base, &source.bytes).map_err(before)?;
        let reservation = crate::trap::reserve(
            self.plan.parts().physical_pc as usize,
            source.address as usize,
            source.address as usize + source.bytes.len(),
            0,
        )
        .map_err(|_| before(Refusal::OwnershipConflict))?;
        let staged = ExecutableTrampoline::allocate_image_at(&self.image, self.image.address())
            .map_err(|e| before(Refusal::Backend(e.to_string())))?;
        if staged.trampoline().address() != self.image.address() {
            return Err(before(Refusal::InvalidPlan));
        }
        let routes: Vec<_> = self
            .plan
            .parts()
            .obligations
            .iter()
            .filter_map(|obligation| {
                if let EntryObligation::Routed(route) = obligation {
                    Some(*route)
                } else {
                    None
                }
            })
            .collect();
        let mut routing = if routes.is_empty() {
            None
        } else {
            crate::entry_router::prepare().map_err(before)?;
            // SAFETY: staged code is initialized, dependency lease is held, and
            // routes are derived from the trusted emitter's exact entry map.
            Some(unsafe { crate::entry_router::stage(&routes) }.map_err(before)?)
        };
        // All allocation/signal setup precedes the final identity/byte check.
        lease.check(&self.plan).map_err(before)?;
        check_bytes(writable_base, &source.bytes).map_err(before)?;
        if routing.is_some() {
            crate::entry_router::verify().map_err(before)?;
        }
        let trampoline = staged.commit();
        trampoline.publish_program_counter_mappings();
        if let Some(registration) = routing.as_mut() {
            registration.commit();
        }
        let installed = InstalledOnce {
            plan: self.plan.clone(),
            writable_base,
            reservation: Some(reservation),
            routing,
            trampoline,
            retired: false,
        };
        lease.poison();
        // SAFETY: every changed and preserved store byte is authenticated and
        // held; the alias and signal contracts exclude concurrent accesses.
        unsafe { write_source(&self.plan, writable_base, false) };
        // Dropping the installed handle on error deliberately retains reachable
        // code, routing and byte ownership. The caller must keep the gate held.
        if let Err(reason) = finalize().and_then(|()| sync_core()) {
            return Err(PublicationFailure {
                reason,
                stage: FailureStage::KeepGated,
            });
        }
        lease.publication_completed();
        // SAFETY: every plan obligation, byte write, allocation and route is now
        // installed and instruction-stream visibility completed while held.
        let receipt = unsafe { PublicationReceipt::completed(self.plan.clone()) };
        Ok((installed, receipt))
    }
}

impl PlannedInstall {
    /// Publishes an independently prepared normal-backtrace qualification.
    ///
    /// Existing publication without unwind metadata is unchanged. This method
    /// retains code/CFI/source/consumer owners before registering FDEs, verifies
    /// exact lookup, and only then publishes routes and source bytes.
    ///
    /// # Safety
    /// All requirements of [`Self::publish_with`] apply. The separately
    /// certified source, hook and consumer contracts must remain valid. No
    /// concurrent consumer registration, fork, module unload or metadata write
    /// may occur during preparation/commit. Registration is process-lifetime;
    /// retirement or error must not deregister or reclaim the retained records.
    pub unsafe fn publish_with_unwind(
        &self,
        unwind: &crate::generated_unwind::PreparedUnwind,
        writable_base: *mut u8,
        lease: &mut QuiescenceLease<'_>,
        mut finalize: impl FnMut() -> Result<(), Refusal>,
    ) -> Result<
        (
            InstalledOnce,
            PublicationReceipt,
            crate::generated_unwind::RegisteredUnwind,
        ),
        crate::generated_unwind::PublicationError,
    > {
        use crate::generated_unwind::PublicationError;
        let before = |reason| PublicationError::Publication(before(reason));
        if self.image.artifact_metadata().is_some() {
            return Err(before(Refusal::InvalidPlan));
        }
        unwind
            .check(&self.plan, &self.image)
            .map_err(PublicationError::Preparation)?;
        lease.check(&self.plan).map_err(before)?;
        if writable_base.is_null() {
            return Err(before(Refusal::InvalidRange));
        }
        qualify_host().map_err(before)?;
        let current_state = crate::trampoline::SavedExtendedStateLayout::detect()
            .map_err(|error| before(Refusal::Backend(error.to_string())))?;
        if current_state != self.image.layout().saved_extended_state {
            return Err(before(Refusal::UnsupportedSemantics(
                "extended-state layout changed since planning".into(),
            )));
        }
        prepare_sync_core().map_err(before)?;
        let source = &self.plan.parts().reads[0];
        if matches!(
            self.plan.parts().kind,
            PlanKind::GeneralizedPun(_) | PlanKind::PrefixedPun(_)
        ) && writable_base as usize % 64 != source.address as usize % 64
        {
            return Err(before(Refusal::InvalidRange));
        }
        check_bytes(writable_base, &source.bytes).map_err(before)?;
        let reservation = crate::trap::reserve(
            self.plan.parts().physical_pc as usize,
            source.address as usize,
            source.address as usize + source.bytes.len(),
            0,
        )
        .map_err(|_| before(Refusal::OwnershipConflict))?;
        let staged = ExecutableTrampoline::allocate_image_at(&self.image, self.image.address())
            .map_err(|e| before(Refusal::Backend(e.to_string())))?;
        if staged.trampoline().address() != self.image.address() {
            return Err(before(Refusal::InvalidPlan));
        }
        let routes: Vec<_> = self
            .plan
            .parts()
            .obligations
            .iter()
            .filter_map(|obligation| {
                if let EntryObligation::Routed(route) = obligation {
                    Some(*route)
                } else {
                    None
                }
            })
            .collect();
        let mut routing = if routes.is_empty() {
            None
        } else {
            crate::entry_router::prepare().map_err(before)?;
            // SAFETY: staged code is initialized, dependency lease is held, and
            // routes are derived from the trusted emitter's exact entry map.
            Some(unsafe { crate::entry_router::stage(&routes) }.map_err(before)?)
        };
        let staged_unwind = unwind.stage().map_err(PublicationError::Preparation)?;
        // All allocation/signal setup precedes the final identity/byte check.
        unwind
            .check(&self.plan, &self.image)
            .map_err(PublicationError::Preparation)?;
        lease.check(&self.plan).map_err(before)?;
        check_bytes(writable_base, &source.bytes).map_err(before)?;
        if routing.is_some() {
            crate::entry_router::verify().map_err(before)?;
        }
        let trampoline = staged.commit();
        // Code is already process-lifetime retained. CFI/source/consumer owners
        // become irrevocably retained BEFORE the real void registration call.
        // A failed lookup cannot reclaim them or publish any source redirect.
        let registered = staged_unwind
            .commit()
            .map_err(PublicationError::RetainedBeforeWrite)?;
        trampoline.publish_program_counter_mappings();
        if let Some(registration) = routing.as_mut() {
            registration.commit();
        }
        let installed = InstalledOnce {
            plan: self.plan.clone(),
            writable_base,
            reservation: Some(reservation),
            routing,
            trampoline,
            retired: false,
        };
        lease.poison();
        // SAFETY: every changed and preserved store byte is authenticated and
        // held; the alias and signal contracts exclude concurrent accesses.
        unsafe { write_source(&self.plan, writable_base, false) };
        // Dropping the installed handle on error deliberately retains reachable
        // code, routing and byte ownership. The caller must keep the gate held.
        if let Err(reason) = finalize().and_then(|()| sync_core()) {
            return Err(PublicationError::Publication(PublicationFailure {
                reason,
                stage: FailureStage::KeepGated,
            }));
        }
        lease.publication_completed();
        // SAFETY: every plan obligation, byte write, allocation and route is now
        // installed and instruction-stream visibility completed while held.
        let receipt = unsafe { PublicationReceipt::completed(self.plan.clone()) };
        Ok((installed, receipt, registered))
    }
}

/// Permanently active interception; only generation retirement is exposed.
///
/// Drop preserves active code and routes. Explicit retirement requires a new
/// lease that also drains generated-code execution and saved contexts. Generated
/// code/reverse-PC metadata are retained for process lifetime in this first
/// implementation; retired source ownership and active SIGILL routes are released.
pub struct InstalledOnce {
    plan: PatchPlan,
    writable_base: *mut u8,
    reservation: Option<crate::trap::PendingTrapSite>,
    routing: Option<crate::entry_router::RouteRegistration>,
    trampoline: ExecutableTrampoline,
    retired: bool,
}
impl InstalledOnce {
    /// Exact installed plan and identity.
    pub const fn plan(&self) -> &PatchPlan {
        &self.plan
    }
    /// Generated mapping retained for the process lifetime.
    pub const fn trampoline(&self) -> &ExecutableTrampoline {
        &self.trampoline
    }
    /// Number of owned SIGILL entries actually routed.
    pub fn routed_entries(&self) -> u64 {
        self.routing.as_ref().map_or(0, |r| r.handled())
    }
    /// Whether source bytes were restored and routing disabled.
    pub const fn is_retired(&self) -> bool {
        self.retired
    }

    /// Restores original bytes under a fresh lease, with permissions already suitable.
    ///
    /// # Safety
    /// The retained source alias must be writable again. The lease must hold
    /// all source and generated ranges and drain every saved/executing reference.
    pub unsafe fn retire(
        &mut self,
        lease: &mut QuiescenceLease<'_>,
    ) -> Result<(), PublicationFailure> {
        self.retire_inner(lease, || Ok(()))
    }

    /// Retires and finalizes caller-owned source permissions before completion.
    ///
    /// # Safety
    /// The retained source alias must be writable again. `finalize` must
    /// restore final permissions without changing bytes/identity,
    /// admitting execution, or unwinding. The lease must cover all original and
    /// generated execution/saved references, as required by its constructor.
    pub unsafe fn retire_with(
        &mut self,
        lease: &mut QuiescenceLease<'_>,
        finalize: impl FnMut() -> Result<(), Refusal>,
    ) -> Result<(), PublicationFailure> {
        self.retire_inner(lease, finalize)
    }

    fn retire_inner(
        &mut self,
        lease: &mut QuiescenceLease<'_>,
        mut finalize: impl FnMut() -> Result<(), Refusal>,
    ) -> Result<(), PublicationFailure> {
        lease.check(&self.plan).map_err(before)?;
        if self.retired {
            return Ok(());
        }
        if !self
            .plan
            .parts()
            .allocations
            .iter()
            .all(|allocation| lease.covers(allocation.range))
        {
            return Err(before(Refusal::DependencyNotHeld));
        }
        if self.routing.is_some() {
            crate::entry_router::verify().map_err(before)?;
        }
        let source = &self.plan.parts().reads[0];
        let mut expected = source.bytes.clone();
        for edit in &self.plan.parts().writes {
            let offset = (edit.address - source.address) as usize;
            expected[offset..offset + edit.bytes.len()].copy_from_slice(&edit.bytes);
        }
        check_bytes(self.writable_base, &expected).map_err(before)?;
        prepare_sync_core().map_err(before)?;
        lease.poison();
        // SAFETY: the original alias is writable and every source/generated
        // reader, executor and saved continuation has been drained.
        unsafe { write_source(&self.plan, self.writable_base, true) };
        if let Err(reason) = finalize().and_then(|()| sync_core()) {
            return Err(PublicationFailure {
                reason,
                stage: FailureStage::KeepGated,
            });
        }
        if let Some(routing) = &self.routing {
            routing.deactivate();
        }
        self.reservation.take();
        self.retired = true;
        lease.publication_completed();
        Ok(())
    }
}
impl Drop for InstalledOnce {
    fn drop(&mut self) {
        // An active permanent redirect outlives its Rust handle. Do not release
        // byte ownership merely because a caller drops the handle or an error.
        if let Some(reservation) = self.reservation.take() {
            std::mem::forget(reservation);
        }
    }
}

fn before(reason: Refusal) -> PublicationFailure {
    PublicationFailure {
        reason,
        stage: FailureStage::BeforeWrite,
    }
}

unsafe fn write_source(plan: &PatchPlan, writable: *mut u8, restore: bool) {
    let source = &plan.parts().reads[0];
    let store = match &plan.parts().kind {
        PlanKind::GeneralizedPun(pun) => Some(&pun.store),
        PlanKind::PrefixedPun(pun) => Some(&pun.store),
        PlanKind::Relocation => None,
    };
    if let Some(store) = store {
        let offset = (store.address - source.address) as usize;
        let bytes = if restore {
            &source.bytes[offset..offset + store.bytes.len()]
        } else {
            &store.bytes
        };
        // SAFETY: checked plan authenticates the complete byte/word/dword span;
        // caller holds its lease and a valid writable alias with equal line offset.
        unsafe { single_store(writable.add(offset), bytes) };
    } else {
        for edit in &plan.parts().writes {
            let offset = (edit.address - source.address) as usize;
            let bytes = if restore {
                &source.bytes[offset..offset + edit.bytes.len()]
            } else {
                &edit.bytes
            };
            // SAFETY: caller owns every planned edit under the source lease.
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), writable.add(offset), bytes.len())
            };
        }
    }
}

pub(crate) unsafe fn single_store(address: *mut u8, bytes: &[u8]) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: caller certifies writable, line-contained span and no concurrent
    // accesses. Explicit MOV prevents compiler splitting, including L3's pad.
    unsafe {
        match bytes {
            [value] => core::arch::asm!("mov byte ptr [{address}], {value}",
                address=in(reg) address, value=in(reg_byte) *value,
                options(nostack, preserves_flags)),
            [a, b] => core::arch::asm!("mov word ptr [{address}], {value:x}",
                address=in(reg) address, value=in(reg) u16::from_le_bytes([*a, *b]),
                options(nostack, preserves_flags)),
            [a, b, c, d] => core::arch::asm!("mov dword ptr [{address}], {value:e}",
                address=in(reg) address, value=in(reg) u32::from_le_bytes([*a, *b, *c, *d]),
                options(nostack, preserves_flags)),
            _ => unreachable!("checked generalized-pun store width"),
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (address, bytes);
        unreachable!("publication qualification requires x86-64");
    }
}
fn check_bytes(pointer: *mut u8, expected: &[u8]) -> Result<(), Refusal> {
    // SAFETY: only called with the source alias authenticated at the unsafe
    // constructor boundary and while the full read dependency is leased.
    let observed = unsafe { std::slice::from_raw_parts(pointer, expected.len()) };
    if observed == expected {
        Ok(())
    } else {
        Err(Refusal::ExpectedBytesChanged)
    }
}

pub(crate) fn prepare_sync_core() -> Result<(), Refusal> {
    const SYNC: libc::c_int = 1 << 5;
    const REGISTER: libc::c_int = 1 << 6;
    // SAFETY: Linux membarrier integer arguments, no pointers.
    let available = unsafe { libc::syscall(libc::SYS_membarrier, 0, 0, 0) };
    if available < 0
        || available & (SYNC | REGISTER) as libc::c_long != (SYNC | REGISTER) as libc::c_long
        || unsafe { libc::syscall(libc::SYS_membarrier, REGISTER, 0, 0) } != 0
    {
        return Err(Refusal::Synchronization);
    }
    Ok(())
}
pub(crate) fn sync_core() -> Result<(), Refusal> {
    // SAFETY: the command was queried and registered before any code write.
    if unsafe { libc::syscall(libc::SYS_membarrier, 1 << 5, 0, 0) } == 0 {
        Ok(())
    } else {
        Err(Refusal::Synchronization)
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests {
    use super::*;

    unsafe extern "C" fn noop(_: *mut crate::trampoline::HookContext) {}

    #[test]
    fn unmappable_last_cache_line_refuses_without_address_overflow() {
        // A pure plan accepts synthetic addresses as input. Even impossible
        // userspace placements must refuse instead of overflowing line-end math.
        let pc = u64::MAX - 31;
        let code = [0x66, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90];
        let scope = AddressRange::new(pc, code.len()).unwrap();
        let identity = CodeIdentity {
            source: SourceIdentity([1; 32]),
            mapping: 1,
            generation: 1,
        };
        let entries = LegalEntrySet {
            identity,
            scope,
            provenance: EntryProvenance::Declared(
                "synthetic overflowing-address regression".into(),
            ),
            completeness: EntryCompleteness::AllInstructionHeads,
            entries: vec![],
            resumes: ResumeObligation::NoneExist,
        };
        let allocation = AllocationPolicy {
            ranges: vec![AddressRange::new(0x10000, 4096).unwrap()],
            preferred_address: None,
            max_candidates: 4,
            max_mappings: 1,
            max_mapped_bytes: 4096,
        };
        let request = InstallRequest {
            identity,
            code: &code,
            base_address: pc,
            function: scope,
            block: scope,
            logical_pc: pc,
            entries: &entries,
            hook: noop,
            semantics: HookSemantics::Observe,
            allocation: &allocation,
            search: SearchPolicy {
                tactics: TacticPolicy::GeneralizedPunOnly,
                ..SearchPolicy::default()
            },
        };
        assert!(matches!(
            plan_install(&request),
            Err(Refusal::AllocationUnavailable)
        ));
    }
}

#[cfg(test)]
mod search_candidate_tests {
    use super::*;
    use crate::search::{CandidateProof, SearchStop};

    fn policy(preferred: Option<u64>, ranges: Vec<AddressRange>, limit: usize) -> AllocationPolicy {
        AllocationPolicy {
            preferred_address: preferred,
            ranges,
            max_candidates: limit,
            max_mappings: 1,
            max_mapped_bytes: 8192,
        }
    }

    #[test]
    fn indexed_endpoint_preserves_invalid_prefix_and_eager_default() {
        let proof = candidate_target_proof(0x9000_0000, [false; 4], Some(0), 0);
        let CandidateProof::Indexed {
            omitted: Some(witness),
            ..
        } = proof
        else {
            panic!("known later seed required");
        };
        assert_eq!(candidate_target(0x9000_0000, [false; 4], Some(0), 0), None);
        assert_eq!(witness.slot, 4097);
        assert_eq!(witness.target, 0x1001_0000);
        assert_eq!(
            candidate_target(0x9000_0000, [false; 4], Some(0), witness.slot),
            Some(witness.target)
        );
        let physical = u64::MAX - 31;
        assert_eq!(
            candidate_target(physical, [false; 4], Some(physical), 0),
            None
        );
        assert_eq!(
            candidate_target_proof(physical, [false; 4], Some(physical), 0),
            CandidateProof::Indexed {
                permanent_end_exclusive: Some(0),
                omitted: None
            }
        );
    }

    #[test]
    fn invalid_choice_is_not_permanent_end_and_unproved_tail_stays_unknown() {
        let mask = [false, false, false, true];
        assert_eq!(candidate_target(0, mask, Some(5), 13), None);
        let proof = candidate_target_proof(0, mask, Some(5), 13);
        let CandidateProof::Indexed {
            omitted: Some(witness),
            ..
        } = proof
        else {
            panic!("next group has known work");
        };
        assert_eq!(witness.slot, 14);
        assert_eq!(
            candidate_target(0, mask, Some(5), witness.slot),
            Some(witness.target)
        );
        let physical = u64::MAX - 65541;
        let proof =
            candidate_target_proof(physical, [false, false, true, false], Some(physical + 5), 0);
        assert_eq!(
            proof,
            CandidateProof::Indexed {
                permanent_end_exclusive: Some(28),
                omitted: None
            }
        );
        let mut report = SearchEvidence::default();
        let run = report.begin(
            SearchDomain::SelectedImages,
            SearchScope::default(),
            0,
            None,
        );
        report.finish_candidates(run, proof);
        assert_eq!(report.runs[run].stop, SearchStop::UnclassifiedBoundedStop);
        assert!(!report.classification_complete);
    }

    #[test]
    fn all_masks_keep_their_original_slots_and_prove_permanent_upper_end() {
        for bits in 0..16_u8 {
            let mask = std::array::from_fn(|index| bits & (1 << index) != 0);
            let physical = 0x4000_0000;
            let preferred = Some(physical + 5 + i32::MAX as u64);
            let combinations = 14_usize.pow(bits.count_ones());
            for examined in [0, 1, combinations - 1, combinations, combinations + 1] {
                let proof = candidate_target_proof(physical, mask, preferred, examined);
                let CandidateProof::Indexed {
                    permanent_end_exclusive,
                    omitted,
                } = proof
                else {
                    unreachable!();
                };
                assert_eq!(permanent_end_exclusive, Some(combinations));
                if let Some(witness) = omitted {
                    assert!(witness.slot >= examined && witness.slot < combinations);
                    assert_eq!(
                        candidate_target(physical, mask, preferred, witness.slot),
                        Some(witness.target)
                    );
                }
                for slot in [combinations, combinations + 1, combinations * 2, usize::MAX] {
                    assert_eq!(candidate_target(physical, mask, preferred, slot), None);
                }
            }
            // This mathematical property licenses the bounded binary search;
            // all 50,625 byte-choice combinations across the 16 masks are tested.
            for displacement in [i32::MIN, -5, 0, i32::MAX] {
                let mut prior = None;
                for choice in 0..combinations {
                    let word = candidate_word(displacement, mask, choice);
                    assert!(prior.is_none_or(|previous| previous < word));
                    prior = Some(word);
                }
            }
        }
    }

    #[test]
    fn pun_duplicate_preference_ranges_and_both_caps_have_exact_evidence() {
        let window = AddressRange::new(0x1003, 0x3000).unwrap();
        let range = AddressRange::new(0x1000, 0x4000).unwrap();
        let one = pun_candidates(window, &policy(Some(0x1003), vec![range, range], 1));
        assert_eq!(one.addresses, [0x1003]);
        let CandidateProof::PageBoundary { omitted, walks, .. } = one.proof else {
            unreachable!();
        };
        assert_eq!(omitted, Some(0x2000));
        assert_eq!(walks.len(), 2);
        assert!(
            walks
                .iter()
                .all(|walk| walk.finite_slots == 4 && walk.examined == 1)
        );
        let complete = pun_candidates(window, &policy(Some(0x1003), vec![range, range], 4));
        assert_eq!(complete.addresses, [0x1003, 0x2000, 0x3000, 0x4000]);
        assert!(matches!(
            complete.proof,
            CandidateProof::PageBoundary { omitted: None, .. }
        ));
        // A per-range prefix can spend work on duplicates before reaching a new
        // address. The proof concerns all distinct scheduled targets, not len==cap.
        let zero = pun_candidates(window, &policy(Some(0x1003), vec![range], 0));
        assert!(zero.addresses.is_empty());
        assert!(matches!(
            zero.proof,
            CandidateProof::PageBoundary {
                omitted: Some(0x1003),
                ..
            }
        ));
        let singleton = AddressRange::new(0x1003, 1).unwrap();
        let one = pun_candidates(singleton, &policy(Some(0x1003), vec![range, range], 1));
        assert_eq!(one.addresses, [0x1003]);
        assert!(matches!(
            one.proof,
            CandidateProof::PageBoundary { omitted: None, .. }
        ));
        let empty = pun_candidates(singleton, &policy(None, vec![], 0));
        assert!(empty.addresses.is_empty());
        assert!(matches!(
            empty.proof,
            CandidateProof::PageBoundary { omitted: None, .. }
        ));
    }
}

#[cfg(test)]
mod mandatory_prefix_qualification_tests {
    use super::qualify_instruction;
    use crate::contracts::Refusal;
    use iced_x86::{Decoder, DecoderOptions, Instruction, OpKind, Register};

    fn decode(bytes: &[u8]) -> Instruction {
        let mut decoder = Decoder::with_ip(64, bytes, 0x1234_5000, DecoderOptions::NONE);
        let instruction = decoder.decode();
        assert_eq!(instruction.len(), bytes.len());
        assert!(!decoder.can_decode());
        instruction
    }

    #[test]
    fn exact_five_mandatory_prefix_forms_require_admission() {
        for bytes in [
            [0xf3, 0x0f, 0x10, 0xc1], // MOVSS register source
            [0xf2, 0x0f, 0x10, 0xc1], // MOVSD register source, not string MOVSD
            [0x66, 0x0f, 0x6f, 0xc1], // MOVDQA register source
            [0xf3, 0x0f, 0x6f, 0x07], // MOVDQU memory load
            [0xf3, 0x0f, 0x7f, 0x07], // MOVDQU memory store
        ] {
            let instruction = decode(&bytes);
            assert!(!instruction.is_invalid());
            assert_eq!(qualify_instruction(&instruction), Ok(()));
        }
    }

    #[test]
    fn nearby_simd_string_address_and_extra_prefix_forms_stay_refused() {
        let valid: &[&[u8]] = &[
            &[0xf3, 0x0f, 0x58, 0xc1],             // ADDSS
            &[0xf2, 0x0f, 0x58, 0xc1],             // ADDSD
            &[0x66, 0x0f, 0x7f, 0x07],             // MOVDQA store
            &[0xf3, 0x0f, 0x10, 0x07],             // MOVSS memory load
            &[0xf2, 0x0f, 0x10, 0x07],             // MOVSD memory load
            &[0x66, 0x0f, 0x6f, 0x07],             // MOVDQA memory load
            &[0xf3, 0x0f, 0x6f, 0xc1],             // MOVDQU register source is not in this matrix
            &[0xc5, 0xfa, 0x6f, 0xc1],             // valid VEX VMOVDQU
            &[0x62, 0xf1, 0x7e, 0x48, 0x6f, 0xc1], // valid EVEX VMOVDQU32
            &[0xa5],                               // string MOVSD
            &[0xf3, 0xa5],                         // REP string MOVSD
            &[0xf3, 0xf3, 0x0f, 0x10, 0xc1],       // duplicate mandatory prefix
            &[0xf2, 0xf3, 0x0f, 0x10, 0xc1],       // mixed extra REP prefix
            &[0x67, 0xf3, 0x0f, 0x6f, 0x07],       // address-size override
            &[0x64, 0xf3, 0x0f, 0x6f, 0x07],       // FS memory addressing
            &[0xf3, 0x44, 0x0f, 0x10, 0xc1],       // REX extended register
            &[0xf3, 0x0f, 0x6f, 0x47, 0x10],       // displacement form
        ];
        for &bytes in valid {
            let instruction = decode(bytes);
            assert!(
                !instruction.is_invalid(),
                "negative fixture must be a real nearby encoding: {bytes:x?}"
            );
            assert!(
                matches!(
                    qualify_instruction(&instruction),
                    Err(Refusal::UnsupportedSemantics(_))
                ),
                "unexpected qualification: {bytes:x?}"
            );
        }
        let locked = decode(&[0xf0, 0xf3, 0x0f, 0x10, 0xc1]);
        assert!(locked.is_invalid());
        assert!(matches!(
            qualify_instruction(&locked),
            Err(Refusal::UnsupportedSemantics(_))
        ));
    }

    #[test]
    fn exact_codes_do_not_bypass_register_or_memory_operand_checks() {
        for register in [
            Register::EAX,
            Register::RAX,
            Register::MM0,
            Register::YMM0,
            Register::XMM8,
        ] {
            let mut instruction = decode(&[0xf3, 0x0f, 0x10, 0xc1]);
            instruction.set_op1_register(register);
            assert!(matches!(
                qualify_instruction(&instruction),
                Err(Refusal::UnsupportedSemantics(_))
            ));
        }
        let mut instruction = decode(&[0xf3, 0x0f, 0x6f, 0x07]);
        instruction.set_op1_kind(OpKind::Register);
        instruction.set_op1_register(Register::XMM1);
        assert!(matches!(
            qualify_instruction(&instruction),
            Err(Refusal::UnsupportedSemantics(_))
        ));
        let mut instruction = decode(&[0xf3, 0x0f, 0x6f, 0x07]);
        instruction.set_memory_base(Register::EDI);
        assert!(matches!(
            qualify_instruction(&instruction),
            Err(Refusal::UnsupportedSemantics(_))
        ));
    }

    #[test]
    fn existing_gpr_and_refused_special_forms_keep_their_outcomes() {
        for bytes in [
            &[0x89, 0xc0][..],
            &[0x48, 0x8d, 0x07],
            &[0x01, 0xc8],
            &[0x90],
            &[0xc3],
        ] {
            assert_eq!(qualify_instruction(&decode(bytes)), Ok(()));
        }
        for bytes in [
            &[0x8e, 0xd8][..],
            &[0x9d],
            &[0xd9, 0xe8],
            &[0xe8, 0, 0, 0, 0],
        ] {
            assert!(matches!(
                qualify_instruction(&decode(bytes)),
                Err(Refusal::UnsupportedSemantics(_))
            ));
        }
    }
}
