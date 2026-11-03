//! One explicitly bounded artifact B1 window with ordered observations.
//! No frontend population, loader, stack, entry-router or execution authority.
use super::*;
use crate::composition::Composition;

/// A declared group-only relocation attempt, never an implicit singleton fallback.
///
/// The artifact site retains one common source/entry/target/hook and numeric
/// search/allocation policy. The caller must bind every member to those policies
/// and prove that observation_pcs equals the complete selected-manifest
/// intersection with this interval. Core decoding alone cannot prove selection.
/// The separate group profile must explicitly select RelocationOnly.
pub struct ArtifactObservationRequest<'a> {
    /// Immutable original source and caller-owned symbolic target/hook binding.
    pub artifact: ArtifactRequest<'a>,
    /// Exact physical head; no upstream candidate search is added.
    pub physical_pc: u64,
    /// Exclusive whole-instruction end within the same block.
    pub end: u64,
    /// Nonempty, strictly increasing original observation heads. The first must
    /// equal artifact.site.logical_pc; unselected displaced heads remain routed.
    pub observation_pcs: &'a [u64],
}

/// Separately opted-in same-block upstream search for one fixed observation group.
///
/// The selected population and exclusive end never change between candidates.
/// Numeric search policy is supplied once, not summed over members. The named
/// frontend profile binds its 64-byte/64-head/256-byte limits and allocation arena;
/// this generic core honors the supplied SearchPolicy and retains the existing
/// one-candidate/one-mapping/4096-byte artifact allocation contract.
///
/// The caller must prove that every allowed expanded interval intersects the
/// COMPLETE selected manifest in exactly observation_pcs, including previously
/// accepted and straddling intervals. A pending-only list is not that proof.
pub struct ArtifactObservationSearchRequest<'a> {
    /// Immutable source and caller-owned target/hook/search/allocation binding.
    pub artifact: ArtifactRequest<'a>,
    /// Exclusive whole-instruction end, unchanged across physical candidates.
    pub end: u64,
    /// Complete ordered observation heads; first equals artifact.site.logical_pc.
    pub observation_pcs: &'a [u64],
}

/// Immutable geometry of the smallest same-block window covering the supplied
/// observation heads and at least five bytes. This is not a complete-selection
/// certificate: the caller must join both spans to its FULL selected manifest.
///
/// Only bounded retained bytes and PCs are owned. No borrowed entry, hook or
/// emission authority survives scoped request construction. Current ownership,
/// entries/CET, placement, callback/stack safety and final publication are still
/// checked or owed by the existing planner and its consumer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactObservationWindowSeal {
    identity: CodeIdentity,
    source: AddressRange,
    function: AddressRange,
    block: AddressRange,
    selected: AddressRange,
    retained: AddressRange,
    max_displaced_bytes: usize,
    observation_pcs: Box<[u64]>,
    original_bytes: Box<[u8]>,
}
impl ArtifactObservationWindowSeal {
    /// First selected head through the last selected instruction, before padding.
    pub const fn selected_span(&self) -> AddressRange {
        self.selected
    }
    /// Minimal whole-instruction span, independently bounded by the original block.
    pub const fn retained_span(&self) -> AddressRange {
        self.retained
    }
    /// Exact supplied ordered heads; no inferred selection completeness.
    pub fn observation_pcs(&self) -> &[u64] {
        &self.observation_pcs
    }
    /// Join this geometry to immutable source coordinates, identity, bound and PCs.
    /// This does not revalidate mutable admission facts or replace planning. In
    /// particular an unchanged original request can match after Composition has
    /// claimed its bytes; the existing planner must then reject that overlay.
    pub fn matches_request(
        &self,
        artifact: &ArtifactRequest<'_>,
        observation_pcs: &[u64],
    ) -> Result<(), Refusal> {
        let site = &artifact.site;
        if site.identity != self.identity {
            return Err(Refusal::StaleGeneration);
        }
        if AddressRange::new(site.base_address, site.code.len())? != self.source
            || site.function != self.function
            || site.block != self.block
            || site.logical_pc != self.selected.start()
        {
            return Err(Refusal::InvalidRange);
        }
        if site.search.max_displaced_bytes != self.max_displaced_bytes
            || observation_pcs != self.observation_pcs.as_ref()
        {
            return Err(Refusal::InvalidPlan);
        }
        if retained_source_bytes(site.code, self.source, self.retained)?
            != self.original_bytes.as_ref()
        {
            return Err(Refusal::ExpectedBytesChanged);
        }
        Ok(())
    }
}

fn retained_source_bytes(
    bytes: &[u8],
    source: AddressRange,
    retained: AddressRange,
) -> Result<&[u8], Refusal> {
    if !source.covers(retained) {
        return Err(Refusal::InvalidRange);
    }
    let start =
        usize::try_from(retained.start() - source.start()).map_err(|_| Refusal::InvalidRange)?;
    let end =
        usize::try_from(retained.end() - source.start()).map_err(|_| Refusal::InvalidRange)?;
    bytes.get(start..end).ok_or(Refusal::InvalidRange)
}

/// Freeze a minimum five-byte geometry from immutable source, before any search.
///
/// Uses the same source/population checks and ordinary bounded collector as B1;
/// every retained instruction is qualified and a control transfer must be final.
/// A supported unselected final RET is retained without adding an observation.
/// Existing fixed-end APIs and their error/evidence order are unchanged.
///
/// Success does not try a candidate or grant allocation/entry/ownership authority.
/// Failure has no attempted candidates or search runs; qualification evidence
/// retains its existing sites. Consumers must preserve failed units and every
/// selected member, authenticate the exact minimal end, then use the unchanged
/// upstream planner with that fixed end. No splitting or selection filtering.
pub fn seal_artifact_observation_window_min5(
    artifact: &ArtifactRequest<'_>,
    observation_pcs: &[u64],
) -> Result<ArtifactObservationWindowSeal, PlanningFailure> {
    let mut search = SearchEvidence::default();
    let result = (|| {
        let request = PlanningRequest::artifact(artifact);
        let (source, scan) = validated_source_core(&request).inspect_err(|reason| {
            search.qualification(SearchScope::default(), reason);
        })?;
        let input = ArtifactObservationRequest {
            artifact: *artifact,
            physical_pc: request.logical_pc,
            end: request.block.end(),
            observation_pcs,
        };
        validate_population(&input, &scan).inspect_err(|reason| {
            search.qualification(SearchScope::default(), reason);
        })?;
        let last_pc = *observation_pcs.last().ok_or(Refusal::InvalidPlan)?;
        let window = collect_relocation_window(
            &request,
            &scan,
            request.logical_pc,
            last_pc,
            None,
            &mut search,
        )?;
        let last = scan.site(last_pc).ok_or(Refusal::NotInstructionHead)?;
        let selected_end = last_pc
            .checked_add(last.instruction_len() as u64)
            .ok_or(Refusal::InvalidRange)?;
        let selected = AddressRange::new(
            request.logical_pc,
            usize::try_from(selected_end - request.logical_pc)
                .map_err(|_| Refusal::InvalidRange)?,
        )?;
        // Both copies follow the bounded collector. Distinct supplied heads all
        // lie in its interval; byte and PC counts are bounded by retained length.
        Ok(ArtifactObservationWindowSeal {
            identity: request.identity,
            source,
            function: request.function,
            block: request.block,
            selected,
            retained: window.displaced,
            max_displaced_bytes: request.search.max_displaced_bytes,
            observation_pcs: observation_pcs.into(),
            original_bytes: retained_source_bytes(request.original_code, source, window.displaced)?
                .into(),
        })
    })();
    result.map_err(|reason| PlanningFailure {
        reason,
        attempts: Vec::new(),
        search,
    })
}

/// One opaque artifact plan plus its complete ordered observation population.
/// The frontend must preserve this association through one AcceptedUnit, ledger,
/// resource accounting and portable metadata; never clone the plan per member.
/// ArtifactPlan remains Clone: this borrow does not prevent stripping the PC
/// association. Consumers must retain and authenticate it. No new consuming
/// conversion or live image/publisher capability is added.
#[derive(Clone, Debug)]
pub struct ArtifactObservationPlan {
    artifact: ArtifactPlan,
    observation_pcs: Box<[u64]>,
    search: SearchEvidence,
}
impl ArtifactObservationPlan {
    /// Borrow the one owned plan for shared composition/carrier consumers.
    pub fn artifact(&self) -> &ArtifactPlan {
        &self.artifact
    }
    /// Exact static PC order; actual callbacks follow the entered control path.
    pub fn observation_pcs(&self) -> &[u64] {
        &self.observation_pcs
    }
    /// All reached qualification, physical and image-search decisions.
    pub fn search(&self) -> &SearchEvidence {
        &self.search
    }
}

/// Plan exactly one artifact B1 window against the authenticated predecessor.
///
/// `pending` must contain the complete canonical OUTSIDE-GROUP original
/// instruction intervals. The frontend proves that excluded members equal the
/// full manifest intersection; including a member here is refused after append.
/// The original/current overlay, pending coverage/ownership and one-page fitting
/// policy are checked first. Then the shared source validator runs, followed by
/// the explicit observing/all-head/population/geometry guards, the shared bounded
/// collector and unchanged instruction, entry/CET, original-byte and B1 checks.
/// The candidate is appended once to a clone and pending is rechecked. Failure
/// returns no plan and never changes predecessor, retries or pools member budgets.
///
/// The caller still owes complete member policies/identity, aggregate resources,
/// hook immutability, loader writes and final whole-selection atomic publication.
/// Every observer after POP RSP needs valid scratch below its newly loaded RSP.
/// Structural success does not discharge any of these runtime obligations.
pub fn plan_artifact_observation_window_after(
    input: &ArtifactObservationRequest<'_>,
    predecessor: &Composition,
    pending: &[AddressRange],
) -> Result<ArtifactObservationPlan, PlanningFailure> {
    plan_window(input, predecessor, pending, PhysicalDomain::Exact)
}

/// Search the existing ordered physical heads for the same exact end/population.
///
/// Source, observing/all-head/profile and pending checks precede one frozen
/// PhysicalSites domain. Each visited head uses the same collector, qualifier,
/// entry/CET/current-byte checks, one-page fitter and transactional append as the
/// exact API. Failed trials do not change predecessor; no member is removed and
/// no end is extended. Earlier failed attempts and nested image runs survive a
/// later success. A bounded stop is not a proof that no placement exists.
///
/// `pending` contains complete OUTSIDE-GROUP original intervals. The caller owes
/// the full-manifest prefix proof documented by ArtifactObservationSearchRequest,
/// aggregate resource/atomic publication checks and the unchanged callback/loader
/// and POP RSP scratch obligations of the exact API. No live capability is added.
pub fn plan_artifact_observation_window_upstream_after(
    input: &ArtifactObservationSearchRequest<'_>,
    predecessor: &Composition,
    pending: &[AddressRange],
) -> Result<ArtifactObservationPlan, PlanningFailure> {
    // The common population check starts at the first observation. Actual
    // physical candidates are separately enumerated from validated original heads.
    let window = ArtifactObservationRequest {
        artifact: input.artifact,
        physical_pc: input.artifact.site.logical_pc,
        end: input.end,
        observation_pcs: input.observation_pcs,
    };
    plan_window(&window, predecessor, pending, PhysicalDomain::Upstream)
}

#[derive(Clone, Copy)]
enum PhysicalDomain {
    Exact,
    Upstream,
}

fn plan_window(
    input: &ArtifactObservationRequest<'_>,
    predecessor: &Composition,
    pending: &[AddressRange],
    domain: PhysicalDomain,
) -> Result<ArtifactObservationPlan, PlanningFailure> {
    let mut attempts = Vec::new();
    let mut search = SearchEvidence::default();
    let result = (|| {
        let current = predecessor.planning_overlay(
            input.artifact.site.identity,
            input.artifact.site.base_address,
            input.artifact.site.code,
        )?;
        predecessor.require_unclaimed_ranges(pending)?;
        crate::emission::placement::validate(input.artifact.site.allocation)?;
        let original = PlanningRequest::artifact(&input.artifact).with_fitting_placement();
        let request = original.with_code(&current);
        let (source, scan) = validated_source_core(&request).inspect_err(|reason| {
            search.qualification(SearchScope::default(), reason);
        })?;
        validate_population(input, &scan).inspect_err(|reason| {
            search.qualification(SearchScope::default(), reason);
        })?;
        let candidates = match domain {
            PhysicalDomain::Exact => vec![input.physical_pc],
            PhysicalDomain::Upstream => physical_head_schedule(&request, &scan),
        };
        let physical_run = search.begin(
            SearchDomain::PhysicalSites,
            SearchScope::default(),
            request.search.max_sites,
            Some(candidates.len()),
        );
        if request.search.max_sites == 0 {
            // Population validation proves that the first observation is a
            // same-block head, so the exact and upstream domains are nonempty.
            search.known_limit_hit(physical_run, candidates.len());
            return Err(Refusal::NoPatchWindow);
        }
        let occupied = request.emission.occupied()?;
        for physical in candidates.into_iter().take(request.search.max_sites) {
            search.visit(physical_run);
            let candidate: Result<PlannedInstall, Refusal> = (|| {
                let mut window = collect_relocation_window(
                    &request,
                    &scan,
                    physical,
                    *input.observation_pcs.last().ok_or(Refusal::InvalidPlan)?,
                    Some(input.end),
                    &mut search,
                )?;
                window.authority = RelocationAuthority::ArtifactObservations(input.observation_pcs);
                let planned = emit_relocation_window(
                    &request,
                    &scan,
                    source,
                    &occupied,
                    (None, None),
                    window,
                    &mut search,
                )?;
                let mut joined = predecessor.clone();
                joined.append(planned.plan())?;
                joined.require_unclaimed_ranges(pending)?;
                Ok(planned)
            })();
            match candidate {
                Ok(planned) => {
                    search.accept(physical_run);
                    attempts.push(SiteAttempt {
                        tactic: PatchTactic::Relocation,
                        physical_pc: physical,
                        refusal: None,
                    });
                    return Ok(planned);
                }
                Err(reason) => attempts.push(SiteAttempt {
                    tactic: PatchTactic::Relocation,
                    physical_pc: physical,
                    refusal: Some(reason),
                }),
            }
        }
        search.finish(physical_run);
        Err(attempts
            .last()
            .and_then(|attempt| attempt.refusal.clone())
            .unwrap_or(Refusal::NoPatchWindow))
    })();
    match result {
        Ok(mut planned) => {
            search.accepted = true;
            planned.metrics.search = search.clone();
            planned.metrics.attempts = attempts;
            Ok(ArtifactObservationPlan {
                artifact: ArtifactPlan::single(planned),
                observation_pcs: input.observation_pcs.into(),
                search,
            })
        }
        Err(reason) => Err(PlanningFailure {
            reason,
            attempts,
            search,
        }),
    }
}

fn validate_population(
    input: &ArtifactObservationRequest<'_>,
    scan: &ScanResult,
) -> Result<(), Refusal> {
    let site = &input.artifact.site;
    if site.semantics != HookSemantics::Observe {
        return Err(Refusal::UnsupportedSemantics(
            "artifact observation window requires observing hooks".into(),
        ));
    }
    if site.entries.completeness != EntryCompleteness::AllInstructionHeads {
        return Err(Refusal::UnresolvedEntry);
    }
    if site.search.tactics != TacticPolicy::RelocationOnly {
        return Err(Refusal::UnsupportedSemantics(
            "artifact observation window requires explicit relocation-only policy".into(),
        ));
    }
    if input.observation_pcs.first().copied() != Some(site.logical_pc)
        || input.observation_pcs.windows(2).any(|pcs| pcs[0] >= pcs[1])
    {
        return Err(Refusal::InvalidPlan);
    }
    if !site.block.contains(input.physical_pc)
        || input.physical_pc > site.logical_pc
        || input.end > site.block.end()
        || input
            .observation_pcs
            .last()
            .is_none_or(|last| *last >= input.end)
    {
        return Err(Refusal::InvalidRange);
    }
    if site.logical_pc - input.physical_pc > site.search.max_upstream_bytes as u64 {
        return Err(Refusal::NoPatchWindow);
    }
    if scan.site(input.physical_pc).is_none()
        || input
            .observation_pcs
            .iter()
            .any(|&pc| scan.site(pc).is_none())
    {
        return Err(Refusal::NotInstructionHead);
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests;

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod upstream_tests;

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod min5_tests;
