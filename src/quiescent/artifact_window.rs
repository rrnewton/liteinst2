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
        let physical_run = search.begin(
            SearchDomain::PhysicalSites,
            SearchScope::default(),
            request.search.max_sites,
            Some(1),
        );
        if request.search.max_sites == 0 {
            search.known_limit_hit(physical_run, 1);
            return Err(Refusal::NoPatchWindow);
        }
        let occupied = request.emission.occupied()?;
        search.visit(physical_run);
        let candidate: Result<PlannedInstall, Refusal> = (|| {
            let mut window = collect_relocation_window(
                &request,
                &scan,
                input.physical_pc,
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
                    physical_pc: input.physical_pc,
                    refusal: None,
                });
                Ok(planned)
            }
            Err(reason) => {
                attempts.push(SiteAttempt {
                    tactic: PatchTactic::Relocation,
                    physical_pc: input.physical_pc,
                    refusal: Some(reason.clone()),
                });
                search.finish(physical_run);
                Err(reason)
            }
        }
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
