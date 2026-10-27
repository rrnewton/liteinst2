//! Artifact-only continuation through explicitly supplied foreign T3 owners.
use super::*;
use crate::emission::PlanningSite;
use crate::neighbor::NeighborAttemptStage;
use crate::search::SearchDomain;
use std::collections::BTreeSet;

/// Runs the unchanged engine, then continues T3 over explicit foreign owners.
///
/// A local success, empty foreign list, or forced non-T3 policy returns the old
/// result unchanged. Foreign candidates are considered in caller order, after
/// the local T3 attempt, and only the exact forced head is eligible when set.
/// Duplicate eligible heads refuse rather than spending a fresh search twice.
/// Each candidate must use the original victim allocation policy exactly; its
/// independent source/entry authority is checked by the two-owner T3 planner.
///
/// Original Victims and JointPairs examined counts are subtracted before every
/// invocation. A foreign candidate rejected before the leaf opens its Victims
/// run is charged one admission visit; no unexamined pair is charged. Earlier
/// local and foreign attempts remain in Engine metrics even after success.
/// Winning Neighbor metrics describe that leaf only; summing the recorded T3
/// runs gives the complete engine cost. No completeness proof is added.
///
/// This artifact-only API neither publishes nor converts images to live plans.
/// The caller still owns final transactional append and aggregate campaign
/// budgets. A foreign success additionally checks inherited composition state.
pub fn plan_with_emission_after_with_foreign(
    request: &ArtifactRequest<'_>,
    predecessor: &Composition,
    victim_allocation: &AllocationPolicy,
    policy: EnginePolicy,
    foreign: &[PlanningSite<'_>],
) -> Result<ArtifactPlan, EngineFailure> {
    let mut failure =
        match plan_with_emission_after(request, predecessor, victim_allocation, policy) {
            Ok(plan) => return Ok(plan),
            Err(failure) => failure,
        };
    if foreign.is_empty()
        || policy
            .forced
            .is_some_and(|tactic| tactic != Tactic::NeighborEviction)
        || failure
            .attempts
            .last()
            .is_none_or(|a| a.tactic != Tactic::NeighborEviction)
    {
        return Err(failure);
    }
    let mut used = (0_usize, 0_usize);
    for attempt in &failure.attempts {
        if attempt.tactic == Tactic::NeighborEviction {
            used = add_work(used, &attempt.search).ok_or_else(|| EngineFailure {
                reason: Refusal::InvalidPlan,
                attempts: failure.attempts.clone(),
            })?;
        }
    }
    if used.0 > policy.neighbor.max_victims || used.1 > policy.neighbor.max_pairs {
        return Err(EngineFailure {
            reason: Refusal::InvalidPlan,
            attempts: failure.attempts,
        });
    }
    if used.0 == policy.neighbor.max_victims || used.1 == policy.neighbor.max_pairs {
        return Err(failure);
    }
    let eligible = |site: &&PlanningSite<'_>| {
        policy
            .neighbor
            .forced_victim
            .is_none_or(|pc| pc == site.logical_pc)
    };
    let mut heads = BTreeSet::new();
    for site in foreign.iter().filter(eligible) {
        if !heads.insert(site.logical_pc) {
            // This is whole-list authority validation, before foreign emission.
            // It does not claim to have searched any additional victim or pair.
            let rejected = refusal(site.logical_pc, Refusal::OwnershipConflict);
            push_failure(&mut failure, rejected);
            return Err(failure);
        }
    }
    for site in foreign.iter().filter(eligible) {
        if used.0 == policy.neighbor.max_victims || used.1 == policy.neighbor.max_pairs {
            break;
        }
        let remaining = NeighborSearch {
            forced_victim: Some(site.logical_pc),
            max_victims: policy.neighbor.max_victims - used.0,
            max_pairs: policy.neighbor.max_pairs - used.1,
        };
        let result = if same_allocation(site.allocation, victim_allocation) {
            neighbor::plan_neighbor_with_emission_from(
                request,
                predecessor,
                site,
                remaining,
                policy.bundle,
            )
        } else {
            Err(refusal(site.logical_pc, Refusal::InvalidRange))
        };
        match result {
            Ok(plan) => {
                let ArtifactMetrics::Neighbor(geometry, metrics) = plan.metrics().clone() else {
                    unreachable!("the forced two-owner planner returns Neighbor metrics")
                };
                let total = add_work(used, &metrics.search).ok_or_else(|| EngineFailure {
                    reason: Refusal::InvalidPlan,
                    attempts: failure.attempts.clone(),
                })?;
                if total.0 > policy.neighbor.max_victims || total.1 > policy.neighbor.max_pairs {
                    return Err(EngineFailure {
                        reason: Refusal::InvalidPlan,
                        attempts: failure.attempts,
                    });
                }
                failure.attempts.push(EngineAttempt {
                    search: metrics.search.clone(),
                    outer_refusal: None,
                    tactic: Tactic::NeighborEviction,
                    refusal: None,
                    candidates: CandidateEvidence::Neighbor(metrics.attempts.clone()),
                });
                return Ok(plan.with_metrics(ArtifactMetrics::Engine(
                    Tactic::NeighborEviction,
                    SelectedMetrics::Neighbor(geometry, metrics),
                    failure.attempts,
                )));
            }
            Err(mut rejected) => {
                if !rejected
                    .search
                    .runs
                    .iter()
                    .any(|run| run.domain == SearchDomain::Victims)
                {
                    // Source/owner/policy qualification can reject before the
                    // leaf opens a run. This candidate was still considered.
                    let id = rejected.search.begin(
                        SearchDomain::Victims,
                        SearchScope {
                            physical_pc: Some(site.logical_pc),
                            ..SearchScope::default()
                        },
                        remaining.max_victims,
                        Some(1),
                    );
                    rejected.search.visit(id);
                    if rejected.attempts.is_empty() {
                        rejected.attempts.push(NeighborAttempt {
                            victim: site.logical_pc,
                            stage: NeighborAttemptStage::Qualification,
                            victim_target: None,
                            selected_target: None,
                            refusal: Some(rejected.reason.clone()),
                        });
                    }
                }
                let total = add_work(used, &rejected.search);
                push_failure(&mut failure, rejected);
                let Some(total) = total else {
                    failure.reason = Refusal::InvalidPlan;
                    return Err(failure);
                };
                if total.0 > policy.neighbor.max_victims || total.1 > policy.neighbor.max_pairs {
                    failure.reason = Refusal::InvalidPlan;
                    return Err(failure);
                }
                used = total;
            }
        }
    }
    Err(failure)
}

fn add_work(mut used: (usize, usize), search: &SearchEvidence) -> Option<(usize, usize)> {
    for run in &search.runs {
        match run.domain {
            SearchDomain::Victims => used.0 = used.0.checked_add(run.examined)?,
            SearchDomain::JointPairs => used.1 = used.1.checked_add(run.examined)?,
            _ => {}
        }
    }
    Some(used)
}

fn same_allocation(left: &AllocationPolicy, right: &AllocationPolicy) -> bool {
    left.ranges == right.ranges
        && left.preferred_address == right.preferred_address
        && left.max_candidates == right.max_candidates
        && left.max_mappings == right.max_mappings
        && left.max_mapped_bytes == right.max_mapped_bytes
}

fn refusal(pc: u64, reason: Refusal) -> neighbor::NeighborFailure {
    let mut search = SearchEvidence::default();
    search.qualification(
        SearchScope {
            physical_pc: Some(pc),
            ..SearchScope::default()
        },
        &reason,
    );
    neighbor::NeighborFailure {
        search,
        attempts: vec![NeighborAttempt {
            victim: pc,
            stage: NeighborAttemptStage::Qualification,
            victim_target: None,
            selected_target: None,
            refusal: Some(reason.clone()),
        }],
        reason,
    }
}

fn push_failure(failure: &mut EngineFailure, rejected: neighbor::NeighborFailure) {
    failure.reason = rejected.reason.clone();
    failure.attempts.push(EngineAttempt {
        search: rejected.search,
        outer_refusal: None,
        tactic: Tactic::NeighborEviction,
        refusal: Some(rejected.reason),
        candidates: CandidateEvidence::Neighbor(rejected.attempts),
    });
}
