//! Bounded install-once selection across the qualified core tactics.
//!
//! Every result is one trusted bundle, including single-image plans. The
//! preferred order is generalized pun, ordinary relocation, prefixed pun,
//! successor eviction, then neighbor eviction. RapidProbe remains a separate
//! exact-byte toggle interface.

use crate::bundle::{BundleBudget, PlannedBundle};
use crate::contracts::{ExpectedBytes, Refusal};
use crate::emission::{ArtifactMetrics, ArtifactPlan, ArtifactRequest, PlanningRequest};
use crate::eviction::{self, EvictionAttempt, EvictionMetrics};
use crate::neighbor::{self, NeighborAttempt, NeighborGeometry, NeighborMetrics, NeighborSearch};
use crate::quiescent::{
    self, AllocationPolicy, InstallRequest, PlanMetrics, SiteAttempt, TacticPolicy,
};
use crate::search::{RefusalClass, RefusalEvidence, SearchEvidence, SearchScope};

/// Explicit install-once tactic; forced searches never substitute another one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tactic {
    /// B2: E9 plus the selected instruction's free displacement bytes.
    GeneralizedPun,
    /// B1: same-site or bounded upstream whole-instruction relocation.
    Relocation,
    /// T1: redundant-prefix punning.
    PrefixedPun,
    /// T2: whole-successor eviction followed by a selected B2/T1 pun.
    SuccessorEviction,
    /// T3: EB to a private source relay in a preserved neighboring instruction.
    NeighborEviction,
}

/// Outer search policy, in addition to the request's per-site allocation bounds.
#[derive(Clone, Copy, Debug)]
pub struct EnginePolicy {
    /// None tries the documented five-tactic order; Some forces exactly one.
    pub forced: Option<Tactic>,
    /// B2/T1 choice inside T2. RelocationOnly is invalid for forced T2 and
    /// records an UnsupportedSemantics refusal when preferred search reaches T2.
    pub successor_puns: TacticPolicy,
    /// Victim and total pair bounds for T3, including an optional forced victim.
    pub neighbor: NeighborSearch,
    /// Aggregate transaction limits, including a single-image result.
    pub bundle: BundleBudget,
}

impl Default for EnginePolicy {
    fn default() -> Self {
        Self {
            forced: None,
            successor_puns: TacticPolicy::PreferGeneralizedPun,
            neighbor: NeighborSearch::default(),
            bundle: BundleBudget::default(),
        }
    }
}

/// Original leaf-planner diagnostics, retaining their stage-specific meanings.
#[derive(Clone, Debug)]
pub enum CandidateEvidence {
    /// Ordered same-site/upstream/prefix attempts from a single-image planner.
    Single(Vec<SiteAttempt>),
    /// Victim placement and actual selected-prefix attempts from T2.
    Successor(Vec<EvictionAttempt>),
    /// Qualification, placement and joint-composition attempts from T3.
    Neighbor(Vec<NeighborAttempt>),
}

/// One attempted tactic, including a later aggregate-bundle refusal.
#[derive(Clone, Debug)]
pub struct EngineAttempt {
    /// Original leaf search evidence, even when a later bundle check refuses.
    pub search: SearchEvidence,
    /// A later single-image bundle refusal, separate from the accepted leaf.
    pub outer_refusal: Option<RefusalEvidence>,
    /// The exact forced leaf tactic used for this attempt.
    pub tactic: Tactic,
    /// None only when a complete bounded bundle was selected.
    pub refusal: Option<Refusal>,
    /// Leaf attempts are retained even if their successful image exceeds the
    /// aggregate bundle limits. Such a leaf success is not an engine success.
    pub candidates: CandidateEvidence,
}

/// Winning leaf geometry and search cost, without timing estimates.
#[derive(Clone, Debug)]
pub enum SelectedMetrics {
    /// Single-image placement, upstream distance and complete displaced length.
    Single(PlanMetrics),
    /// Successor geometry, candidate count and auxiliary transfer cost.
    Successor(EvictionMetrics),
    /// Neighbor geometry, total pair count and separate path transfer costs.
    Neighbor(NeighborGeometry, NeighborMetrics),
}

/// Complete immutable install-once result with its ordered selection evidence.
#[derive(Clone, Debug)]
pub struct EnginePlan {
    bundle: PlannedBundle,
    tactic: Tactic,
    metrics: SelectedMetrics,
    attempts: Vec<EngineAttempt>,
}

impl EnginePlan {
    /// The single publication/retirement transaction for all source edits.
    pub const fn bundle(&self) -> &PlannedBundle {
        &self.bundle
    }
    /// The actual winning tactic, never inferred from a generic success.
    pub const fn tactic(&self) -> Tactic {
        self.tactic
    }
    /// Winning geometry and bounded search cost.
    pub const fn metrics(&self) -> &SelectedMetrics {
        &self.metrics
    }
    /// All attempted tactics in order, including earlier refusals.
    pub fn attempts(&self) -> &[EngineAttempt] {
        &self.attempts
    }
}

/// An unsuccessful complete search; no source or executable mappings changed.
#[derive(Clone, Debug)]
pub struct EngineFailure {
    /// Final attempted tactic's refusal. Earlier precise reasons remain below.
    pub reason: Refusal,
    /// Complete ordered tactic and candidate evidence. A bounded-search refusal
    /// remains a refusal, not successful coverage.
    pub attempts: Vec<EngineAttempt>,
}

/// Selects an install-once bundle using the preferred or exact forced tactic.
///
/// `request.search.tactics` is replaced by the outer tactic choice; its other
/// bounds remain in force. T2 uses `policy.successor_puns`. Both image allocation
/// policies retain their independent bounds and every result pays the aggregate
/// bundle budget. Preferred search has at most five leaf invocations; each leaf
/// retains its documented finite site/prefix/victim/candidate bounds. Original
/// validation may be repeated by those invocations; no decode-sharing or search
/// performance improvement is claimed. This operation reserves no executable
/// memory and performs no source publication.
pub fn plan(
    request: &InstallRequest<'_>,
    victim_allocation: &AllocationPolicy,
    policy: EnginePolicy,
) -> Result<EnginePlan, EngineFailure> {
    plan_core(&PlanningRequest::live(request), victim_allocation, policy)
}

/// Shared five-tactic engine with explicit symbolic target emission.
/// No live callback conversion or post-hoc image rewriting is performed.
pub fn plan_with_emission(
    request: &ArtifactRequest<'_>,
    victim_allocation: &AllocationPolicy,
    policy: EnginePolicy,
) -> Result<ArtifactPlan, EngineFailure> {
    plan_core(
        &PlanningRequest::artifact(request),
        victim_allocation,
        policy,
    )
    .map(|plan| {
        ArtifactPlan::bundle(
            plan.bundle(),
            ArtifactMetrics::Engine(
                plan.tactic(),
                plan.metrics().clone(),
                plan.attempts().to_vec(),
            ),
        )
    })
}

fn plan_core(
    request: &PlanningRequest<'_>,
    victim_allocation: &AllocationPolicy,
    policy: EnginePolicy,
) -> Result<EnginePlan, EngineFailure> {
    const ORDER: [Tactic; 5] = [
        Tactic::GeneralizedPun,
        Tactic::Relocation,
        Tactic::PrefixedPun,
        Tactic::SuccessorEviction,
        Tactic::NeighborEviction,
    ];
    let forced = [policy.forced.unwrap_or(Tactic::GeneralizedPun)];
    let tactics = if policy.forced.is_some() {
        forced.as_slice()
    } else {
        ORDER.as_slice()
    };
    let mut attempts = Vec::new();
    let mut reason = Refusal::NoPatchWindow;
    for &tactic in tactics {
        let (result, candidates, search) = match tactic {
            Tactic::GeneralizedPun | Tactic::Relocation | Tactic::PrefixedPun => {
                let request = request.with_search(quiescent::SearchPolicy {
                    tactics: match tactic {
                        Tactic::GeneralizedPun => TacticPolicy::GeneralizedPunOnly,
                        Tactic::Relocation => TacticPolicy::RelocationOnly,
                        Tactic::PrefixedPun => TacticPolicy::PrefixPunOnly,
                        _ => unreachable!(),
                    },
                    ..request.search
                });
                match quiescent::plan_install_core(&request) {
                    Ok(member) => {
                        let metrics = member.metrics().clone();
                        let search = metrics.search.clone();
                        let candidates = CandidateEvidence::Single(metrics.attempts.clone());
                        let bundle = PlannedBundle::compose(
                            vec![ExpectedBytes {
                                address: request.base_address,
                                bytes: request.code.to_vec(),
                            }],
                            vec![member],
                            policy.bundle,
                        );
                        (
                            bundle.map(|bundle| (bundle, SelectedMetrics::Single(metrics))),
                            candidates,
                            search,
                        )
                    }
                    Err(failure) => (
                        Err(failure.reason),
                        CandidateEvidence::Single(failure.attempts),
                        failure.search,
                    ),
                }
            }
            Tactic::SuccessorEviction => {
                let request = request.with_search(quiescent::SearchPolicy {
                    tactics: policy.successor_puns,
                    ..request.search
                });
                match eviction::plan_successor_core(&request, victim_allocation, policy.bundle) {
                    Ok(plan) => (
                        Ok((
                            plan.bundle().clone(),
                            SelectedMetrics::Successor(plan.metrics().clone()),
                        )),
                        CandidateEvidence::Successor(plan.metrics().attempts.clone()),
                        plan.metrics().search.clone(),
                    ),
                    Err(failure) => (
                        Err(failure.reason),
                        CandidateEvidence::Successor(failure.attempts),
                        failure.search,
                    ),
                }
            }
            Tactic::NeighborEviction => match neighbor::plan_neighbor_core(
                request,
                victim_allocation,
                policy.neighbor,
                policy.bundle,
            ) {
                Ok(plan) => (
                    Ok((
                        plan.bundle().clone(),
                        SelectedMetrics::Neighbor(*plan.geometry(), plan.metrics().clone()),
                    )),
                    CandidateEvidence::Neighbor(plan.metrics().attempts.clone()),
                    plan.metrics().search.clone(),
                ),
                Err(failure) => (
                    Err(failure.reason),
                    CandidateEvidence::Neighbor(failure.attempts),
                    failure.search,
                ),
            },
        };
        // Only the single-image arms compose a bundle after a successful leaf.
        // At that exact call boundary compose's AllocationUnavailable sites are
        // explicit step or aggregate memory capacities; other errors stay local.
        let outer_refusal = if search.accepted
            && matches!(
                tactic,
                Tactic::GeneralizedPun | Tactic::Relocation | Tactic::PrefixedPun
            ) {
            result.as_ref().err().map(|reason| RefusalEvidence {
                reason: reason.clone(),
                class: match reason {
                    Refusal::AllocationUnavailable => RefusalClass::ResourceCapacity,
                    Refusal::OwnershipConflict => RefusalClass::Prerequisite,
                    Refusal::Backend(_) => RefusalClass::Backend,
                    _ => RefusalClass::Unclassified,
                },
                scope: SearchScope::default(),
            })
        } else {
            None
        };
        attempts.push(EngineAttempt {
            outer_refusal,
            search,
            tactic,
            refusal: result.as_ref().err().cloned(),
            candidates,
        });
        match result {
            Ok((bundle, metrics)) => {
                return Ok(EnginePlan {
                    bundle,
                    tactic,
                    metrics,
                    attempts,
                });
            }
            Err(error) => reason = error,
        }
    }
    Err(EngineFailure { reason, attempts })
}
