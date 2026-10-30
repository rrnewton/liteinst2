//! Bounded install-once selection across the qualified core tactics.
//!
//! Every result is one trusted bundle, including single-image plans. The
//! preferred order is generalized pun, ordinary relocation, prefixed pun,
//! successor eviction, then neighbor eviction. RapidProbe remains a separate
//! exact-byte toggle interface.

use crate::bundle::{BundleBudget, PlannedBundle};
use crate::composition::Composition;
use crate::contracts::{AddressRange, ExpectedBytes, Refusal};
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
    .map(artifact_plan)
}

/// Plans an artifact step after previously composed source edits.
///
/// The request still supplies immutable original bytes and original entry,
/// function and block facts. They must match the predecessor's identity and
/// complete original snapshots. Decoding and relocated operations use that
/// original view; read expectations, padding and pun suffixes use the current
/// overlay. Each candidate refuses to displace an already changed original
/// instruction, including when replacing rather than observing it.
///
/// This does not append to the predecessor. The caller must transactionally
/// append every returned step to enforce inherited byte locks, physical-site
/// uniqueness and allocation ownership, and enforce its aggregate budgets.
/// An inherited conflict may therefore still refuse a selected bundle.
pub fn plan_with_emission_after(
    request: &ArtifactRequest<'_>,
    predecessor: &Composition,
    victim_allocation: &AllocationPolicy,
    policy: EnginePolicy,
) -> Result<ArtifactPlan, EngineFailure> {
    let current = predecessor
        .planning_overlay(
            request.site.identity,
            request.site.base_address,
            request.site.code,
        )
        .map_err(|reason| EngineFailure {
            reason,
            attempts: Vec::new(),
        })?;
    let original = PlanningRequest::artifact(request);
    plan_core(&original.with_code(&current), victim_allocation, policy).map(artifact_plan)
}

/// The same five-tactic engine with an explicit short-only T3 family.
///
/// Generalized pun, relocation, prefixed pun and successor eviction retain their
/// order and exact policies. T3 considers only same-function 6..=9-byte victims;
/// it never retries long victims or obtains a second victim/pair budget. A
/// forced tactic remains one invocation. The full ten-byte fetch/edit requires
/// the existing quiescent source/entry/lease contract, including its suffix.
/// No cross-function short planning or additional publication authority exists.
pub fn plan_with_short_neighbors(
    request: &InstallRequest<'_>,
    victim_allocation: &AllocationPolicy,
    policy: EnginePolicy,
) -> Result<EnginePlan, EngineFailure> {
    plan_core_family(
        &PlanningRequest::live(request),
        victim_allocation,
        policy,
        true,
    )
}

/// Artifact counterpart of the explicit short-only engine. No live authority.
pub fn plan_with_emission_and_short_neighbors(
    request: &ArtifactRequest<'_>,
    victim_allocation: &AllocationPolicy,
    policy: EnginePolicy,
) -> Result<ArtifactPlan, EngineFailure> {
    plan_core_family(
        &PlanningRequest::artifact(request),
        victim_allocation,
        policy,
        true,
    )
    .map(artifact_plan)
}

/// Short-only T3 against an authenticated preceding composition overlay.
///
/// Original instruction identity remains separate from current read bytes.
/// As with the legacy entrypoint, the caller must append every returned step
/// transactionally; inherited site, suffix-lock and allocation conflicts refuse.
pub fn plan_with_emission_after_and_short_neighbors(
    request: &ArtifactRequest<'_>,
    predecessor: &Composition,
    victim_allocation: &AllocationPolicy,
    policy: EnginePolicy,
) -> Result<ArtifactPlan, EngineFailure> {
    let current = predecessor
        .planning_overlay(
            request.site.identity,
            request.site.base_address,
            request.site.code,
        )
        .map_err(|reason| EngineFailure {
            reason,
            attempts: Vec::new(),
        })?;
    let original = PlanningRequest::artifact(request);
    plan_core_family(
        &original.with_code(&current),
        victim_allocation,
        policy,
        true,
    )
    .map(artifact_plan)
}

/// Short-only neighboring-instruction eviction with inherited T3 admission.
///
/// The predecessor authenticates the request's complete immutable original
/// source and supplies its current overlay. Original instruction identity stays
/// separate from current read expectations. Each complete short-neighbor pair
/// must append, in order, to a fresh predecessor clone before selection; a
/// refusal continues within the same victim, image and pair limits.
///
/// Generalized pun, ordinary relocation, prefixed pun and successor eviction
/// keep their order, bounds and first local success. Those four tactics do not
/// preflight inherited ownership and may still fail the caller's later append;
/// that refusal does not retry neighboring-instruction eviction. Only the
/// explicit 6..=9-byte neighboring-instruction family uses inherited admission.
///
/// This does not mutate the predecessor, reserve executable memory or publish
/// source bytes. The caller must append every returned step transactionally and
/// retain the existing entry, hook, lease, aggregate-budget, publication and
/// retirement checks. The complete ten-byte victim fetch remains required.
pub fn plan_after_and_short_t3_ownership(
    request: &InstallRequest<'_>,
    predecessor: &Composition,
    victim_allocation: &AllocationPolicy,
    policy: EnginePolicy,
) -> Result<EnginePlan, EngineFailure> {
    let current = predecessor
        .planning_overlay(request.identity, request.base_address, request.code)
        .map_err(|reason| EngineFailure {
            reason,
            attempts: Vec::new(),
        })?;
    let original = PlanningRequest::live(request);
    plan_core_family_with_inherited(
        &original.with_code(&current),
        victim_allocation,
        policy,
        true,
        Some(predecessor),
    )
}

/// Symbolic counterpart of [`plan_after_and_short_t3_ownership`].
///
/// Only complete short neighboring-instruction eviction pairs preflight against
/// inherited ownership. Generalized pun, ordinary relocation, prefixed pun and
/// successor eviction keep their first local success and may still refuse the
/// caller's final append. The caller retains all aggregate and publication
/// obligations; artifact plans gain no live publication authority or conversion.
pub fn plan_with_emission_after_and_short_t3_ownership(
    request: &ArtifactRequest<'_>,
    predecessor: &Composition,
    victim_allocation: &AllocationPolicy,
    policy: EnginePolicy,
) -> Result<ArtifactPlan, EngineFailure> {
    let current = predecessor
        .planning_overlay(
            request.site.identity,
            request.site.base_address,
            request.site.code,
        )
        .map_err(|reason| EngineFailure {
            reason,
            attempts: Vec::new(),
        })?;
    let original = PlanningRequest::artifact(request);
    plan_core_family_with_inherited(
        &original.with_code(&current),
        victim_allocation,
        policy,
        true,
        Some(predecessor),
    )
    .map(artifact_plan)
}

/// Artifact-only short T3 continuation preserving caller-supplied pending ranges.
///
/// The predecessor first authenticates the complete immutable original view,
/// then validates canonical, covered and unclaimed pending ranges. The caller
/// must supply every outstanding original instruction except the current site;
/// this slice cannot itself prove a complete selected population. Empty is valid.
/// Every complete short T3 pair must append all steps to a fresh predecessor
/// clone and leave these ranges unclaimed before it can be selected. Rejection
/// consumes the same existing pair; no victim filtering or second search occurs.
///
/// The first four tactics retain their first local success and do NOT apply the
/// post-append pending check. The caller must append every returned step, check
/// pending ownership and retain all hook, entry, lease, aggregate and publication
/// obligations before committing. This operation does not mutate the predecessor
/// or grant artifact plans live authority. An empty slice never disables the
/// inherited T3 append checks.
pub fn plan_with_emission_after_and_short_t3_pending(
    request: &ArtifactRequest<'_>,
    predecessor: &Composition,
    pending: &[AddressRange],
    victim_allocation: &AllocationPolicy,
    policy: EnginePolicy,
) -> Result<ArtifactPlan, EngineFailure> {
    let current = predecessor
        .planning_overlay(
            request.site.identity,
            request.site.base_address,
            request.site.code,
        )
        .map_err(|reason| EngineFailure {
            reason,
            attempts: Vec::new(),
        })?;
    predecessor
        .require_unclaimed_ranges(pending)
        .map_err(|reason| EngineFailure {
            reason,
            attempts: Vec::new(),
        })?;
    let original = PlanningRequest::artifact(request);
    plan_core_family_with_pending(
        &original.with_code(&current),
        victim_allocation,
        policy,
        true,
        Some(predecessor),
        Some(pending),
    )
    .map(artifact_plan)
}

// Explicit artifact-only continuation; all existing engine entry points stay literal.
#[path = "engine_foreign.rs"]
mod foreign;
pub use foreign::plan_with_emission_after_with_foreign;

fn artifact_plan(plan: EnginePlan) -> ArtifactPlan {
    ArtifactPlan::bundle(
        plan.bundle(),
        ArtifactMetrics::Engine(
            plan.tactic(),
            plan.metrics().clone(),
            plan.attempts().to_vec(),
        ),
    )
}

fn plan_core(
    request: &PlanningRequest<'_>,
    victim_allocation: &AllocationPolicy,
    policy: EnginePolicy,
) -> Result<EnginePlan, EngineFailure> {
    plan_core_family(request, victim_allocation, policy, false)
}

fn plan_core_family(
    request: &PlanningRequest<'_>,
    victim_allocation: &AllocationPolicy,
    policy: EnginePolicy,
    short_only: bool,
) -> Result<EnginePlan, EngineFailure> {
    plan_core_family_with_inherited(request, victim_allocation, policy, short_only, None)
}

fn plan_core_family_with_inherited(
    request: &PlanningRequest<'_>,
    victim_allocation: &AllocationPolicy,
    policy: EnginePolicy,
    short_only: bool,
    inherited: Option<&Composition>,
) -> Result<EnginePlan, EngineFailure> {
    plan_core_family_with_pending(
        request,
        victim_allocation,
        policy,
        short_only,
        inherited,
        None,
    )
}

fn plan_core_family_with_pending(
    request: &PlanningRequest<'_>,
    victim_allocation: &AllocationPolicy,
    policy: EnginePolicy,
    short_only: bool,
    inherited: Option<&Composition>,
    pending: Option<&[AddressRange]>,
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
            Tactic::NeighborEviction => match if let (true, Some(predecessor), Some(pending)) =
                (short_only, inherited, pending)
            {
                neighbor::plan_neighbor_short_pending_core(
                    request,
                    predecessor,
                    pending,
                    victim_allocation,
                    policy.neighbor,
                    policy.bundle,
                )
            } else if short_only {
                match inherited {
                    Some(predecessor) => neighbor::plan_neighbor_short_after_core(
                        request,
                        predecessor,
                        victim_allocation,
                        policy.neighbor,
                        policy.bundle,
                    ),
                    None => neighbor::plan_neighbor_short_core(
                        request,
                        victim_allocation,
                        policy.neighbor,
                        policy.bundle,
                    ),
                }
            } else {
                neighbor::plan_neighbor_core(
                    request,
                    victim_allocation,
                    policy.neighbor,
                    policy.bundle,
                )
            } {
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
