//! Forced neighboring-instruction eviction (T3).
//!
//! Original instruction identity is never recovered from a rewrite overlay.
//! The selected head receives EB to a private source relay in one whole victim;
//! both immutable images and every source dependency are published as a bundle.

use crate::bundle::{BundleBudget, PlannedBundle};
use crate::composition::Composition;
use crate::contracts::*;
use crate::emission::{ArtifactMetrics, ArtifactPlan, ArtifactRequest, PlanningRequest};
use crate::eviction::{
    image_allocation, instruction_member_core, near_redirect, qualify_victim_core,
};
use crate::planner::HookSemantics;
use crate::quiescent::{self, AllocationPolicy, InstallRequest};
use crate::scanner::{ScanResult, ScannedInstruction};
use crate::search::{RefusalClass, SearchDomain, SearchEvidence, SearchScope};
use crate::trampoline::{PreparedArtifact, TrampolineImage, TrampolinePlan};

/// Independent bounds for the forced neighboring-victim search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NeighborSearch {
    /// If present, this exact original head is the only possible victim.
    pub forced_victim: Option<u64>,
    /// Maximum geometrically eligible original victim heads examined.
    pub max_victims: usize,
    /// Maximum selected placement candidate slots across all victim placements.
    pub max_pairs: usize,
}

impl Default for NeighborSearch {
    fn default() -> Self {
        Self {
            forced_victim: None,
            max_victims: 32,
            max_pairs: 256,
        }
    }
}

/// Exact source and image geometry, bound to the enclosing bundle's generation.
///
/// `relay` is a private generated source transfer, not an original legal entry.
/// This record does not register process-lifetime PC authority for source bytes
/// and does not add asynchronous signal/unwind transparency to the existing ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NeighborGeometry {
    /// Selected original instruction head.
    pub selected: u64,
    /// Whole original selected instruction length, 2..=4.
    pub selected_len: usize,
    /// Original victim instruction head.
    pub victim: u64,
    /// Whole original victim length: 10..=15, or 6..=9 via an explicit short family.
    pub victim_len: usize,
    /// Exact second E9 address, victim + 5.
    pub relay: u64,
    /// EB displacement from selected + 2 to the relay.
    pub rel8: i8,
    /// Observing/replacing selected image entry.
    pub selected_target: u64,
    /// Callback-free victim image entry.
    pub victim_target: u64,
}

/// Stage of an unsuccessful candidate, or the final successful composition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NeighborAttemptStage {
    /// Original instruction/entry/short-branch qualification.
    Qualification,
    /// Callback-free image placement, before a selected target is considered.
    VictimPlacement,
    /// A charged joint pair, including an unrepresentable selected target.
    SelectedPlacement,
    /// Both images are placed and their complete source transaction is checked.
    Composition,
    /// Direct fit certificate refused before the same charged slot uses a veneer.
    EntryVeneerCertificate,
}

/// Ordered, bounded search evidence; unavailable targets remain explicit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NeighborAttempt {
    /// Original victim head considered.
    pub victim: u64,
    /// Attempt stage, including when a target could not be represented.
    pub stage: NeighborAttemptStage,
    /// Callback-free image candidate, when representable.
    pub victim_target: Option<u64>,
    /// Selected image candidate, when representable.
    pub selected_target: Option<u64>,
    /// None only for the final, completely composed successful transaction.
    pub refusal: Option<Refusal>,
}

/// Search and execution geometry without performance estimates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NeighborMetrics {
    /// Explicit bounded-search evidence; incomplete proofs remain marked.
    pub search: SearchEvidence,
    /// Geometrically eligible original heads examined, including qualifications.
    pub victims_examined: usize,
    /// Charged selected-placement candidate slots across all victims/placements.
    pub pairs_examined: usize,
    /// EB, source relay E9 and generated continuation for selected fallthrough.
    /// The explicit artifact entry-veneer path adds its checked fourth redirect.
    pub selected_fallthrough_redirects: usize,
    /// Entry E9 and generated continuation for victim fallthrough.
    pub victim_fallthrough_redirects: usize,
    /// Ordered refused candidates followed by the successful composition.
    pub attempts: Vec<NeighborAttempt>,
}

/// Trusted, immutable T3 transaction; its members cannot be published separately.
#[derive(Clone, Debug)]
pub struct PlannedNeighbor {
    bundle: PlannedBundle,
    geometry: NeighborGeometry,
    metrics: NeighborMetrics,
}

impl PlannedNeighbor {
    /// Complete source/image/lease/publication transaction.
    pub const fn bundle(&self) -> &PlannedBundle {
        &self.bundle
    }
    /// Exact original heads, relay and generated destinations.
    pub const fn geometry(&self) -> &NeighborGeometry {
        &self.geometry
    }
    /// Bounded search inventory and auxiliary transfer accounting.
    pub const fn metrics(&self) -> &NeighborMetrics {
        &self.metrics
    }
}

/// Failed forced search, retaining all attempted-stage evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NeighborFailure {
    /// Explicit bounded-search evidence; incomplete proofs remain marked.
    pub search: SearchEvidence,
    /// Final fail-closed reason; a refusal is not successful tactic coverage.
    pub reason: Refusal,
    /// Ordered candidate outcomes after common original-source validation.
    pub attempts: Vec<NeighborAttempt>,
}

/// Forces T3 with EB at the selected head and two E9s inside one whole victim.
///
/// The selected instruction is 2..=4 bytes and the victim is 10..=15 bytes.
/// Their original intervals must be disjoint, within the owned function and
/// exhaustive entry scope. Original observation/branch/rejoin semantics remain
/// those of the existing qualified emitters. ReplaceFirst skips only the selected
/// instruction. The victim redirect/image itself adds no selected hook.
///
/// Victims are considered in descending original-address order. A forced victim
/// is never substituted. `request.search.tactics` and `max_upstream_bytes` apply
/// to the ordinary single-image planner and are explicitly unused here. A zero
/// `max_sites` still refuses, and `max_displaced_bytes` bounds each whole original
/// instruction. `request.allocation` controls the selected image; the separate
/// policy controls the victim image. Both full mappings count against the bundle.
/// Planning performs no source stores or executable reservations.
pub fn plan_neighbor(
    request: &InstallRequest<'_>,
    victim_allocation: &AllocationPolicy,
    search: NeighborSearch,
    budget: BundleBudget,
) -> Result<PlannedNeighbor, Refusal> {
    plan_neighbor_detailed(request, victim_allocation, search, budget)
        .map_err(|failure| failure.reason)
}

/// Forced T3 planner retaining candidate diagnostics on failure.
pub fn plan_neighbor_detailed(
    request: &InstallRequest<'_>,
    victim_allocation: &AllocationPolicy,
    search: NeighborSearch,
    budget: BundleBudget,
) -> Result<PlannedNeighbor, NeighborFailure> {
    plan_neighbor_core(
        &PlanningRequest::live(request),
        victim_allocation,
        search,
        budget,
    )
}

/// Forces T3 with symbolic selected/victim images in one target environment.
/// The source relay and all pending artifact requirements remain inspectable.
pub fn plan_neighbor_with_emission(
    request: &ArtifactRequest<'_>,
    victim_allocation: &AllocationPolicy,
    search: NeighborSearch,
    budget: BundleBudget,
) -> Result<ArtifactPlan, NeighborFailure> {
    plan_neighbor_core(
        &PlanningRequest::artifact(request),
        victim_allocation,
        search,
        budget,
    )
    .map(|plan| {
        ArtifactPlan::bundle(
            plan.bundle(),
            ArtifactMetrics::Neighbor(*plan.geometry(), plan.metrics().clone()),
        )
    })
}

pub(crate) fn plan_neighbor_core(
    request: &PlanningRequest<'_>,
    victim_allocation: &AllocationPolicy,
    search: NeighborSearch,
    budget: BundleBudget,
) -> Result<PlannedNeighbor, NeighborFailure> {
    plan_neighbor_mode(request, victim_allocation, search, budget, false)
}

pub(crate) fn plan_neighbor_long_after_core(
    request: &PlanningRequest<'_>,
    predecessor: &Composition,
    victim_allocation: &AllocationPolicy,
    search: NeighborSearch,
    budget: BundleBudget,
) -> Result<PlannedNeighbor, NeighborFailure> {
    plan_neighbor_mode_with_inherited(
        request,
        victim_allocation,
        search,
        budget,
        false,
        Some(predecessor),
    )
}

pub(crate) fn plan_neighbor_short_core(
    request: &PlanningRequest<'_>,
    victim_allocation: &AllocationPolicy,
    search: NeighborSearch,
    budget: BundleBudget,
) -> Result<PlannedNeighbor, NeighborFailure> {
    plan_neighbor_mode(request, victim_allocation, search, budget, true)
}

pub(crate) fn plan_neighbor_short_after_core(
    request: &PlanningRequest<'_>,
    predecessor: &Composition,
    victim_allocation: &AllocationPolicy,
    search: NeighborSearch,
    budget: BundleBudget,
) -> Result<PlannedNeighbor, NeighborFailure> {
    plan_neighbor_mode_with_inherited(
        request,
        victim_allocation,
        search,
        budget,
        true,
        Some(predecessor),
    )
}

fn plan_neighbor_mode(
    request: &PlanningRequest<'_>,
    victim_allocation: &AllocationPolicy,
    search: NeighborSearch,
    budget: BundleBudget,
    short_victims: bool,
) -> Result<PlannedNeighbor, NeighborFailure> {
    plan_neighbor_mode_with_inherited(
        request,
        victim_allocation,
        search,
        budget,
        short_victims,
        None,
    )
}

pub(crate) fn plan_neighbor_short_pending_core(
    request: &PlanningRequest<'_>,
    predecessor: &Composition,
    pending: &[AddressRange],
    victim_allocation: &AllocationPolicy,
    search: NeighborSearch,
    budget: BundleBudget,
) -> Result<PlannedNeighbor, NeighborFailure> {
    plan_neighbor_mode_with_pending(
        request,
        victim_allocation,
        search,
        budget,
        true,
        Some(predecessor),
        Some(pending),
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum VictimFamily {
    Long,
    Short,
    Mixed,
}

pub(crate) fn plan_neighbor_mixed_pending_core(
    request: &PlanningRequest<'_>,
    predecessor: &Composition,
    pending: &[AddressRange],
    victim_allocation: &AllocationPolicy,
    search: NeighborSearch,
    budget: BundleBudget,
) -> Result<PlannedNeighbor, NeighborFailure> {
    plan_neighbor_family_with_pending(
        request,
        victim_allocation,
        search,
        budget,
        VictimFamily::Mixed,
        Some(predecessor),
        Some(pending),
    )
}

fn plan_neighbor_mode_with_inherited(
    request: &PlanningRequest<'_>,
    victim_allocation: &AllocationPolicy,
    search: NeighborSearch,
    budget: BundleBudget,
    short_victims: bool,
    inherited: Option<&Composition>,
) -> Result<PlannedNeighbor, NeighborFailure> {
    plan_neighbor_mode_with_pending(
        request,
        victim_allocation,
        search,
        budget,
        short_victims,
        inherited,
        None,
    )
}

fn plan_neighbor_mode_with_pending(
    request: &PlanningRequest<'_>,
    victim_allocation: &AllocationPolicy,
    search: NeighborSearch,
    budget: BundleBudget,
    short_victims: bool,
    inherited: Option<&Composition>,
    pending: Option<&[AddressRange]>,
) -> Result<PlannedNeighbor, NeighborFailure> {
    plan_neighbor_family_with_pending(
        request,
        victim_allocation,
        search,
        budget,
        if short_victims {
            VictimFamily::Short
        } else {
            VictimFamily::Long
        },
        inherited,
        pending,
    )
}

fn plan_neighbor_family_with_pending(
    request: &PlanningRequest<'_>,
    victim_allocation: &AllocationPolicy,
    search: NeighborSearch,
    budget: BundleBudget,
    family: VictimFamily,
    inherited: Option<&Composition>,
    pending: Option<&[AddressRange]>,
) -> Result<PlannedNeighbor, NeighborFailure> {
    let result = plan_neighbor_family_with_layout(
        request,
        victim_allocation,
        search,
        budget,
        NeighborLayout {
            family,
            entry_veneer: false,
        },
        inherited,
        pending,
    )?;
    match result.pair {
        NeighborPair::Direct(bundle) => Ok(PlannedNeighbor {
            bundle,
            geometry: result.geometry,
            metrics: result.metrics,
        }),
        NeighborPair::Artifact(_) => Err(NeighborFailure {
            reason: Refusal::InvalidPlan,
            attempts: result.metrics.attempts,
            search: result.metrics.search,
        }),
    }
}

fn plan_neighbor_family_with_layout(
    request: &PlanningRequest<'_>,
    victim_allocation: &AllocationPolicy,
    search: NeighborSearch,
    budget: BundleBudget,
    layout: NeighborLayout,
    inherited: Option<&Composition>,
    pending: Option<&[AddressRange]>,
) -> Result<NeighborResult, NeighborFailure> {
    let NeighborLayout {
        family,
        entry_veneer,
    } = layout;
    let short_victims = family == VictimFamily::Short;
    let mut attempts = Vec::new();
    let mut search_evidence = SearchEvidence::default();
    let result = (|| {
        let (source, scan) = quiescent::validated_source_core(request)
            .inspect_err(|reason| search_evidence.qualification(SearchScope::default(), reason))?;
        let selected_scope = SearchScope {
            physical_pc: Some(request.logical_pc),
            ..SearchScope::default()
        };
        let selected = qualify_selected(request, &scan).inspect_err(|reason| {
            // max_sites=0 is a work limit, not a geometric prerequisite proof.
            if request.search.max_sites != 0 {
                search_evidence.qualification(selected_scope, reason);
            }
        })?;
        if search.max_victims == 0
            || search.max_pairs == 0
            || budget.max_steps < 2
            || budget.max_mappings < 2
            || budget.max_virtual_bytes < 8192
            || budget.max_backing_bytes < 8192
            || [request.allocation, victim_allocation]
                .iter()
                .any(|policy| {
                    policy.max_candidates == 0
                        || policy.max_mappings == 0
                        || policy.max_mapped_bytes < 4096
                })
        {
            let class = if budget.max_steps < 2
                || budget.max_mappings < 2
                || budget.max_virtual_bytes < 8192
                || budget.max_backing_bytes < 8192
                || [request.allocation, victim_allocation]
                    .iter()
                    .any(|policy| policy.max_mappings == 0 || policy.max_mapped_bytes < 4096)
            {
                RefusalClass::ResourceCapacity
            } else {
                RefusalClass::Unclassified
            };
            search_evidence.refusal(selected_scope, class, &Refusal::AllocationUnavailable);
            return Err(Refusal::AllocationUnavailable);
        }
        let selected_range = AddressRange::new(selected.address(), selected.len())?;
        let candidates = if let Some(forced) = search.forced_victim {
            match scan
                .instructions()
                .iter()
                .find(|item| item.address() == forced)
            {
                Some(victim) => vec![victim],
                None => {
                    attempts.push(NeighborAttempt {
                        victim: forced,
                        stage: NeighborAttemptStage::Qualification,
                        victim_target: None,
                        selected_target: None,
                        refusal: Some(Refusal::NotInstructionHead),
                    });
                    return Err(Refusal::NotInstructionHead);
                }
            }
        } else if family == VictimFamily::Mixed {
            scan.instructions()
                .iter()
                .rev()
                .filter(|item| {
                    (6..=15).contains(&item.len())
                        && AddressRange::new(item.address(), item.len()).is_ok_and(|range| {
                            !range.overlaps(selected_range) && request.function.covers(range)
                        })
                        && short_redirect(selected.address(), item.address()).is_ok()
                })
                .collect()
        } else if short_victims {
            scan.instructions()
                .iter()
                .rev()
                .filter(|item| {
                    (6..=9).contains(&item.len())
                        && AddressRange::new(item.address(), item.len()).is_ok_and(|range| {
                            !range.overlaps(selected_range) && request.function.covers(range)
                        })
                        && short_redirect(selected.address(), item.address()).is_ok()
                })
                .collect()
        } else {
            scan.instructions()
                .iter()
                .rev()
                .filter(|item| {
                    (10..=15).contains(&item.len())
                        && AddressRange::new(item.address(), item.len()).is_ok_and(|range| {
                            !range.overlaps(selected_range) && request.function.covers(range)
                        })
                        && short_redirect(selected.address(), item.address()).is_ok()
                })
                .collect()
        };
        let victims = search_evidence.begin(
            SearchDomain::Victims,
            selected_scope,
            search.max_victims,
            Some(candidates.len()),
        );
        let pair_search = search_evidence.begin(
            SearchDomain::JointPairs,
            selected_scope,
            search.max_pairs,
            None,
        );
        let occupied = request.emission.occupied()?;
        let selected_plan = request
            .emission
            .short(
                &scan,
                selected.address(),
                request.semantics == HookSemantics::ReplaceFirst,
            )
            .map_err(|error| Refusal::Backend(error.to_string()))?;
        let mut pairs_examined = 0;
        let mut last_error = Refusal::NoPatchWindow;
        // A failed joint composition is more informative than a later unavailable
        // victim placement. Keep it separately, as in the successor planner.
        let mut joint_error = None;
        for (victim_index, victim) in candidates.into_iter().take(search.max_victims).enumerate() {
            let victims_examined = victim_index + 1;
            search_evidence.visit(victims);
            // The mixed domain uses the existing proof for this victim's length,
            // including the complete ten-byte fetch for every 6..=9-byte victim.
            // Its one descending catalogue shares the same victim and pair scopes.
            let short_victims =
                short_victims || (family == VictimFamily::Mixed && (6..=9).contains(&victim.len()));
            let victim_scope = SearchScope {
                physical_pc: Some(victim.address()),
                ..SearchScope::default()
            };
            let qualification = (|| {
                let victim_range = if short_victims {
                    if !(6..=9).contains(&victim.len()) {
                        return Err(Refusal::NoPatchWindow);
                    }
                    qualify_victim_core(request, &scan, victim, 6)?
                } else {
                    qualify_victim_core(request, &scan, victim, 10)?
                };
                if victim_range.overlaps(selected_range) {
                    return Err(Refusal::NoPatchWindow);
                }
                let (relay, rel8, patch) = short_redirect(selected.address(), victim.address())?;
                let short_relay = if short_victims {
                    Some(short::Relay::new(request, source, victim_range, patch)?)
                } else {
                    None
                };
                Ok((victim_range, relay, rel8, patch, short_relay))
            })();
            let (victim_range, relay, rel8, selected_patch, short_relay) = match qualification {
                Ok(value) => value,
                Err(reason) => {
                    search_evidence.qualification(victim_scope, &reason);
                    attempts.push(NeighborAttempt {
                        victim: victim.address(),
                        stage: NeighborAttemptStage::Qualification,
                        victim_target: None,
                        selected_target: None,
                        refusal: Some(reason.clone()),
                    });
                    last_error = reason;
                    continue;
                }
            };
            let victim_plan = TrampolinePlan::from_instruction(&scan, victim.address())
                .map_err(|error| Refusal::Backend(error.to_string()))?;
            let victim_images = search_evidence.begin(
                SearchDomain::VictimImages,
                victim_scope,
                victim_allocation.max_candidates,
                None,
            );
            let mut fitted_victim = prepare_fitting_placement(
                request,
                &victim_plan,
                victim_allocation,
                source,
                &occupied,
                victim.address(),
                None,
            );
            let effective_victim = fitted_victim
                .as_ref()
                .ok()
                .and_then(|fit| fit.as_ref().map(|fit| fit.policy.clone()));
            let victim_policy = effective_victim.as_ref().unwrap_or(victim_allocation);
            for victim_candidate in 0..victim_allocation.max_candidates {
                search_evidence.visit(victim_images);
                let victim_target = if fitted_victim.is_err() {
                    None
                } else {
                    quiescent::candidate_target(
                        victim.address(),
                        [false; 4],
                        victim_policy.preferred_address,
                        victim_candidate,
                    )
                };
                let placed = place_fitting_or_original(
                    &mut fitted_victim,
                    (request.emission, &victim_plan),
                    victim_target,
                    victim_policy,
                    source,
                    &occupied,
                    None,
                );
                let (victim_image, victim_mapping) = match placed {
                    Ok(value) => value,
                    Err(reason) => {
                        attempts.push(NeighborAttempt {
                            victim: victim.address(),
                            stage: NeighborAttemptStage::VictimPlacement,
                            victim_target,
                            selected_target: None,
                            refusal: Some(reason.clone()),
                        });
                        last_error = reason;
                        continue;
                    }
                };
                let victim_target = victim_image.address();
                let selected_images = search_evidence.begin(
                    SearchDomain::SelectedImages,
                    SearchScope {
                        victim_target: Some(victim_target),
                        ..selected_scope
                    },
                    request.allocation.max_candidates,
                    None,
                );
                // Only the new fitting context augments preference selection.
                // The unchanged real-image check below still checks `other` too.
                let selected_occupied = if request.emission.fitting_placement() {
                    let mut held = occupied.clone();
                    held.push(victim_mapping);
                    held
                } else {
                    Vec::new()
                };
                let mut fitted_selected =
                    if let (true, Some(short)) = (entry_veneer, short_relay.as_ref()) {
                        prepare_entry_veneer_placement(
                            request,
                            &selected_plan,
                            request.allocation,
                            source,
                            &selected_occupied,
                            short.window(),
                        )
                    } else {
                        prepare_fitting_placement(
                            request,
                            &selected_plan,
                            request.allocation,
                            source,
                            if request.emission.fitting_placement() {
                                &selected_occupied
                            } else {
                                &occupied
                            },
                            relay,
                            short_relay.as_ref().map(|relay| relay.window()),
                        )
                    };
                let effective_selected = fitted_selected
                    .as_ref()
                    .ok()
                    .and_then(|fit| fit.as_ref().map(|fit| fit.policy.clone()));
                let selected_policy = effective_selected.as_ref().unwrap_or(request.allocation);
                let short_candidates = if fitted_selected.is_err() {
                    None
                } else {
                    short_relay
                        .as_ref()
                        .map(|relay| quiescent::pun_candidates(relay.window(), selected_policy))
                };
                let selected_slots = short_candidates
                    .as_ref()
                    .map_or(request.allocation.max_candidates, |c| c.addresses.len());
                if short_candidates
                    .as_ref()
                    .is_some_and(|c| c.addresses.is_empty())
                {
                    last_error = Refusal::AllocationUnavailable;
                }
                for selected_candidate in 0..selected_slots {
                    if pairs_examined == search.max_pairs {
                        // This entered loop has one current, unexamined pair.
                        search_evidence.known_limit_hit(pair_search, 1);
                        return Err(joint_error.unwrap_or(Refusal::AllocationUnavailable));
                    }
                    pairs_examined += 1;
                    search_evidence.visit(pair_search);
                    search_evidence.visit(selected_images);
                    if fitted_selected
                        .as_ref()
                        .ok()
                        .and_then(|fit| fit.as_ref())
                        .is_some_and(|fit| fit.veneer.is_some())
                    {
                        search_evidence.refusal(
                            SearchScope {
                                victim_target: Some(victim_target),
                                ..selected_scope
                            },
                            RefusalClass::ResourceCapacity,
                            &Refusal::AllocationUnavailable,
                        );
                        attempts.push(NeighborAttempt {
                            victim: victim.address(),
                            stage: NeighborAttemptStage::EntryVeneerCertificate,
                            victim_target: Some(victim_target),
                            selected_target: None,
                            refusal: Some(Refusal::AllocationUnavailable),
                        });
                    }
                    // This E9 starts at V+5: candidate_target adds five to that
                    // actual origin, not to the selected original instruction.
                    let selected_target = if fitted_selected.is_err() {
                        None
                    } else if let Some(candidates) = &short_candidates {
                        Some(candidates.addresses[selected_candidate])
                    } else {
                        quiescent::candidate_target(
                            relay,
                            [false; 4],
                            selected_policy.preferred_address,
                            selected_candidate,
                        )
                    };
                    let placed = place_selected_artifact_or_original(
                        &mut fitted_selected,
                        (request.emission, &selected_plan),
                        selected_target,
                        selected_policy,
                        source,
                        &occupied,
                        Some(victim_mapping),
                    );
                    let (selected_image, selected_mapping) = match placed {
                        Ok(value) => value,
                        Err(reason) => {
                            attempts.push(NeighborAttempt {
                                victim: victim.address(),
                                stage: NeighborAttemptStage::SelectedPlacement,
                                victim_target: Some(victim_target),
                                selected_target,
                                refusal: Some(reason.clone()),
                            });
                            joint_error = Some(reason);
                            continue;
                        }
                    };
                    let selected_target = selected_image.view().entry_address();
                    let has_veneer = selected_image.view().entry_veneer().is_some();
                    let composed = compose_selected_pair(
                        request,
                        source,
                        selected_patch,
                        ArtifactPlacedInstruction {
                            displaced: selected_range,
                            image: selected_image,
                            allocation: selected_mapping,
                            candidate: selected_candidate,
                        },
                        ArtifactPlacedInstruction {
                            displaced: victim_range,
                            image: crate::emission::ArtifactStoredImage::Direct(
                                victim_image.clone(),
                            ),
                            allocation: victim_mapping,
                            candidate: victim_candidate,
                        },
                        budget,
                        (short_relay.as_ref(), entry_veneer),
                    );
                    // Inherited refusal consumes this already charged pair. Check
                    // every step before recording success, without mutating prior state.
                    let composed = composed.and_then(|bundle| {
                        if let Some(predecessor) = inherited {
                            let mut current = predecessor.clone();
                            for step in bundle.plan().steps() {
                                current.append(step)?;
                            }
                            if let Some(pending) = pending {
                                current.require_unclaimed_ranges(pending)?;
                            }
                        }
                        Ok(bundle)
                    });
                    attempts.push(NeighborAttempt {
                        victim: victim.address(),
                        stage: NeighborAttemptStage::Composition,
                        victim_target: Some(victim_target),
                        selected_target: Some(selected_target),
                        refusal: composed.as_ref().err().cloned(),
                    });
                    match composed {
                        Ok(bundle) => {
                            for id in [victims, pair_search, victim_images, selected_images] {
                                search_evidence.accept(id);
                            }
                            return Ok(NeighborResult {
                                pair: bundle,
                                geometry: NeighborGeometry {
                                    selected: selected.address(),
                                    selected_len: selected.len(),
                                    victim: victim.address(),
                                    victim_len: victim.len(),
                                    relay,
                                    rel8,
                                    selected_target,
                                    victim_target,
                                },
                                metrics: NeighborMetrics {
                                    search: SearchEvidence::default(),
                                    victims_examined,
                                    pairs_examined,
                                    selected_fallthrough_redirects: if has_veneer { 4 } else { 3 },
                                    victim_fallthrough_redirects: 2,
                                    attempts: attempts.clone(),
                                },
                            });
                        }
                        Err(reason) => joint_error = Some(reason),
                    }
                }
                if fitted_selected.is_err() {
                    // Preparation/certification refusal consumed its one slot;
                    // no uncapped target schedule was established.
                    search_evidence.finish(selected_images);
                } else {
                    search_evidence.finish_candidates(
                        selected_images,
                        if let Some(candidates) = short_candidates {
                            candidates.proof
                        } else {
                            quiescent::candidate_target_proof(
                                relay,
                                [false; 4],
                                selected_policy.preferred_address,
                                selected_policy.max_candidates,
                            )
                        },
                    );
                }
            }
            if fitted_victim.is_err() {
                search_evidence.finish(victim_images);
            } else {
                search_evidence.finish_candidates(
                    victim_images,
                    quiescent::candidate_target_proof(
                        victim.address(),
                        [false; 4],
                        victim_policy.preferred_address,
                        victim_policy.max_candidates,
                    ),
                );
            }
        }
        search_evidence.finish(victims);
        search_evidence.finish(pair_search);
        Err(joint_error.unwrap_or(last_error))
    })();
    match result {
        Ok(mut plan) => {
            search_evidence.accepted = true;
            plan.metrics.search = search_evidence;
            Ok(plan)
        }
        Err(reason) => Err(NeighborFailure {
            reason,
            attempts,
            search: search_evidence,
        }),
    }
}

fn qualify_selected<'a>(
    request: &PlanningRequest<'_>,
    scan: &'a ScanResult,
) -> Result<&'a ScannedInstruction, Refusal> {
    let selected = scan
        .instructions()
        .iter()
        .find(|item| item.address() == request.logical_pc)
        .ok_or(Refusal::NotInstructionHead)?;
    let displaced = AddressRange::new(selected.address(), selected.len())?;
    if request.search.max_sites == 0
        || !(2..=4).contains(&selected.len())
        || selected.len() > request.search.max_displaced_bytes
        || !request.block.covers(displaced)
    {
        return Err(Refusal::NoPatchWindow);
    }
    if request.semantics != HookSemantics::ReplaceFirst {
        quiescent::qualify_instruction(selected.instruction())?;
    }
    if request
        .entries
        .entries
        .iter()
        .any(|entry| displaced.contains(entry.address) && entry.requires_endbr)
    {
        return Err(Refusal::UnsupportedSemantics(
            "CET IBT landing pad at neighboring-eviction selected instruction".into(),
        ));
    }
    if scan.instructions().iter().any(|item| {
        matches!(
            item.instruction().op0_kind(),
            iced_x86::OpKind::NearBranch16
                | iced_x86::OpKind::NearBranch32
                | iced_x86::OpKind::NearBranch64
        ) && displaced.contains(item.instruction().near_branch_target())
            && item.instruction().near_branch_target() != selected.address()
    }) {
        return Err(Refusal::NotInstructionHead);
    }
    // ReplaceFirst also must not bypass a previously changed original operation.
    request.require_original(displaced)?;
    Ok(selected)
}

fn short_redirect(selected: u64, victim: u64) -> Result<(u64, i8, [u8; 2]), Refusal> {
    let relay = victim.checked_add(5).ok_or(Refusal::InvalidRange)?;
    let next = selected.checked_add(2).ok_or(Refusal::InvalidRange)?;
    let rel8 =
        i8::try_from(i128::from(relay) - i128::from(next)).map_err(|_| Refusal::NoPatchWindow)?;
    Ok((relay, rel8, [0xeb, rel8 as u8]))
}

// A prepared image is owned, not Clone: exactly one charged candidate can
// consume it. Old contexts return None before any preparation or policy change.
struct FittingPlacement {
    image: Option<PreparedArtifact>,
    policy: AllocationPolicy,
    veneer: Option<crate::trampoline::EntryVeneerPlacement>,
}

fn prepare_fitting_placement(
    request: &PlanningRequest<'_>,
    plan: &TrampolinePlan,
    policy: &AllocationPolicy,
    source: AddressRange,
    occupied: &[AddressRange],
    physical: u64,
    window: Option<AddressRange>,
) -> Result<Option<FittingPlacement>, Refusal> {
    let Some(image) = request
        .emission
        .prepare_fitting(plan)
        .map_err(|error| Refusal::Backend(error.to_string()))?
    else {
        return Ok(None);
    };
    let policy = if let Some(window) = window {
        crate::emission::placement::fitting_for_pun(
            policy,
            window,
            occupied,
            source,
            image.size_bound(),
        )?
    } else {
        crate::emission::placement::fitting_for_relocation(
            policy,
            physical,
            [false; 4],
            occupied,
            source,
            image.size_bound(),
        )?
    };
    Ok(Some(FittingPlacement {
        image: Some(image),
        policy,
        veneer: None,
    }))
}

fn place_fitting_or_original(
    fitting: &mut Result<Option<FittingPlacement>, Refusal>,
    original: (crate::emission::EmissionContext<'_>, &TrampolinePlan),
    target: Option<u64>,
    policy: &AllocationPolicy,
    source: AddressRange,
    occupied: &[AddressRange],
    other: Option<AddressRange>,
) -> Result<(TrampolineImage, AddressRange), Refusal> {
    let (emission, plan) = original;
    let prepared = match fitting {
        Ok(None) => return place_image(emission, plan, target, policy, source, occupied, other),
        Err(reason) => return Err(reason.clone()),
        Ok(Some(fit)) => fit.image.take().ok_or(Refusal::InvalidPlan)?,
    };
    let target = target.ok_or(Refusal::AllocationUnavailable)?;
    let image = prepared
        .emit_at(target)
        .map_err(|error| Refusal::Backend(error.to_string()))?;
    // Same actual-image extent, permit, source and occupancy checks as the
    // original path. A certificate never replaces these post-encode checks.
    let allocation = image_allocation(&image)?;
    if allocation.len() > policy.max_mapped_bytes as u64
        || !policy.ranges.iter().any(|range| range.covers(allocation))
        || source.overlaps(allocation)
        || occupied.iter().any(|range| range.overlaps(allocation))
        || other.is_some_and(|range| range.overlaps(allocation))
    {
        return Err(Refusal::AllocationUnavailable);
    }
    Ok((image, allocation))
}

fn place_image(
    emission: crate::emission::EmissionContext<'_>,
    plan: &TrampolinePlan,
    target: Option<u64>,
    policy: &AllocationPolicy,
    source: AddressRange,
    occupied: &[AddressRange],
    other: Option<AddressRange>,
) -> Result<(TrampolineImage, AddressRange), Refusal> {
    let target = target.ok_or(Refusal::AllocationUnavailable)?;
    let image = emission
        .emit(plan, target)
        .map_err(|error| Refusal::Backend(error.to_string()))?;
    let allocation = image_allocation(&image)?;
    if allocation.len() > policy.max_mapped_bytes as u64
        || !policy.ranges.iter().any(|range| range.covers(allocation))
        || source.overlaps(allocation)
        || occupied.iter().any(|range| range.overlaps(allocation))
        || other.is_some_and(|range| range.overlaps(allocation))
    {
        return Err(Refusal::AllocationUnavailable);
    }
    Ok((image, allocation))
}

struct PlacedInstruction {
    displaced: AddressRange,
    image: TrampolineImage,
    allocation: AddressRange,
    candidate: usize,
}

fn compose_pair(
    request: &PlanningRequest<'_>,
    source: AddressRange,
    selected_patch: [u8; 2],
    selected: PlacedInstruction,
    victim: PlacedInstruction,
    budget: BundleBudget,
    short_relay: Option<&short::Relay>,
) -> Result<PlannedBundle, Refusal> {
    let relay = victim
        .displaced
        .start()
        .checked_add(5)
        .ok_or(Refusal::InvalidRange)?;
    let mut victim_patch = near_redirect(victim.displaced.start(), victim.image.address())?;
    victim_patch.extend_from_slice(&near_redirect(relay, selected.image.address())?);
    if let Some(short) = short_relay {
        short.check_patch(&victim_patch, selected.image.address())?;
    }
    let mut source_members = [(selected, selected_patch.to_vec()), (victim, victim_patch)];
    source_members.sort_unstable_by_key(|member| std::cmp::Reverse(member.0.displaced.start()));
    let mut overlay = request.code.to_vec();
    let mut members = Vec::with_capacity(2);
    for (placed, patch) in source_members {
        let overlaid = request.with_code(&overlay);
        if let Some(short) = short_relay.filter(|r| r.victim() == placed.displaced.start()) {
            short.check_current(&overlaid, source, &patch)?;
        }
        let member = instruction_member_core(
            &overlaid,
            source,
            placed.displaced,
            placed.image,
            placed.allocation,
            patch,
            placed.candidate,
        )?;
        // Original identities/images were established before this loop. Only
        // the next member's authenticated byte reads observe the virtual edits.
        for edit in &member.plan().parts().writes {
            let offset = (edit.address - source.start()) as usize;
            overlay[offset..offset + edit.bytes.len()].copy_from_slice(&edit.bytes);
        }
        members.push(member);
    }
    PlannedBundle::compose(
        vec![ExpectedBytes {
            address: source.start(),
            bytes: request.code.to_vec(),
        }],
        members,
        budget,
    )
}

// Explicit short-only same-function authority; no engine or cross-function widening.
#[path = "neighbor_short.rs"]
mod short;
pub use short::{
    plan_neighbor_short, plan_neighbor_short_detailed, plan_neighbor_short_with_emission,
};

// Explicit second-function artifact authority; existing same-function paths stay separate.
#[path = "neighbor_cross_function.rs"]
mod cross_function;
pub use cross_function::plan_neighbor_with_emission_from;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_redirect_has_exact_signed_endpoints_without_wrapping() {
        let selected = 0x1000;
        assert_eq!(
            short_redirect(selected, selected - 131),
            Ok((selected - 126, -128, [0xeb, 0x80]))
        );
        assert_eq!(
            short_redirect(selected, selected + 124),
            Ok((selected + 129, 127, [0xeb, 0x7f]))
        );
        assert_eq!(
            short_redirect(selected, selected - 132),
            Err(Refusal::NoPatchWindow)
        );
        assert_eq!(
            short_redirect(selected, selected + 125),
            Err(Refusal::NoPatchWindow)
        );
        assert_eq!(short_redirect(0, u64::MAX), Err(Refusal::InvalidRange));
        assert_eq!(short_redirect(u64::MAX, 0), Err(Refusal::InvalidRange));
        assert_eq!(short_redirect(0, 128), Err(Refusal::NoPatchWindow));
    }
}

#[cfg(test)]
#[path = "neighbor_long_ownership_tests.rs"]
mod long_ownership_tests;

// Private result adapter: old routes can only unwrap Direct; the opt-in artifact
// route carries a checked pair without manufacturing a publishable live handle.
struct NeighborResult {
    pair: NeighborPair,
    geometry: NeighborGeometry,
    metrics: NeighborMetrics,
}
enum NeighborPair {
    Direct(PlannedBundle),
    Artifact(crate::bundle::CheckedArtifactPair),
}
impl NeighborPair {
    fn plan(&self) -> &crate::bundle::BundlePlan {
        match self {
            Self::Direct(pair) => pair.plan(),
            Self::Artifact(pair) => &pair.plan,
        }
    }
}

pub(crate) fn plan_neighbor_entry_veneer_pending_core(
    request: &PlanningRequest<'_>,
    predecessor: &Composition,
    pending: &[AddressRange],
    victim_allocation: &AllocationPolicy,
    search: NeighborSearch,
    budget: BundleBudget,
) -> Result<ArtifactPlan, NeighborFailure> {
    let result = plan_neighbor_family_with_layout(
        request,
        victim_allocation,
        search,
        budget,
        NeighborLayout {
            family: VictimFamily::Mixed,
            entry_veneer: true,
        },
        Some(predecessor),
        Some(pending),
    )?;
    match result.pair {
        NeighborPair::Artifact(pair) => Ok(ArtifactPlan::checked_pair(
            pair,
            ArtifactMetrics::Neighbor(result.geometry, result.metrics),
        )),
        NeighborPair::Direct(_) => Err(NeighborFailure {
            reason: Refusal::InvalidPlan,
            attempts: result.metrics.attempts,
            search: result.metrics.search,
        }),
    }
}

fn prepare_entry_veneer_placement(
    request: &PlanningRequest<'_>,
    plan: &TrampolinePlan,
    policy: &AllocationPolicy,
    source: AddressRange,
    occupied: &[AddressRange],
    window: AddressRange,
) -> Result<Option<FittingPlacement>, Refusal> {
    let image = request
        .emission
        .prepare_fitting(plan)
        .map_err(|error| Refusal::Backend(error.to_string()))?
        .ok_or(Refusal::InvalidPlan)?;
    match crate::emission::placement::fitting_for_pun(
        policy,
        window,
        occupied,
        source,
        image.size_bound(),
    ) {
        Ok(policy) => Ok(Some(FittingPlacement {
            image: Some(image),
            policy,
            veneer: None,
        })),
        Err(Refusal::AllocationUnavailable) => {
            let veneer = crate::emission::placement::entry_veneer_for_pun(
                policy,
                window,
                occupied,
                source,
                image.size_bound(),
            )?;
            let mut policy = policy.clone();
            policy.preferred_address = Some(veneer.entry_address());
            Ok(Some(FittingPlacement {
                image: Some(image),
                policy,
                veneer: Some(veneer),
            }))
        }
        Err(reason) => Err(reason),
    }
}

fn place_selected_artifact_or_original(
    fitting: &mut Result<Option<FittingPlacement>, Refusal>,
    original: (crate::emission::EmissionContext<'_>, &TrampolinePlan),
    target: Option<u64>,
    policy: &AllocationPolicy,
    source: AddressRange,
    occupied: &[AddressRange],
    other: Option<AddressRange>,
) -> Result<(crate::emission::ArtifactStoredImage, AddressRange), Refusal> {
    let veneer = fitting
        .as_ref()
        .ok()
        .and_then(|fit| fit.as_ref())
        .and_then(|fit| fit.veneer);
    let Some(placement) = veneer else {
        return place_fitting_or_original(
            fitting, original, target, policy, source, occupied, other,
        )
        .map(|(image, allocation)| {
            (
                crate::emission::ArtifactStoredImage::Direct(image),
                allocation,
            )
        });
    };
    if target != Some(placement.entry_address()) {
        return Err(Refusal::InvalidPlan);
    }
    let Ok(Some(fit)) = fitting else {
        return Err(Refusal::InvalidPlan);
    };
    let prepared = fit.image.take().ok_or(Refusal::InvalidPlan)?;
    let image = crate::trampoline::ArtifactTrampolineAllocation::emit(prepared, placement)
        .map_err(|error| Refusal::Backend(error.to_string()))?;
    let allocation = image.placement().mapping();
    // Certificate and actual envelope must name exactly one owned page. Nothing
    // is emitted again if any actual extent/occupancy or field check refuses.
    let actual = AddressRange::new(image.storage_address(), image.bytes().len())?;
    if !allocation.covers(actual)
        || allocation.len() != 4096
        || allocation.len() > policy.max_mapped_bytes as u64
        || !policy.ranges.iter().any(|range| range.covers(allocation))
        || source.overlaps(allocation)
        || occupied.iter().any(|range| range.overlaps(allocation))
        || other.is_some_and(|range| range.overlaps(allocation))
    {
        return Err(Refusal::AllocationUnavailable);
    }
    Ok((
        crate::emission::ArtifactStoredImage::EntryVeneer(image),
        allocation,
    ))
}

struct ArtifactPlacedInstruction {
    displaced: AddressRange,
    image: crate::emission::ArtifactStoredImage,
    allocation: AddressRange,
    candidate: usize,
}
fn compose_selected_pair(
    request: &PlanningRequest<'_>,
    source: AddressRange,
    selected_patch: [u8; 2],
    selected: ArtifactPlacedInstruction,
    victim: ArtifactPlacedInstruction,
    budget: BundleBudget,
    layout: (Option<&short::Relay>, bool),
) -> Result<NeighborPair, Refusal> {
    let (short_relay, artifact) = layout;
    if !artifact {
        return compose_pair(
            request,
            source,
            selected_patch,
            PlacedInstruction {
                displaced: selected.displaced,
                image: selected.image.into_direct()?,
                allocation: selected.allocation,
                candidate: selected.candidate,
            },
            PlacedInstruction {
                displaced: victim.displaced,
                image: victim.image.into_direct()?,
                allocation: victim.allocation,
                candidate: victim.candidate,
            },
            budget,
            short_relay,
        )
        .map(NeighborPair::Direct);
    }
    let relay = victim
        .displaced
        .start()
        .checked_add(5)
        .ok_or(Refusal::InvalidRange)?;
    let selected_entry = selected.image.view().entry_address();
    let mut victim_patch = near_redirect(
        victim.displaced.start(),
        victim.image.view().entry_address(),
    )?;
    victim_patch.extend_from_slice(&near_redirect(relay, selected_entry)?);
    if let Some(short) = short_relay {
        short.check_patch(&victim_patch, selected_entry)?;
    }
    let mut source_members = [(selected, selected_patch.to_vec()), (victim, victim_patch)];
    source_members.sort_unstable_by_key(|member| std::cmp::Reverse(member.0.displaced.start()));
    let mut overlay = request.code.to_vec();
    let mut members = Vec::with_capacity(2);
    for (placed, patch) in source_members {
        let overlaid = request.with_code(&overlay);
        if let Some(short) = short_relay.filter(|r| r.victim() == placed.displaced.start()) {
            short.check_current(&overlaid, source, &patch)?;
        }
        let member = crate::eviction::artifact_instruction_member_core(
            &overlaid,
            source,
            placed.displaced,
            placed.image,
            placed.allocation,
            patch,
        )?;
        for edit in &member.plan.parts().writes {
            let offset = (edit.address - source.start()) as usize;
            overlay[offset..offset + edit.bytes.len()].copy_from_slice(&edit.bytes);
        }
        members.push(member);
    }
    crate::bundle::compose_artifact_pair(
        vec![ExpectedBytes {
            address: source.start(),
            bytes: request.code.to_vec(),
        }],
        members,
        budget,
    )
    .map(NeighborPair::Artifact)
}

struct NeighborLayout {
    family: VictimFamily,
    entry_veneer: bool,
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
#[path = "neighbor_entry_veneer_tests.rs"]
mod entry_veneer_tests;
