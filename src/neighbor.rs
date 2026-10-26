//! Forced neighboring-instruction eviction (T3).
//!
//! Original instruction identity is never recovered from a rewrite overlay.
//! The selected head receives EB to a private source relay in one whole victim;
//! both immutable images and every source dependency are published as a bundle.

use crate::bundle::{BundleBudget, PlannedBundle};
use crate::contracts::*;
use crate::emission::{ArtifactMetrics, ArtifactPlan, ArtifactRequest, PlanningRequest};
use crate::eviction::{
    image_allocation, instruction_member_core, near_redirect, qualify_victim_core,
};
use crate::planner::HookSemantics;
use crate::quiescent::{self, AllocationPolicy, InstallRequest};
use crate::scanner::{ScanResult, ScannedInstruction};
use crate::search::{RefusalClass, SearchDomain, SearchEvidence, SearchScope};
use crate::trampoline::{TrampolineImage, TrampolinePlan};

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
    /// Whole original victim instruction length, 10..=15.
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
            let victim_scope = SearchScope {
                physical_pc: Some(victim.address()),
                ..SearchScope::default()
            };
            let qualification = (|| {
                let victim_range = qualify_victim_core(request, &scan, victim, 10)?;
                if victim_range.overlaps(selected_range) {
                    return Err(Refusal::NoPatchWindow);
                }
                let (relay, rel8, patch) = short_redirect(selected.address(), victim.address())?;
                Ok((victim_range, relay, rel8, patch))
            })();
            let (victim_range, relay, rel8, selected_patch) = match qualification {
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
            for victim_candidate in 0..victim_allocation.max_candidates {
                search_evidence.visit(victim_images);
                let victim_target = quiescent::candidate_target(
                    victim.address(),
                    [false; 4],
                    victim_allocation.preferred_address,
                    victim_candidate,
                );
                let placed = place_image(
                    request.emission,
                    &victim_plan,
                    victim_target,
                    victim_allocation,
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
                for selected_candidate in 0..request.allocation.max_candidates {
                    if pairs_examined == search.max_pairs {
                        // This entered loop has one current, unexamined pair.
                        search_evidence.known_limit_hit(pair_search, 1);
                        return Err(joint_error.unwrap_or(Refusal::AllocationUnavailable));
                    }
                    pairs_examined += 1;
                    search_evidence.visit(pair_search);
                    search_evidence.visit(selected_images);
                    // This E9 starts at V+5: candidate_target adds five to that
                    // actual origin, not to the selected original instruction.
                    let selected_target = quiescent::candidate_target(
                        relay,
                        [false; 4],
                        request.allocation.preferred_address,
                        selected_candidate,
                    );
                    let placed = place_image(
                        request.emission,
                        &selected_plan,
                        selected_target,
                        request.allocation,
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
                    let selected_target = selected_image.address();
                    let composed = compose_pair(
                        request,
                        source,
                        selected_patch,
                        PlacedInstruction {
                            displaced: selected_range,
                            image: selected_image,
                            allocation: selected_mapping,
                            candidate: selected_candidate,
                        },
                        PlacedInstruction {
                            displaced: victim_range,
                            image: victim_image.clone(),
                            allocation: victim_mapping,
                            candidate: victim_candidate,
                        },
                        budget,
                    );
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
                            return Ok(PlannedNeighbor {
                                bundle,
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
                                    selected_fallthrough_redirects: 3,
                                    victim_fallthrough_redirects: 2,
                                    attempts: attempts.clone(),
                                },
                            });
                        }
                        Err(reason) => joint_error = Some(reason),
                    }
                }
                search_evidence.finish_candidates(
                    selected_images,
                    quiescent::candidate_target_proof(
                        relay,
                        [false; 4],
                        request.allocation.preferred_address,
                        request.allocation.max_candidates,
                    ),
                );
            }
            search_evidence.finish_candidates(
                victim_images,
                quiescent::candidate_target_proof(
                    victim.address(),
                    [false; 4],
                    victim_allocation.preferred_address,
                    victim_allocation.max_candidates,
                ),
            );
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
    Ok(selected)
}

fn short_redirect(selected: u64, victim: u64) -> Result<(u64, i8, [u8; 2]), Refusal> {
    let relay = victim.checked_add(5).ok_or(Refusal::InvalidRange)?;
    let next = selected.checked_add(2).ok_or(Refusal::InvalidRange)?;
    let rel8 =
        i8::try_from(i128::from(relay) - i128::from(next)).map_err(|_| Refusal::NoPatchWindow)?;
    Ok((relay, rel8, [0xeb, rel8 as u8]))
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
) -> Result<PlannedBundle, Refusal> {
    let relay = victim
        .displaced
        .start()
        .checked_add(5)
        .ok_or(Refusal::InvalidRange)?;
    let mut victim_patch = near_redirect(victim.displaced.start(), victim.image.address())?;
    victim_patch.extend_from_slice(&near_redirect(relay, selected.image.address())?);
    let mut source_members = [(selected, selected_patch.to_vec()), (victim, victim_patch)];
    source_members.sort_unstable_by_key(|member| std::cmp::Reverse(member.0.displaced.start()));
    let mut overlay = request.code.to_vec();
    let mut members = Vec::with_capacity(2);
    for (placed, patch) in source_members {
        let overlaid = request.with_code(&overlay);
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
