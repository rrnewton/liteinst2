//! Artifact-only T3 with two overlapping E9s inside one original instruction.
//!
//! The six source bytes are `e9 e9 d0 d1 d2 d3`. Entry at V executes the
//! callback-free victim image; entry at V+1 executes the selected image. The
//! selected original head receives EB to V+1. Joint target arithmetic happens
//! before either image is encoded. No successor bytes are consumed or changed.
use super::*;

/// Force the overlapping-relay T3 family for an offline artifact.
///
/// The selected instruction is 2..=4 bytes and the disjoint victim is one
/// unchanged original instruction of 6..=15 bytes in the same function. Both
/// original instructions keep the existing semantic and exhaustive-entry
/// qualifications. V+1 is a generated relay, never an original entry.
///
/// Each allocation policy must permit exactly one candidate, one mapping and
/// one 4096-byte page. A finite joint certificate selects both image entries;
/// each prepared image is then encoded once and its actual full allocation is
/// checked. Failed encoding/composition is not retried at another target.
/// Victims remain descending and share the caller's victim/pair bounds.
///
/// This is an explicit artifact family, not a live publication API. It does not
/// change existing T3 modes or qualify asynchronous signal/unwind transparency.
pub fn plan_neighbor_overlapping_with_emission(
    request: &ArtifactRequest<'_>,
    victim_allocation: &AllocationPolicy,
    search: NeighborSearch,
    budget: BundleBudget,
) -> Result<ArtifactPlan, NeighborFailure> {
    plan_overlapping(
        &PlanningRequest::artifact(request).with_fitting_placement(),
        victim_allocation,
        search,
        budget,
        None,
        None,
    )
}

/// The caller supplies the predecessor's authenticated planning overlay, as in
/// the existing pending-aware family. Every proposed step is appended to a
/// clone before accepting; pending original instructions remain unclaimed.
pub(crate) fn plan_neighbor_overlapping_pending_core(
    request: &PlanningRequest<'_>,
    predecessor: &Composition,
    pending: &[AddressRange],
    victim_allocation: &AllocationPolicy,
    search: NeighborSearch,
    budget: BundleBudget,
) -> Result<ArtifactPlan, NeighborFailure> {
    plan_overlapping(
        request,
        victim_allocation,
        search,
        budget,
        Some(predecessor),
        Some(pending),
    )
}

fn redirect(selected: u64, victim: u64) -> Result<(u64, i8, [u8; 2]), Refusal> {
    let relay = victim.checked_add(1).ok_or(Refusal::InvalidRange)?;
    let next = selected.checked_add(2).ok_or(Refusal::InvalidRange)?;
    let rel8 =
        i8::try_from(i128::from(relay) - i128::from(next)).map_err(|_| Refusal::NoPatchWindow)?;
    Ok((relay, rel8, [0xeb, rel8 as u8]))
}

fn plan_overlapping(
    request: &PlanningRequest<'_>,
    victim_allocation: &AllocationPolicy,
    search: NeighborSearch,
    budget: BundleBudget,
    inherited: Option<&Composition>,
    pending: Option<&[AddressRange]>,
) -> Result<ArtifactPlan, NeighborFailure> {
    let mut attempts = Vec::new();
    let mut evidence = SearchEvidence::default();
    let result = (|| {
        let (source, scan) = quiescent::validated_source_core(request)
            .inspect_err(|reason| evidence.qualification(SearchScope::default(), reason))?;
        let selected_scope = SearchScope {
            physical_pc: Some(request.logical_pc),
            ..SearchScope::default()
        };
        let selected = qualify_selected(request, &scan).inspect_err(|reason| {
            if request.search.max_sites != 0 {
                evidence.qualification(selected_scope, reason);
            }
        })?;
        if !request.emission.fitting_placement() {
            return Err(Refusal::InvalidPlan);
        }
        for policy in [request.allocation, victim_allocation] {
            crate::emission::placement::validate(policy)?;
        }
        if search.max_victims == 0 || search.max_pairs == 0 {
            return Err(Refusal::AllocationUnavailable);
        }
        if budget.max_steps < 2
            || budget.max_mappings < 2
            || budget.max_virtual_bytes < 8192
            || budget.max_backing_bytes < 8192
        {
            evidence.refusal(
                selected_scope,
                RefusalClass::ResourceCapacity,
                &Refusal::AllocationUnavailable,
            );
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
                    (6..=15).contains(&item.len())
                        && AddressRange::new(item.address(), item.len()).is_ok_and(|range| {
                            !range.overlaps(selected_range) && request.function.covers(range)
                        })
                        && redirect(selected.address(), item.address()).is_ok()
                })
                .collect()
        };
        let victims = evidence.begin(
            SearchDomain::Victims,
            selected_scope,
            search.max_victims,
            Some(candidates.len()),
        );
        let pairs = evidence.begin(
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
        let mut joint_error = None;
        for (index, victim) in candidates.into_iter().take(search.max_victims).enumerate() {
            evidence.visit(victims);
            let victim_scope = SearchScope {
                physical_pc: Some(victim.address()),
                ..SearchScope::default()
            };
            let qualification = (|| {
                let range = qualify_victim_core(request, &scan, victim, 6)?;
                if range.overlaps(selected_range) {
                    return Err(Refusal::NoPatchWindow);
                }
                let (relay, rel8, patch) = redirect(selected.address(), victim.address())?;
                Ok((range, relay, rel8, patch))
            })();
            let (victim_range, relay, rel8, selected_patch) = match qualification {
                Ok(value) => value,
                Err(reason) => {
                    evidence.qualification(victim_scope, &reason);
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
            if pairs_examined == search.max_pairs {
                evidence.known_limit_hit(pairs, 1);
                return Err(joint_error.unwrap_or(Refusal::AllocationUnavailable));
            }
            pairs_examined += 1;
            evidence.visit(pairs);
            // The declared candidate schedule has one joint certificate. Its
            // finite size does not claim that an encoding refusal proves that
            // every other possible address would fail.
            let victim_images = evidence.begin(
                SearchDomain::VictimImages,
                victim_scope,
                victim_allocation.max_candidates,
                Some(1),
            );
            let selected_images = evidence.begin(
                SearchDomain::SelectedImages,
                selected_scope,
                request.allocation.max_candidates,
                Some(1),
            );
            evidence.visit(victim_images);
            evidence.visit(selected_images);
            let mut attempt = NeighborAttempt {
                victim: victim.address(),
                stage: NeighborAttemptStage::VictimPlacement,
                victim_target: None,
                selected_target: None,
                refusal: None,
            };
            let pair = (|| {
                let victim_plan = TrampolinePlan::from_instruction(&scan, victim.address())
                    .map_err(|error| Refusal::Backend(error.to_string()))?;
                let victim_prepared = request
                    .emission
                    .prepare_fitting(&victim_plan)
                    .map_err(|error| Refusal::Backend(error.to_string()))?
                    .ok_or(Refusal::InvalidPlan)?;
                attempt.stage = NeighborAttemptStage::SelectedPlacement;
                let selected_prepared = request
                    .emission
                    .prepare_fitting(&selected_plan)
                    .map_err(|error| Refusal::Backend(error.to_string()))?
                    .ok_or(Refusal::InvalidPlan)?;
                let (selected_target, victim_target) =
                    crate::emission::placement::joint_overlapping_targets(
                        request.allocation,
                        victim_allocation,
                        &occupied,
                        source,
                        victim.address(),
                        selected_prepared.size_bound(),
                        victim_prepared.size_bound(),
                    )?;
                attempt.selected_target = Some(selected_target);
                attempt.victim_target = Some(victim_target);
                let mut fitted_victim = Ok(Some(FittingPlacement {
                    image: Some(victim_prepared),
                    policy: victim_allocation.clone(),
                    veneer: None,
                }));
                attempt.stage = NeighborAttemptStage::VictimPlacement;
                let (victim_image, victim_mapping) = place_fitting_or_original(
                    &mut fitted_victim,
                    (request.emission, &victim_plan),
                    Some(victim_target),
                    victim_allocation,
                    source,
                    &occupied,
                    None,
                )?;
                let mut fitted_selected = Ok(Some(FittingPlacement {
                    image: Some(selected_prepared),
                    policy: request.allocation.clone(),
                    veneer: None,
                }));
                attempt.stage = NeighborAttemptStage::SelectedPlacement;
                let (selected_image, selected_mapping) = place_fitting_or_original(
                    &mut fitted_selected,
                    (request.emission, &selected_plan),
                    Some(selected_target),
                    request.allocation,
                    source,
                    &occupied,
                    Some(victim_mapping),
                )?;
                attempt.stage = NeighborAttemptStage::Composition;
                let pair = compose(
                    request,
                    source,
                    selected_patch,
                    ArtifactPlacedInstruction {
                        displaced: selected_range,
                        image: crate::emission::ArtifactStoredImage::Direct(selected_image),
                        allocation: selected_mapping,
                        candidate: 0,
                    },
                    ArtifactPlacedInstruction {
                        displaced: victim_range,
                        image: crate::emission::ArtifactStoredImage::Direct(victim_image),
                        allocation: victim_mapping,
                        candidate: 0,
                    },
                    budget,
                )?;
                if let Some(predecessor) = inherited {
                    let mut current = predecessor.clone();
                    for step in pair.plan.steps() {
                        current.append(step)?;
                    }
                    if let Some(pending) = pending {
                        current.require_unclaimed_ranges(pending)?;
                    }
                }
                Ok((pair, selected_target, victim_target))
            })();
            match pair {
                Ok((pair, selected_target, victim_target)) => {
                    attempts.push(attempt);
                    for run in [victims, pairs, victim_images, selected_images] {
                        evidence.accept(run);
                    }
                    evidence.accepted = true;
                    return Ok(ArtifactPlan::checked_pair(
                        pair,
                        ArtifactMetrics::Neighbor(
                            NeighborGeometry {
                                selected: selected.address(),
                                selected_len: selected.len(),
                                victim: victim.address(),
                                victim_len: victim.len(),
                                relay,
                                rel8,
                                selected_target,
                                victim_target,
                            },
                            NeighborMetrics {
                                search: evidence.clone(),
                                victims_examined: index + 1,
                                pairs_examined,
                                selected_fallthrough_redirects: 3,
                                victim_fallthrough_redirects: 2,
                                attempts: attempts.clone(),
                            },
                        ),
                    ));
                }
                Err(reason) => {
                    attempt.refusal = Some(reason.clone());
                    attempts.push(attempt);
                    joint_error = Some(reason);
                    evidence.finish(victim_images);
                    evidence.finish(selected_images);
                }
            }
        }
        evidence.finish(victims);
        evidence.finish(pairs);
        Err(joint_error.unwrap_or(last_error))
    })();
    result.map_err(|reason| NeighborFailure {
        search: evidence,
        reason,
        attempts,
    })
}

fn compose(
    request: &PlanningRequest<'_>,
    source: AddressRange,
    selected_patch: [u8; 2],
    selected: ArtifactPlacedInstruction,
    victim: ArtifactPlacedInstruction,
    budget: BundleBudget,
) -> Result<crate::bundle::CheckedArtifactPair, Refusal> {
    let relay = victim
        .displaced
        .start()
        .checked_add(1)
        .ok_or(Refusal::InvalidRange)?;
    let mut victim_patch = near_redirect(
        victim.displaced.start(),
        victim.image.view().entry_address(),
    )?;
    let selected_redirect = near_redirect(relay, selected.image.view().entry_address())?;
    // Independent post-encode check of the shared four bytes. The first E9's
    // low displacement byte must itself be the second E9 opcode.
    if victim_patch[1..] != selected_redirect[..4] || victim.displaced.len() < 6 {
        return Err(Refusal::InvalidPlan);
    }
    victim_patch.push(selected_redirect[4]);
    let mut source_members = [(selected, selected_patch.to_vec()), (victim, victim_patch)];
    source_members.sort_unstable_by_key(|member| std::cmp::Reverse(member.0.displaced.start()));
    let mut overlay = request.code.to_vec();
    let mut members = Vec::with_capacity(2);
    for (placed, patch) in source_members {
        let member = crate::eviction::artifact_instruction_member_core(
            &request.with_code(&overlay),
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
}

#[cfg(test)]
#[path = "neighbor_overlap/tests.rs"]
mod tests;
