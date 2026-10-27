//! Forced T3 across two separately authenticated function owners.
//! No address-based owner inference, live publication or automatic fallback.
use super::*;
use crate::composition::Composition;
use crate::emission::PlanningSite;

/// Plans T3 using an exact victim in a separately owned function.
///
/// Both sites supply immutable originals, actual containing blocks, complete
/// function entry/resume facts and the same identity. The victim's semantics
/// must be Observe and its search policy must equal the selected policy; its
/// allocation controls only the callback-free victim image. The selected
/// request supplies the single common target/hook/occupied-address context.
/// `search.forced_victim` must name the victim's exact original logical PC.
/// Missing or different forced heads refuse; no other victim is substituted.
///
/// Both full originals are authenticated against the same predecessor before
/// decoding. Displaced operations must still be original after its overlay.
/// The complete returned transaction is checked on a clone of the predecessor
/// for inherited locks, physical sites and allocations. The caller must still
/// append every step transactionally and enforce its whole-campaign budgets.
/// No source writes, mapping, runtime admission or native result is provided.
pub fn plan_neighbor_with_emission_from(
    request: &ArtifactRequest<'_>,
    predecessor: &Composition,
    victim: &PlanningSite<'_>,
    search: NeighborSearch,
    budget: BundleBudget,
) -> Result<ArtifactPlan, NeighborFailure> {
    let mut attempts = Vec::new();
    let mut evidence = SearchEvidence::default();
    let result = (|| {
        let selected_scope = SearchScope {
            physical_pc: Some(request.site.logical_pc),
            ..SearchScope::default()
        };
        let victim_scope = SearchScope {
            physical_pc: Some(victim.logical_pc),
            ..SearchScope::default()
        };
        let prepare = (|| {
            if victim.identity != request.site.identity {
                return Err(Refusal::StaleGeneration);
            }
            if search.forced_victim != Some(victim.logical_pc)
                || victim.semantics != HookSemantics::Observe
                || victim.search.tactics != request.site.search.tactics
                || victim.search.max_upstream_bytes != request.site.search.max_upstream_bytes
                || victim.search.max_displaced_bytes != request.site.search.max_displaced_bytes
                || victim.search.max_sites != request.site.search.max_sites
                || victim.entries.scope != victim.function
                || request.site.entries.scope != request.site.function
            {
                return Err(Refusal::InvalidRange);
            }
            let source = AddressRange::new(request.site.base_address, request.site.code.len())?;
            let other = AddressRange::new(victim.base_address, victim.code.len())?;
            if source.overlaps(other) || request.site.function.overlaps(victim.function) {
                return Err(Refusal::OwnershipConflict);
            }
            let selected_current = predecessor.planning_overlay(
                request.site.identity,
                request.site.base_address,
                request.site.code,
            )?;
            let victim_current =
                predecessor.planning_overlay(victim.identity, victim.base_address, victim.code)?;
            Ok((source, other, selected_current, victim_current))
        })();
        let (source, other, selected_current, victim_current) = prepare.inspect_err(|reason| {
            evidence.qualification(SearchScope::default(), reason);
        })?;
        let selected_original = PlanningRequest::artifact(request);
        let selected_request = selected_original.with_code(&selected_current);
        let victim_artifact = ArtifactRequest {
            site: *victim,
            emission: request.emission,
        };
        let victim_original = PlanningRequest::artifact(&victim_artifact);
        let victim_request = victim_original.with_code(&victim_current);
        let (_, scan) = quiescent::validated_source_core(&selected_request)
            .inspect_err(|reason| evidence.qualification(selected_scope, reason))?;
        let (_, victim_scan) = quiescent::validated_source_core(&victim_request)
            .inspect_err(|reason| evidence.qualification(victim_scope, reason))?;
        let selected = qualify_selected(&selected_request, &scan).inspect_err(|reason| {
            if request.site.search.max_sites != 0 {
                evidence.qualification(selected_scope, reason);
            }
        })?;
        let selected_range = AddressRange::new(selected.address(), selected.len())?;
        let victim_allocation = victim.allocation;
        if search.max_victims == 0
            || search.max_pairs == 0
            || budget.max_steps < 2
            || budget.max_mappings < 2
            || budget.max_virtual_bytes < 8192
            || budget.max_backing_bytes < 8192
            || [request.site.allocation, victim_allocation]
                .iter()
                .any(|p| p.max_candidates == 0 || p.max_mappings == 0 || p.max_mapped_bytes < 4096)
        {
            let class = if budget.max_steps < 2
                || budget.max_mappings < 2
                || budget.max_virtual_bytes < 8192
                || budget.max_backing_bytes < 8192
                || [request.site.allocation, victim_allocation]
                    .iter()
                    .any(|p| p.max_mappings == 0 || p.max_mapped_bytes < 4096)
            {
                RefusalClass::ResourceCapacity
            } else {
                RefusalClass::Unclassified
            };
            evidence.refusal(selected_scope, class, &Refusal::AllocationUnavailable);
            return Err(Refusal::AllocationUnavailable);
        }
        let victims = evidence.begin(
            SearchDomain::Victims,
            selected_scope,
            search.max_victims,
            Some(1),
        );
        let pairs = evidence.begin(
            SearchDomain::JointPairs,
            selected_scope,
            search.max_pairs,
            None,
        );
        evidence.visit(victims);
        let qualification = (|| {
            let instruction = victim_scan
                .instructions()
                .iter()
                .find(|i| i.address() == victim.logical_pc)
                .ok_or(Refusal::NotInstructionHead)?;
            let range = qualify_victim_core(&victim_request, &victim_scan, instruction, 10)?;
            if !victim.block.covers(range) || range.overlaps(selected_range) {
                return Err(Refusal::NoPatchWindow);
            }
            // Each unchanged qualifier checks its own scan. Also check direct
            // targets from the other authenticated original function.
            reject_interior_targets(&scan, range)?;
            reject_interior_targets(&victim_scan, selected_range)?;
            let (relay, rel8, patch) = short_redirect(selected.address(), instruction.address())?;
            Ok((instruction, range, relay, rel8, patch))
        })();
        let (victim_instruction, victim_range, relay, rel8, selected_patch) = qualification
            .inspect_err(|reason| {
                evidence.qualification(victim_scope, reason);
                attempts.push(NeighborAttempt {
                    victim: victim.logical_pc,
                    stage: NeighborAttemptStage::Qualification,
                    victim_target: None,
                    selected_target: None,
                    refusal: Some(reason.clone()),
                });
            })?;
        let selected_plan = selected_request
            .emission
            .short(
                &scan,
                selected.address(),
                request.site.semantics == HookSemantics::ReplaceFirst,
            )
            .map_err(|e| Refusal::Backend(e.to_string()))?;
        let victim_plan =
            TrampolinePlan::from_instruction(&victim_scan, victim_instruction.address())
                .map_err(|e| Refusal::Backend(e.to_string()))?;
        let mut occupied = selected_request.emission.occupied()?;
        // The common caller still owes complete PT_LOAD ownership. Neither
        // separately supplied source may be overlapped even if omitted there.
        occupied.extend([source, other]);
        let images = evidence.begin(
            SearchDomain::VictimImages,
            victim_scope,
            victim_allocation.max_candidates,
            None,
        );
        let mut pairs_examined = 0;
        let mut last_error = Refusal::NoPatchWindow;
        let mut joint_error = None;
        for victim_candidate in 0..victim_allocation.max_candidates {
            evidence.visit(images);
            let victim_target = quiescent::candidate_target(
                victim.logical_pc,
                [false; 4],
                victim_allocation.preferred_address,
                victim_candidate,
            );
            let placed = place_image(
                selected_request.emission,
                &victim_plan,
                victim_target,
                victim_allocation,
                other,
                &occupied,
                None,
            );
            let (victim_image, victim_mapping) = match placed {
                Ok(v) => v,
                Err(reason) => {
                    attempts.push(NeighborAttempt {
                        victim: victim.logical_pc,
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
            let selected_images = evidence.begin(
                SearchDomain::SelectedImages,
                SearchScope {
                    victim_target: Some(victim_target),
                    ..selected_scope
                },
                request.site.allocation.max_candidates,
                None,
            );
            for selected_candidate in 0..request.site.allocation.max_candidates {
                if pairs_examined == search.max_pairs {
                    evidence.known_limit_hit(pairs, 1);
                    return Err(joint_error.unwrap_or(Refusal::AllocationUnavailable));
                }
                pairs_examined += 1;
                evidence.visit(pairs);
                evidence.visit(selected_images);
                let selected_target = quiescent::candidate_target(
                    relay,
                    [false; 4],
                    request.site.allocation.preferred_address,
                    selected_candidate,
                );
                let placed = place_image(
                    selected_request.emission,
                    &selected_plan,
                    selected_target,
                    request.site.allocation,
                    source,
                    &occupied,
                    Some(victim_mapping),
                );
                let (selected_image, selected_mapping) = match placed {
                    Ok(v) => v,
                    Err(reason) => {
                        attempts.push(NeighborAttempt {
                            victim: victim.logical_pc,
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
                let composed = compose_sources(
                    PlacedSource {
                        request: &selected_request,
                        source,
                        instruction: PlacedInstruction {
                            displaced: selected_range,
                            image: selected_image,
                            allocation: selected_mapping,
                            candidate: selected_candidate,
                        },
                    },
                    PlacedSource {
                        request: &victim_request,
                        source: other,
                        instruction: PlacedInstruction {
                            displaced: victim_range,
                            image: victim_image.clone(),
                            allocation: victim_mapping,
                            candidate: victim_candidate,
                        },
                    },
                    selected_patch,
                    budget,
                    predecessor,
                );
                attempts.push(NeighborAttempt {
                    victim: victim.logical_pc,
                    stage: NeighborAttemptStage::Composition,
                    victim_target: Some(victim_target),
                    selected_target: Some(selected_target),
                    refusal: composed.as_ref().err().cloned(),
                });
                match composed {
                    Ok(bundle) => {
                        for id in [victims, pairs, images, selected_images] {
                            evidence.accept(id);
                        }
                        return Ok((
                            bundle,
                            NeighborGeometry {
                                selected: selected.address(),
                                selected_len: selected.len(),
                                victim: victim.logical_pc,
                                victim_len: victim_instruction.len(),
                                relay,
                                rel8,
                                selected_target,
                                victim_target,
                            },
                            pairs_examined,
                        ));
                    }
                    Err(reason) => joint_error = Some(reason),
                }
            }
            evidence.finish_candidates(
                selected_images,
                quiescent::candidate_target_proof(
                    relay,
                    [false; 4],
                    request.site.allocation.preferred_address,
                    request.site.allocation.max_candidates,
                ),
            );
        }
        evidence.finish_candidates(
            images,
            quiescent::candidate_target_proof(
                victim.logical_pc,
                [false; 4],
                victim_allocation.preferred_address,
                victim_allocation.max_candidates,
            ),
        );
        evidence.finish(victims);
        evidence.finish(pairs);
        Err(joint_error.unwrap_or(last_error))
    })();
    match result {
        Ok((bundle, geometry, pairs_examined)) => {
            evidence.accepted = true;
            Ok(ArtifactPlan::bundle(
                &bundle,
                ArtifactMetrics::Neighbor(
                    geometry,
                    NeighborMetrics {
                        search: evidence,
                        victims_examined: 1,
                        pairs_examined,
                        selected_fallthrough_redirects: 3,
                        victim_fallthrough_redirects: 2,
                        attempts,
                    },
                ),
            ))
        }
        Err(reason) => Err(NeighborFailure {
            search: evidence,
            reason,
            attempts,
        }),
    }
}

fn reject_interior_targets(scan: &ScanResult, range: AddressRange) -> Result<(), Refusal> {
    if scan.instructions().iter().any(|item| {
        matches!(
            item.instruction().op0_kind(),
            iced_x86::OpKind::NearBranch16
                | iced_x86::OpKind::NearBranch32
                | iced_x86::OpKind::NearBranch64
        ) && range.contains(item.instruction().near_branch_target())
            && item.instruction().near_branch_target() != range.start()
    }) {
        return Err(Refusal::NotInstructionHead);
    }
    Ok(())
}

struct PlacedSource<'a, 'b> {
    request: &'a PlanningRequest<'b>,
    source: AddressRange,
    instruction: PlacedInstruction,
}

fn compose_sources(
    selected_owner: PlacedSource<'_, '_>,
    victim_owner: PlacedSource<'_, '_>,
    selected_patch: [u8; 2],
    budget: BundleBudget,
    predecessor: &Composition,
) -> Result<PlannedBundle, Refusal> {
    let PlacedSource {
        request: selected_request,
        source,
        instruction: selected,
    } = selected_owner;
    let PlacedSource {
        request: victim_request,
        source: other,
        instruction: victim,
    } = victim_owner;
    let relay = victim
        .displaced
        .start()
        .checked_add(5)
        .ok_or(Refusal::InvalidRange)?;
    let mut victim_patch = near_redirect(victim.displaced.start(), victim.image.address())?;
    victim_patch.extend_from_slice(&near_redirect(relay, selected.image.address())?);
    let selected_member = instruction_member_core(
        selected_request,
        source,
        selected.displaced,
        selected.image,
        selected.allocation,
        selected_patch.to_vec(),
        selected.candidate,
    )?;
    let victim_member = instruction_member_core(
        victim_request,
        other,
        victim.displaced,
        victim.image,
        victim.allocation,
        victim_patch,
        victim.candidate,
    )?;
    let mut members = vec![selected_member, victim_member];
    members.sort_unstable_by_key(|m| std::cmp::Reverse(m.plan().parts().physical_pc));
    let bundle = PlannedBundle::compose(
        vec![
            ExpectedBytes {
                address: source.start(),
                bytes: selected_request.code.to_vec(),
            },
            ExpectedBytes {
                address: other.start(),
                bytes: victim_request.code.to_vec(),
            },
        ],
        members,
        budget,
    )?;
    let mut checked = predecessor.clone();
    for step in bundle.plan().steps() {
        checked.append(step)?;
    }
    Ok(bundle)
}
