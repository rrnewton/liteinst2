//! Pure compiler bridge. It consumes already-produced opaque ArtifactPlan values.
use crate::contracts::{
    ApplicationProfile, CodeIdentity, EntryObligation, ExpectedBytes, PlanKind, SourceIdentity,
};
use crate::emission::{ArtifactMetrics, ArtifactPlan, ArtifactRequirement};
use liteinst_artifact::{
    ContentId,
    startup::{self as c, Blob, Catalog, Image, Input, Obligation, Span, Step},
};

/// Build the complete startup catalog from the writer's accepted opaque plans.
///
/// `input.steps` and `input.images` must be empty: neither caller-supplied routes
/// nor image subsets are accepted. One plan per complete metadata selection is
/// required, including every auxiliary step/image. This pure bridge replans and
/// emits nothing. Its result still requires independent W01 and semantic/package
/// qualification; it is not execution permission.
pub fn catalog_from_plans(mut input: Input, plans: &[(u64, ArtifactPlan)]) -> c::Result<Catalog> {
    if !input.steps.is_empty() || !input.images.is_empty() || plans.len() > 4096 {
        return Err(c::Error::Shape);
    }
    let original = c::parse(&input.original)?;
    let identity = CodeIdentity {
        source: SourceIdentity(ContentId::of(&input.original).0),
        mapping: input.policy.state.domain,
        generation: 1,
    };
    let snapshots = original
        .segments(liteinst_artifact::elf64::SegmentType::Load)
        .filter(|p| p.flags.0 == 5 && p.file_size != 0)
        .map(|p| ExpectedBytes {
            address: p.vaddr.0,
            bytes: input.original[p.offset.0 as usize..(p.offset.0 + p.file_size) as usize]
                .to_vec(),
        })
        .collect();
    let mut composition =
        crate::composition::Composition::new(identity, snapshots).map_err(|_| c::Error::Source)?;
    let mut owners = std::collections::BTreeSet::new();
    for (id, plan) in plans {
        if !owners.insert(*id) {
            return Err(c::Error::Selection);
        }
        let images = plan.images().collect::<Vec<_>>();
        if !(1..=2).contains(&images.len()) || images.len() != plan.source_steps().len() {
            return Err(c::Error::Image);
        }
        let neighbor = match plan.metrics() {
            ArtifactMetrics::Neighbor(g, _)
            | ArtifactMetrics::Engine(_, crate::engine::SelectedMetrics::Neighbor(g, _), _) => {
                Some(c::Neighbor {
                    selected: g.selected,
                    selected_len: g.selected_len as u64,
                    victim: g.victim,
                    victim_len: g.victim_len as u64,
                    relay: g.relay,
                    rel8: g.rel8,
                    selected_target: g.selected_target,
                    victim_target: g.victim_target,
                })
            }
            _ => None,
        };
        for step in plan.source_steps() {
            let p = step.parts();
            if p.profile != ApplicationProfile::InstallOnce
                || p.allocations.len() != 1
                || p.generated.len() != 1
                || !p.requirements.quiescent
                || !p.requirements.sync_core
            {
                return Err(c::Error::Shape);
            }
            composition.append(step).map_err(|_| c::Error::Source)?;
            let g = &p.generated[0];
            let owned = images
                .iter()
                .filter(|i| i.address() == g.address)
                .collect::<Vec<_>>();
            if owned.len() != 1
                || owned[0].bytes() != g.bytes
                || owned[0].program_counter_mappings() != g.program_counters
            {
                return Err(c::Error::Image);
            }
            let mut writes = p
                .writes
                .iter()
                .map(|w| Blob {
                    address: w.address,
                    bytes: w.bytes.clone(),
                })
                .collect::<Vec<_>>();
            let kind = match &p.kind {
                PlanKind::GeneralizedPun(p) => {
                    writes.push(Blob {
                        address: p.store.address,
                        bytes: p.store.bytes.clone(),
                    });
                    c::Kind::GeneralizedPun(c::Pun {
                        instruction_len: u64::from(p.instruction_len),
                        prefixes: 0,
                        consumed: span(p.consumed),
                        target_window: span(p.target_window),
                        store: Span {
                            start: p.store.address,
                            len: p.store.bytes.len() as u64,
                        },
                    })
                }
                PlanKind::PrefixedPun(p) => {
                    writes.push(Blob {
                        address: p.store.address,
                        bytes: p.store.bytes.clone(),
                    });
                    c::Kind::PrefixedPun(c::Pun {
                        instruction_len: u64::from(p.instruction_len),
                        prefixes: u64::from(p.prefix_count),
                        consumed: span(p.consumed),
                        target_window: span(p.target_window),
                        store: Span {
                            start: p.store.address,
                            len: p.store.bytes.len() as u64,
                        },
                    })
                }
                PlanKind::Relocation => c::Kind::Relocation,
            };
            let obligations = p
                .obligations
                .iter()
                .map(|o| match o {
                    EntryObligation::Preserved(original) => Ok(Obligation {
                        original: *original,
                        generated: None,
                    }),
                    EntryObligation::Routed(r) => Ok(Obligation {
                        original: r.original,
                        generated: Some(r.generated),
                    }),
                    EntryObligation::Unresolved { .. } => Err(c::Error::Route),
                })
                .collect::<c::Result<Vec<_>>>()?;
            if p.requirements.sigill_router != obligations.iter().any(|o| o.generated.is_some()) {
                return Err(c::Error::Route);
            }
            input.steps.push(Step {
                selected_id: *id,
                logical: p.logical_pc,
                physical: p.physical_pc,
                displaced: span(p.displaced),
                kind,
                neighbor,
                reads: p
                    .reads
                    .iter()
                    .map(|r| Blob {
                        address: r.address,
                        bytes: r.bytes.clone(),
                    })
                    .collect(),
                writes,
                dependencies: p
                    .dependencies
                    .iter()
                    .map(|d| Span {
                        start: d.start(),
                        len: d.len(),
                    })
                    .collect(),
                allocation: Span {
                    start: p.allocations[0].range.start(),
                    len: p.allocations[0].range.len(),
                },
                image: g.address,
                obligations,
            });
        }
        for i in images {
            check_hook(&i, &input.policy)?;
            let requirements = i
                .metadata()
                .requirements()
                .iter()
                .map(|r| match r {
                    ArtifactRequirement::ArtifactIdentityAndAddressBinding => (1, 0),
                    ArtifactRequirement::TargetCpuAndStateAtEntry => (2, 0),
                    ArtifactRequirement::OriginalDynamicRelocationOwnership => (3, 0),
                    ArtifactRequirement::OriginalImmediatePointerProvenance => (4, 0),
                    ArtifactRequirement::HookAbiAndReadiness(id) => (5, *id),
                    ArtifactRequirement::EntryRouterBootstrap => (6, 0),
                    ArtifactRequirement::GeneratedUnwindInformation => (7, 0),
                    ArtifactRequirement::OriginalCodeAsDataContract => (8, 0),
                })
                .collect();
            input.images.push(Image {
                body: Blob {
                    address: i.address(),
                    bytes: i.bytes().to_vec(),
                },
                entries: i.entry_routes().to_vec(),
                requirements,
            });
        }
    }
    Catalog::new(input)
}

fn check_hook(image: &crate::emission::ArtifactImageView<'_>, policy: &c::Policy) -> c::Result<()> {
    let has_hook = image
        .metadata()
        .requirements()
        .iter()
        .any(|r| matches!(r, ArtifactRequirement::HookAbiAndReadiness(_)));
    let calls = image
        .metadata()
        .fields()
        .iter()
        .filter(|f| f.role == "HookCall")
        .collect::<Vec<_>>();
    if calls.len() != usize::from(has_hook) {
        return Err(c::Error::Target);
    }
    for f in calls {
        let offset = usize::try_from(f.offset).map_err(|_| c::Error::Target)?;
        let end = offset.checked_add(4).ok_or(c::Error::Target)?;
        if offset == 0
            || f.width != 4
            || f.encoding != crate::emission::ArtifactFieldEncoding::Relative
            || f.origin != end as u64
            || f.target != i128::from(policy.hook_pc)
            || f.bias_domain != policy.state.domain
            || image.bytes().get(offset - 1) != Some(&0xe8)
        {
            return Err(c::Error::Target);
        }
        let field = image.bytes().get(offset..end).ok_or(c::Error::Target)?;
        let displacement = i32::from_le_bytes(field.try_into().map_err(|_| c::Error::Target)?);
        if i128::from(image.address()) + i128::from(f.origin) + i128::from(displacement)
            != i128::from(policy.hook_pc)
        {
            return Err(c::Error::Target);
        }
    }
    Ok(())
}

fn span(r: crate::contracts::AddressRange) -> Span {
    Span {
        start: r.start(),
        len: r.len(),
    }
}

#[cfg(test)]
mod tests;
