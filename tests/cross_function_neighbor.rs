//! Pure artifact-planner checks. No executable mapping, CPU query or native call.
use liteinst2::bundle::BundleBudget;
use liteinst2::composition::Composition;
use liteinst2::contracts::*;
use liteinst2::emission::*;
use liteinst2::neighbor::{self, NeighborSearch};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{AllocationPolicy, SearchPolicy};
use liteinst2::trampoline::SavedExtendedStateLayout;

const S: u64 = 0x40186c;
const V: u64 = 0x4018e6;
const SELECTED_BASE: u64 = 0x401850;
const VICTIM_BASE: u64 = 0x4018d0;
// Complete two-function original byte/head vectors, including unselected heads.
const SELECTED_BYTES: &[u8] = &[
    0x41, 0x56, 0x41, 0x55, 0x49, 0x89, 0xfd, 0x41, 0x54, 0x49, 0x89, 0xf4, 0x49, 0xd1, 0xec, 0x55,
    0x48, 0x89, 0xf5, 0x48, 0x89, 0xd6, 0x53, 0x4c, 0x39, 0xe2, 0x72, 0x22, 0xeb, 0x58, 0x66, 0x90,
    0x4c, 0x89, 0xef, 0xe8, 0xc8, 0xff, 0xff, 0xff, 0x4c, 0x89, 0xf2, 0x48, 0x89, 0xde, 0x4c, 0x89,
    0xef, 0xe8, 0xba, 0xff, 0xff, 0xff, 0x4c, 0x39, 0xe3, 0x73, 0x3b, 0x48, 0x89, 0xde, 0x48, 0x8d,
    0x04, 0x36, 0x48, 0x8d, 0x4e, 0x01, 0x48, 0x8d, 0x58, 0x01, 0x48, 0x83, 0xc0, 0x02, 0x49, 0x8b,
    0x54, 0xdd, 0x00, 0x48, 0x39, 0xe8, 0x73, 0x14, 0x48, 0xc1, 0xe1, 0x04, 0x49, 0x8b, 0x4c, 0x0d,
    0x00, 0x48, 0x39, 0xd1, 0x76, 0x06, 0x48, 0x89, 0xca, 0x48, 0x89, 0xc3, 0x4d, 0x8b, 0x74, 0xf5,
    0x00, 0x49, 0x39, 0xd6, 0x72, 0xaa, 0x5b, 0x5d, 0x41, 0x5c, 0x41, 0x5d, 0x41, 0x5e, 0xc3,
];
const SELECTED_HEADS: &[u64] = &[
    0x0, 0x2, 0x4, 0x7, 0x9, 0xc, 0xf, 0x10, 0x13, 0x16, 0x17, 0x1a, 0x1c, 0x1e, 0x20, 0x23, 0x28,
    0x2b, 0x2e, 0x31, 0x36, 0x39, 0x3b, 0x3e, 0x42, 0x46, 0x4a, 0x4e, 0x53, 0x56, 0x58, 0x5c, 0x61,
    0x64, 0x66, 0x69, 0x6c, 0x71, 0x74, 0x76, 0x77, 0x78, 0x7a, 0x7c, 0x7e,
];
const VICTIM_BYTES: &[u8] = &[
    0x48, 0x83, 0xfe, 0x01, 0x76, 0x7a, 0x41, 0x54, 0x49, 0x89, 0xf4, 0x55, 0x49, 0xd1, 0xec, 0x48,
    0x89, 0xfd, 0x53, 0x48, 0x89, 0xf3, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x49, 0x83, 0xec, 0x01, 0x48, 0x89, 0xde, 0x48, 0x89, 0xef, 0x4c, 0x89, 0xe2, 0xe8, 0x4e, 0xff,
    0xff, 0xff, 0x4d, 0x85, 0xe4, 0x75, 0xe9, 0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x8b, 0x54, 0xdd, 0xf8, 0x4c, 0x8b, 0x65, 0x00, 0x31, 0xf6, 0x48, 0x83, 0xeb, 0x01, 0x48,
    0x89, 0xef, 0xe8, 0x19, 0xff, 0xff, 0xff, 0x4c, 0x89, 0xe2, 0x48, 0x89, 0xde, 0x48, 0x89, 0xef,
    0xe8, 0x0b, 0xff, 0xff, 0xff, 0x31, 0xd2, 0x48, 0x89, 0xde, 0x48, 0x89, 0xef, 0xe8, 0x0e, 0xff,
    0xff, 0xff, 0x48, 0x83, 0xfb, 0x01, 0x75, 0xc8, 0x5b, 0x5d, 0x41, 0x5c, 0xc3, 0x0f, 0x1f, 0x00,
    0xc3,
];
const VICTIM_HEADS: &[u64] = &[
    0x0, 0x4, 0x6, 0x8, 0xb, 0xc, 0xf, 0x12, 0x13, 0x16, 0x20, 0x24, 0x27, 0x2a, 0x2d, 0x32, 0x35,
    0x37, 0x40, 0x45, 0x49, 0x4b, 0x4f, 0x52, 0x57, 0x5a, 0x5d, 0x60, 0x65, 0x67, 0x6a, 0x6d, 0x72,
    0x76, 0x78, 0x79, 0x7a, 0x7c, 0x7d, 0x80,
];

fn range(pc: u64, len: usize) -> AddressRange {
    AddressRange::new(pc, len).unwrap()
}
fn identity() -> CodeIdentity {
    CodeIdentity {
        source: SourceIdentity([57; 32]),
        mapping: 15,
        generation: 1,
    }
}
fn allocation(pc: u64) -> AllocationPolicy {
    AllocationPolicy {
        ranges: vec![range(pc, 65536)],
        preferred_address: Some(pc),
        max_candidates: 1,
        max_mappings: 1,
        max_mapped_bytes: 65536,
    }
}
fn entries(base: u64, bytes: &[u8], heads: &[u64]) -> LegalEntrySet {
    LegalEntrySet {
        identity: identity(),
        scope: range(base, bytes.len()),
        provenance: EntryProvenance::Declared("complete two-function source fixture".into()),
        completeness: EntryCompleteness::Complete,
        entries: heads
            .iter()
            .map(|n| LegalEntry {
                address: base + n,
                requires_endbr: false,
            })
            .collect(),
        resumes: ResumeObligation::NoneExist,
    }
}
struct Fixture {
    selected_entries: LegalEntrySet,
    victim_entries: LegalEntrySet,
    selected_allocation: AllocationPolicy,
    victim_allocation: AllocationPolicy,
    emission: ArtifactEmission,
}
impl Fixture {
    fn new() -> Self {
        Self {
            selected_entries: entries(SELECTED_BASE, SELECTED_BYTES, SELECTED_HEADS),
            victim_entries: entries(VICTIM_BASE, VICTIM_BYTES, VICTIM_HEADS),
            selected_allocation: allocation(0x10000),
            victim_allocation: allocation(0x30000),
            emission: ArtifactEmission::new(
                TargetProfile::linux_x86_64_legacy_evex(
                    SavedExtendedStateLayout::describe_target_fxsave64(),
                    1,
                )
                .unwrap(),
                SymbolicHook {
                    identity: 15,
                    address: Some(0x401960),
                },
                vec![range(0x400000, 0x25000)],
            ),
        }
    }
    fn request(&self) -> ArtifactRequest<'_> {
        ArtifactRequest {
            site: PlanningSite {
                identity: identity(),
                code: SELECTED_BYTES,
                base_address: SELECTED_BASE,
                function: self.selected_entries.scope,
                block: range(S, 2),
                logical_pc: S,
                entries: &self.selected_entries,
                semantics: HookSemantics::Observe,
                allocation: &self.selected_allocation,
                search: SearchPolicy {
                    max_sites: 64,
                    max_displaced_bytes: 256,
                    ..SearchPolicy::default()
                },
            },
            emission: &self.emission,
        }
    }
    fn victim(&self) -> PlanningSite<'_> {
        PlanningSite {
            identity: identity(),
            code: VICTIM_BYTES,
            base_address: VICTIM_BASE,
            function: self.victim_entries.scope,
            block: range(0x4018d6, 26),
            logical_pc: V,
            entries: &self.victim_entries,
            semantics: HookSemantics::Observe,
            allocation: &self.victim_allocation,
            search: self.request().site.search,
        }
    }
    fn predecessor(&self) -> Composition {
        Composition::new(
            identity(),
            vec![
                ExpectedBytes {
                    address: SELECTED_BASE,
                    bytes: SELECTED_BYTES.to_vec(),
                },
                ExpectedBytes {
                    address: VICTIM_BASE,
                    bytes: VICTIM_BYTES.to_vec(),
                },
            ],
        )
        .unwrap()
    }
}
fn budget() -> BundleBudget {
    BundleBudget {
        max_virtual_span: 1_073_741_824,
        ..BundleBudget::default()
    }
}
fn search(pc: u64) -> NeighborSearch {
    NeighborSearch {
        forced_victim: Some(pc),
        max_victims: 256,
        max_pairs: 4096,
    }
}
fn planned(
    f: &Fixture,
    predecessor: &Composition,
) -> Result<ArtifactPlan, neighbor::NeighborFailure> {
    neighbor::plan_neighbor_with_emission_from(
        &f.request(),
        predecessor,
        &f.victim(),
        search(V),
        budget(),
    )
}

#[test]
fn exact_id15_id57_two_owner_gateways_images_and_original_relative_bytes() {
    let f = Fixture::new();
    assert_eq!((SELECTED_BYTES.len(), SELECTED_HEADS.len()), (127, 45));
    assert_eq!((VICTIM_BYTES.len(), VICTIM_HEADS.len()), (129, 40));
    let before = f.predecessor();
    let old = neighbor::plan_neighbor_with_emission(
        &f.request(),
        &f.victim_allocation,
        search(V),
        budget(),
    )
    .unwrap_err();
    assert_eq!(old.reason, Refusal::NotInstructionHead);
    let p = planned(&f, &before).unwrap();
    assert!(!p.qualification_complete());
    let ArtifactMetrics::Neighbor(g, m) = p.metrics() else {
        panic!("exact T3 metrics")
    };
    assert_eq!((g.selected, g.victim, g.relay, g.rel8), (S, V, V + 5, 125));
    assert_eq!((g.selected_target, g.victim_target), (0x10000, 0x30000));
    assert_eq!(
        (m.victims_examined, m.pairs_examined, m.attempts.len()),
        (1, 1, 1)
    );
    assert_eq!(m.attempts[0].refusal, None);
    let steps = p.source_steps();
    assert_eq!(steps.len(), 2);
    assert_eq!(steps[0].parts().physical_pc, V);
    assert_eq!(steps[1].parts().physical_pc, S);
    assert_eq!(steps[0].parts().entries, f.victim_entries);
    assert_eq!(steps[1].parts().entries, f.selected_entries);
    assert_eq!(
        steps[0].parts().writes,
        vec![ByteEdit {
            address: V,
            bytes: vec![0xe9, 0x15, 0xe7, 0xc2, 0xff, 0xe9, 0x10, 0xe7, 0xc0, 0xff]
        }]
    );
    assert_eq!(
        steps[1].parts().writes,
        vec![ByteEdit {
            address: S,
            bytes: vec![0xeb, 0x7d]
        }]
    );
    let images = p.images().collect::<Vec<_>>();
    assert_eq!(images.len(), 2);
    assert_eq!(images[0].address(), 0x30000);
    assert_eq!(images[1].address(), 0x10000);
    assert!(
        !images[0]
            .metadata()
            .requirements()
            .iter()
            .any(|r| matches!(r, ArtifactRequirement::HookAbiAndReadiness(_)))
    );
    assert!(
        images[1]
            .metadata()
            .requirements()
            .contains(&ArtifactRequirement::HookAbiAndReadiness(15))
    );
    assert!(
        images[1]
            .metadata()
            .fields()
            .iter()
            .any(|f| f.target == 0x4018c6)
    );
    assert!(
        images[0]
            .metadata()
            .fields()
            .iter()
            .any(|f| f.target == 0x4018f0)
    );
    assert_eq!(
        images[0]
            .instruction_boundaries()
            .iter()
            .map(|x| x.0)
            .collect::<Vec<_>>(),
        vec![V]
    );
    assert_eq!(
        images[1]
            .instruction_boundaries()
            .iter()
            .map(|x| x.0)
            .collect::<Vec<_>>(),
        vec![S]
    );
    let mut composed = before.clone();
    for step in steps {
        composed.append(step).unwrap();
    }
    let mut wanted = before.originals().to_vec();
    wanted[0].bytes[(S - SELECTED_BASE) as usize..(S - SELECTED_BASE) as usize + 2]
        .copy_from_slice(&[0xeb, 0x7d]);
    wanted[1].bytes[(V - VICTIM_BASE) as usize..(V - VICTIM_BASE) as usize + 10]
        .copy_from_slice(&[0xe9, 0x15, 0xe7, 0xc2, 0xff, 0xe9, 0x10, 0xe7, 0xc0, 0xff]);
    assert_eq!(composed.final_bytes(), wanted);
    assert_eq!(before, f.predecessor());
    assert_eq!(composed.locks(), &[range(S, 2), range(V, 10)]);
}

#[test]
fn missing_partial_stale_or_changed_original_victim_authority_refuses() {
    let f = Fixture::new();
    let originals = f.predecessor().originals().to_vec();
    let missing = Composition::new(identity(), vec![originals[0].clone()]).unwrap();
    assert_eq!(
        planned(&f, &missing).unwrap_err().reason,
        Refusal::DependencyNotHeld
    );
    let mut partial = originals.clone();
    partial[1].bytes.pop();
    assert_eq!(
        planned(&f, &Composition::new(identity(), partial).unwrap())
            .unwrap_err()
            .reason,
        Refusal::DependencyNotHeld
    );
    let mut changed = originals;
    changed[1].bytes[0] ^= 1;
    assert_eq!(
        planned(&f, &Composition::new(identity(), changed).unwrap())
            .unwrap_err()
            .reason,
        Refusal::ExpectedBytesChanged
    );
    for field in 0..3 {
        let mut v = f.victim();
        match field {
            0 => v.identity.source.0[0] ^= 1,
            1 => v.identity.mapping += 1,
            _ => v.identity.generation += 1,
        }
        assert_eq!(
            neighbor::plan_neighbor_with_emission_from(
                &f.request(),
                &f.predecessor(),
                &v,
                search(V),
                budget()
            )
            .unwrap_err()
            .reason,
            Refusal::StaleGeneration
        );
    }
}

#[test]
fn both_entry_owners_and_saved_resumes_remain_complete() {
    for selected in [false, true] {
        for mode in 0..5 {
            let mut f = Fixture::new();
            let e = if selected {
                &mut f.selected_entries
            } else {
                &mut f.victim_entries
            };
            let pc = if selected { S } else { V };
            match mode {
                0 => e.completeness = EntryCompleteness::Incomplete,
                1 => e.resumes = ResumeObligation::Unresolved,
                2 => e.entries.push(LegalEntry {
                    address: pc + 1,
                    requires_endbr: false,
                }),
                3 => e.resumes = ResumeObligation::Enumerated(vec![pc + 1]),
                _ => e.identity.generation += 1,
            }
            let expected = match mode {
                0 | 1 => Refusal::UnresolvedEntry,
                2 | 3 => Refusal::NotInstructionHead,
                _ => Refusal::StaleGeneration,
            };
            assert_eq!(planned(&f, &f.predecessor()).unwrap_err().reason, expected);
        }
    }
    let mut f = Fixture::new();
    f.selected_entries.resumes = ResumeObligation::Enumerated(vec![S]);
    f.victim_entries.resumes = ResumeObligation::Enumerated(vec![V, V + 10]);
    planned(&f, &f.predecessor()).unwrap();
}

#[test]
fn wrong_forced_head_block_function_or_semantics_cannot_borrow_authority() {
    let f = Fixture::new();
    for forced in [None, Some(V + 5)] {
        assert_eq!(
            neighbor::plan_neighbor_with_emission_from(
                &f.request(),
                &f.predecessor(),
                &f.victim(),
                NeighborSearch {
                    forced_victim: forced,
                    ..search(V)
                },
                budget()
            )
            .unwrap_err()
            .reason,
            Refusal::InvalidRange
        );
    }
    let mut victim = f.victim();
    victim.block = range(V, 9);
    assert_eq!(
        neighbor::plan_neighbor_with_emission_from(
            &f.request(),
            &f.predecessor(),
            &victim,
            search(V),
            budget()
        )
        .unwrap_err()
        .reason,
        Refusal::NotInstructionHead
    );
    victim = f.victim();
    victim.function = range(V, 10);
    assert_eq!(
        neighbor::plan_neighbor_with_emission_from(
            &f.request(),
            &f.predecessor(),
            &victim,
            search(V),
            budget()
        )
        .unwrap_err()
        .reason,
        Refusal::InvalidRange
    );
    victim = f.victim();
    victim.semantics = HookSemantics::ReplaceFirst;
    assert_eq!(
        neighbor::plan_neighbor_with_emission_from(
            &f.request(),
            &f.predecessor(),
            &victim,
            search(V),
            budget()
        )
        .unwrap_err()
        .reason,
        Refusal::InvalidRange
    );
    victim = f.request().site;
    assert_eq!(
        neighbor::plan_neighbor_with_emission_from(
            &f.request(),
            &f.predecessor(),
            &victim,
            search(S),
            budget()
        )
        .unwrap_err()
        .reason,
        Refusal::OwnershipConflict
    );
}

// A structurally admitted prior plan is enough to test overlay/lock authority;
// this helper supplies no independent instruction semantics or native proof.
fn prior(
    f: &Fixture,
    selected: bool,
    pc: u64,
    byte: u8,
    allocation: Option<AddressRange>,
) -> PatchPlan {
    let (base, bytes, entries) = if selected {
        (SELECTED_BASE, SELECTED_BYTES, &f.selected_entries)
    } else {
        (VICTIM_BASE, VICTIM_BYTES, &f.victim_entries)
    };
    PatchPlan::checked(PlanParts {
        identity: identity(),
        profile: ApplicationProfile::InstallOnce,
        kind: PlanKind::Relocation,
        logical_pc: pc,
        physical_pc: pc,
        displaced: range(pc, 1),
        reads: vec![ExpectedBytes {
            address: base,
            bytes: bytes.to_vec(),
        }],
        writes: vec![ByteEdit {
            address: pc,
            bytes: vec![byte],
        }],
        dependencies: vec![range(base, bytes.len())],
        entries: entries.clone(),
        obligations: vec![EntryObligation::Preserved(pc)],
        allocations: allocation
            .into_iter()
            .map(|r| AllocationRequest {
                range: r,
                alignment: 4096,
            })
            .collect(),
        generated: vec![],
        requirements: PublicationRequirements {
            quiescent: true,
            sync_core: true,
            sigill_router: false,
        },
    })
    .unwrap()
}

#[test]
fn changed_selected_and_victim_operations_refuse_without_mutating_predecessor() {
    let f = Fixture::new();
    for (selected, pc) in [(true, S), (false, V)] {
        let mut c = f.predecessor();
        c.append(&prior(&f, selected, pc, 0xcc, None)).unwrap();
        let before = c.clone();
        assert_eq!(
            planned(&f, &c).unwrap_err().reason,
            Refusal::ExpectedBytesChanged
        );
        assert_eq!(c, before);
    }
}

#[test]
fn current_full_reads_keep_other_edits_and_inherited_locks_are_not_reset() {
    let f = Fixture::new();
    let mut c = f.predecessor();
    c.append(&prior(&f, false, 0x40194c, 0xcc, None)).unwrap();
    let p = planned(&f, &c).unwrap();
    assert_eq!(p.source_steps()[0].parts().reads[0], c.final_bytes()[1]);
    for step in p.source_steps() {
        c.append(step).unwrap();
    }
    assert_eq!(
        c.final_bytes()[1].bytes[(0x40194c - VICTIM_BASE) as usize],
        0xcc
    );
    for alloc in [None, Some(range(0x10000, 4096))] {
        let mut c = f.predecessor();
        let pc = if alloc.is_none() { V } else { 0x40194c };
        let byte = VICTIM_BYTES[(pc - VICTIM_BASE) as usize];
        c.append(&prior(&f, false, pc, byte, alloc)).unwrap();
        let before = c.clone();
        assert_eq!(
            planned(&f, &c).unwrap_err().reason,
            Refusal::OwnershipConflict
        );
        assert_eq!(c, before);
    }
}

#[test]
fn unchanged_budget_and_both_source_placement_exclusions_are_enforced() {
    let f = Fixture::new();
    for bounds in [
        NeighborSearch {
            max_victims: 0,
            ..search(V)
        },
        NeighborSearch {
            max_pairs: 0,
            ..search(V)
        },
    ] {
        assert_eq!(
            neighbor::plan_neighbor_with_emission_from(
                &f.request(),
                &f.predecessor(),
                &f.victim(),
                bounds,
                budget()
            )
            .unwrap_err()
            .reason,
            Refusal::AllocationUnavailable
        );
    }
    for b in [
        BundleBudget {
            max_steps: 1,
            ..budget()
        },
        BundleBudget {
            max_mappings: 1,
            ..budget()
        },
        BundleBudget {
            max_virtual_span: 65536,
            ..budget()
        },
    ] {
        assert_eq!(
            neighbor::plan_neighbor_with_emission_from(
                &f.request(),
                &f.predecessor(),
                &f.victim(),
                search(V),
                b
            )
            .unwrap_err()
            .reason,
            Refusal::AllocationUnavailable
        );
    }
    for selected in [false, true] {
        let mut f = Fixture::new();
        f.emission = ArtifactEmission::new(f.emission.profile().clone(), f.emission.hook(), vec![]);
        let bad = AllocationPolicy {
            preferred_address: Some(SELECTED_BASE),
            ranges: vec![range(0x401000, 65536)],
            ..allocation(0x401000)
        };
        if selected {
            f.selected_allocation = bad;
        } else {
            f.victim_allocation = bad;
        }
        assert_eq!(
            planned(&f, &f.predecessor()).unwrap_err().reason,
            Refusal::AllocationUnavailable
        );
    }
}

#[test]
fn cross_function_direct_branch_into_victim_interior_and_cet_are_refused() {
    let mut f = Fixture::new();
    f.victim_entries
        .entries
        .iter_mut()
        .find(|e| e.address == V)
        .unwrap()
        .requires_endbr = true;
    assert!(matches!(
        planned(&f, &f.predecessor()).unwrap_err().reason,
        Refusal::UnsupportedSemantics(_)
    ));
    let f = Fixture::new();
    let mut code = SELECTED_BYTES.to_vec();
    // The same two-byte JMP now targets V+1; decoder shape/entry heads stay exact.
    code[(S - SELECTED_BASE) as usize + 1] = 121;
    let mut request = f.request();
    request.site.code = &code;
    let c = Composition::new(
        identity(),
        vec![
            ExpectedBytes {
                address: SELECTED_BASE,
                bytes: code.clone(),
            },
            ExpectedBytes {
                address: VICTIM_BASE,
                bytes: VICTIM_BYTES.to_vec(),
            },
        ],
    )
    .unwrap();
    assert_eq!(
        neighbor::plan_neighbor_with_emission_from(&request, &c, &f.victim(), search(V), budget())
            .unwrap_err()
            .reason,
        Refusal::NotInstructionHead
    );
}

#[test]
fn exact_upper_rel8_limit_is_accepted_and_next_byte_refuses() {
    let f = Fixture::new();
    for (shift, accepted) in [(2_u64, true), (3, false)] {
        let mut e = f.victim_entries.clone();
        e.scope = range(VICTIM_BASE + shift, VICTIM_BYTES.len());
        for entry in &mut e.entries {
            entry.address += shift;
        }
        let mut v = f.victim();
        v.base_address += shift;
        v.function = e.scope;
        v.block = range(0x4018d6 + shift, 26);
        v.logical_pc += shift;
        v.entries = &e;
        let c = Composition::new(
            identity(),
            vec![
                ExpectedBytes {
                    address: SELECTED_BASE,
                    bytes: SELECTED_BYTES.to_vec(),
                },
                ExpectedBytes {
                    address: VICTIM_BASE + shift,
                    bytes: VICTIM_BYTES.to_vec(),
                },
            ],
        )
        .unwrap();
        let r = neighbor::plan_neighbor_with_emission_from(
            &f.request(),
            &c,
            &v,
            search(v.logical_pc),
            budget(),
        );
        if accepted {
            let p = r.unwrap();
            let ArtifactMetrics::Neighbor(g, _) = p.metrics() else {
                panic!("T3 geometry")
            };
            assert_eq!(g.rel8, 127);
        } else {
            assert_eq!(r.unwrap_err().reason, Refusal::NoPatchWindow);
        }
    }
}
