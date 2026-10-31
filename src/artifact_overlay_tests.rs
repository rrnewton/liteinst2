//! Pure original/current artifact-planning contracts; no code is published or executed.

use crate::composition::Composition;
use crate::contracts::*;
use crate::emission::*;
use crate::engine::{self, CandidateEvidence, EngineFailure, EnginePolicy, Tactic};
use crate::neighbor::NeighborSearch;
use crate::planner::HookSemantics;
use crate::quiescent::{AllocationPolicy, SearchPolicy, TacticPolicy};
use crate::scanner::InstructionScanner;
use crate::trampoline::SavedExtendedStateLayout;

const S: u64 = 0x4200_0000_0080;
const BASE: u64 = S - 16;
const TACTICS: [Tactic; 5] = [
    Tactic::Relocation,
    Tactic::GeneralizedPun,
    Tactic::PrefixedPun,
    Tactic::SuccessorEviction,
    Tactic::NeighborEviction,
];

fn identity() -> CodeIdentity {
    CodeIdentity {
        source: SourceIdentity([7; 32]),
        mapping: 1,
        generation: 3,
    }
}

fn allocation(address: u64) -> AllocationPolicy {
    AllocationPolicy {
        ranges: vec![AddressRange::new(address & !4095, 8192).unwrap()],
        preferred_address: Some(address),
        max_candidates: 256,
        max_mappings: 1,
        max_mapped_bytes: 8192,
    }
}

struct Fixture {
    tactic: Tactic,
    code: Vec<u8>,
    block_len: usize,
    entries: LegalEntrySet,
    selected: AllocationPolicy,
    victim: AllocationPolicy,
    emission: ArtifactEmission,
}

impl Fixture {
    fn new(tactic: Tactic) -> Self {
        // Literal five source shapes and allocations from artifact_emission_tests.
        let (mut body, block_len, heads) = match tactic {
            Tactic::Relocation => (vec![0xb8, 42, 0, 0, 0, 0xc3], 6, vec![0, 5]),
            Tactic::GeneralizedPun => (
                vec![0x0f, 0x1f, 0, 0xb8, 42, 0, 0, 0, 0xc3],
                9,
                vec![0, 3, 8],
            ),
            Tactic::PrefixedPun => (vec![0x89, 0xc0, 0xb8, 42, 0, 0, 0, 0xc3], 8, vec![0, 2, 7]),
            Tactic::SuccessorEviction => (
                vec![
                    0x0f, 0x1f, 0, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0, 0xb8, 42, 0, 0, 0, 0xc3,
                ],
                17,
                vec![0, 3, 11, 16, 64, 74],
            ),
            Tactic::NeighborEviction => (vec![0x75, 1, 0x90, 0xc3], 2, vec![0, 2, 3, 64, 74]),
        };
        if matches!(tactic, Tactic::SuccessorEviction | Tactic::NeighborEviction) {
            body.resize(64, 0x90);
            body.extend_from_slice(&[0x48, 0xb8]);
            body.extend_from_slice(&42_u64.to_le_bytes());
            body.push(0xc3);
        }
        let selected = match tactic {
            Tactic::Relocation | Tactic::NeighborEviction => S + 0x400_0000,
            Tactic::GeneralizedPun => S + 5 + 0x2ab8_0000 + 0x8000,
            Tactic::PrefixedPun => S + 6 + 0x2ab8,
            Tactic::SuccessorEviction => S + 5 + 0x56e9_0000 + 0x8000,
        };
        let victim = if tactic == Tactic::SuccessorEviction {
            S + 8 + 0x0012_3456
        } else {
            S + 0x600_0000
        };
        Self::shape(tactic, body, block_len, heads, selected, victim)
    }

    fn shape(
        tactic: Tactic,
        body: Vec<u8>,
        block_len: usize,
        heads: Vec<u64>,
        selected: u64,
        victim: u64,
    ) -> Self {
        let function = AddressRange::new(S, body.len()).unwrap();
        let mut code = vec![0x90; 16];
        code.extend_from_slice(&body);
        Self {
            tactic,
            code,
            block_len,
            entries: LegalEntrySet {
                identity: identity(),
                scope: function,
                provenance: EntryProvenance::Declared(
                    "pure overlay fixture; explicit original heads".into(),
                ),
                completeness: EntryCompleteness::Complete,
                entries: heads
                    .into_iter()
                    .map(|offset| LegalEntry {
                        address: S + offset,
                        requires_endbr: false,
                    })
                    .collect(),
                resumes: ResumeObligation::NoneExist,
            },
            selected: allocation(selected),
            victim: allocation(victim),
            emission: ArtifactEmission::new(
                TargetProfile::linux_x86_64_legacy_evex(
                    SavedExtendedStateLayout::describe_target_fxsave64(),
                    7,
                )
                .unwrap(),
                SymbolicHook {
                    identity: 11,
                    address: Some(S + 0x1000),
                },
                vec![AddressRange::new(S & !4095, 8192).unwrap()],
            ),
        }
    }

    fn request(&self, semantics: HookSemantics) -> ArtifactRequest<'_> {
        ArtifactRequest {
            site: PlanningSite {
                identity: identity(),
                code: &self.code,
                base_address: BASE,
                function: self.entries.scope,
                block: AddressRange::new(S, self.block_len).unwrap(),
                logical_pc: S,
                entries: &self.entries,
                semantics,
                allocation: &self.selected,
                search: SearchPolicy {
                    tactics: TacticPolicy::RelocationOnly,
                    max_upstream_bytes: 0,
                    max_sites: 1,
                    ..SearchPolicy::default()
                },
            },
            emission: &self.emission,
        }
    }

    fn policy(&self) -> EnginePolicy {
        EnginePolicy {
            forced: Some(self.tactic),
            neighbor: NeighborSearch {
                forced_victim: Some(S + 64),
                ..NeighborSearch::default()
            },
            ..EnginePolicy::default()
        }
    }

    fn predecessor(&self) -> Composition {
        Composition::new(
            identity(),
            vec![ExpectedBytes {
                address: BASE,
                bytes: self.code.clone(),
            }],
        )
        .unwrap()
    }

    fn plan(
        &self,
        predecessor: &Composition,
        semantics: HookSemantics,
    ) -> Result<ArtifactPlan, EngineFailure> {
        engine::plan_with_emission_after(
            &self.request(semantics),
            predecessor,
            &self.victim,
            self.policy(),
        )
    }
}

// A checked synthetic byte edit isolates the public overlay contract. This is
// not an emitted instruction, semantic proof or executable predecessor fixture.
fn append_edit(predecessor: &mut Composition, address: u64, bytes: &[u8]) {
    let reads = predecessor.final_bytes().to_vec();
    let source = AddressRange::new(BASE, reads[0].bytes.len()).unwrap();
    let plan = PatchPlan::checked(PlanParts {
        identity: identity(),
        profile: ApplicationProfile::InstallOnce,
        kind: PlanKind::Relocation,
        logical_pc: address,
        physical_pc: address,
        displaced: AddressRange::new(address, bytes.len()).unwrap(),
        reads,
        writes: vec![ByteEdit {
            address,
            bytes: bytes.to_vec(),
        }],
        dependencies: vec![source],
        entries: LegalEntrySet {
            identity: identity(),
            scope: source,
            provenance: EntryProvenance::Declared("synthetic composition-byte setup only".into()),
            completeness: EntryCompleteness::Complete,
            entries: vec![],
            resumes: ResumeObligation::NoneExist,
        },
        obligations: vec![],
        allocations: vec![],
        generated: vec![],
        requirements: PublicationRequirements {
            quiescent: true,
            sync_core: true,
            sigill_router: false,
        },
    })
    .unwrap();
    predecessor.append(&plan).unwrap();
}

fn assert_current_steps(fixture: &Fixture, predecessor: &Composition, plan: &ArtifactPlan) {
    let ArtifactMetrics::Engine(winner, _, attempts) = plan.metrics() else {
        panic!("engine metrics missing")
    };
    assert_eq!(*winner, fixture.tactic);
    assert_eq!(attempts.len(), 1);
    let steps = if matches!(
        fixture.tactic,
        Tactic::SuccessorEviction | Tactic::NeighborEviction
    ) {
        2
    } else {
        1
    };
    assert_eq!(plan.source_steps().len(), steps);
    assert_eq!(plan.images().count(), steps);
    assert!(!plan.qualification_complete());
    let mut composed = predecessor.clone();
    for step in plan.source_steps() {
        // For T2/T3 the second read must include both inherited and local edits.
        assert_eq!(step.parts().reads, composed.final_bytes());
        assert_eq!(
            step.parts().dependencies,
            vec![AddressRange::new(BASE, fixture.code.len()).unwrap()]
        );
        assert_eq!(step.parts().entries, fixture.entries);
        step.check_entry_obligations().unwrap();
        composed.append(step).unwrap();
    }
    assert_eq!(composed.originals(), predecessor.originals());
    if steps == 2 {
        assert_ne!(
            plan.source_steps()[0].parts().reads,
            plan.source_steps()[1].parts().reads
        );
    }
}

#[test]
fn five_tactics_decode_originals_and_keep_inherited_full_reads() {
    for tactic in TACTICS {
        let fixture = Fixture::new(tactic);
        let mut predecessor = fixture.predecessor();
        append_edit(&mut predecessor, BASE, &[0x06]); // invalid in long mode
        assert!(
            InstructionScanner::default()
                .scan(&predecessor.final_bytes()[0].bytes, BASE)
                .is_err()
        );
        assert!(
            InstructionScanner::default()
                .scan(&fixture.code, BASE)
                .is_ok()
        );
        let saved = predecessor.clone();
        let plan = fixture.plan(&predecessor, HookSemantics::Observe).unwrap();
        assert_current_steps(&fixture, &predecessor, &plan);
        assert!(plan.images().any(|image| {
            image
                .instruction_boundaries()
                .iter()
                .any(|&(original, _)| original == S)
        }));
        assert!(
            plan.source_steps()
                .iter()
                .all(|step| step.parts().reads[0].bytes[0] == 0x06)
        );
        assert_eq!(
            predecessor, saved,
            "planning must not append or mutate the predecessor"
        );
    }
}

#[test]
fn generalized_and_prefixed_puns_preserve_inherited_suffix_and_store_padding() {
    for tactic in [Tactic::GeneralizedPun, Tactic::PrefixedPun] {
        let mut fixture = Fixture::new(Tactic::GeneralizedPun); // NOP3 has a four-byte store.
        fixture.tactic = tactic;
        // Current successor is MOV ECX,43, but original identity remains MOV EAX,42.
        let target = match tactic {
            Tactic::GeneralizedPun => S + 5 + 0x2bb9_0000 + 0x8000,
            Tactic::PrefixedPun => S + 6 + 0x002b_b900 + 0x80,
            _ => unreachable!(),
        };
        fixture.selected = allocation(target);
        let mut predecessor = fixture.predecessor();
        append_edit(&mut predecessor, S + 3, &[0xb9, 43]);
        let saved = predecessor.clone();
        let plan = fixture.plan(&predecessor, HookSemantics::Observe).unwrap();
        assert_current_steps(&fixture, &predecessor, &plan);
        let parts = plan.source_steps()[0].parts();
        let (consumed, window, store, prefixes) = match &parts.kind {
            PlanKind::GeneralizedPun(pun) => (pun.consumed, pun.target_window, &pun.store, 0),
            PlanKind::PrefixedPun(pun) => (
                pun.consumed,
                pun.target_window,
                &pun.store,
                usize::from(pun.prefix_count),
            ),
            PlanKind::Relocation => panic!("forced pun must remain a pun"),
        };
        assert_eq!(prefixes, usize::from(tactic == Tactic::PrefixedPun));
        assert_eq!(parts.displaced, AddressRange::new(S, 3).unwrap());
        assert_eq!(consumed, AddressRange::new(S, 5 + prefixes).unwrap());
        assert_eq!(
            window.start(),
            if prefixes == 0 {
                S + 5 + 0x2bb9_0000
            } else {
                S + 6 + 0x002b_b900
            }
        );
        assert_eq!(store.address, S);
        assert_eq!(store.bytes.len(), 4);
        assert_eq!(store.bytes[3], 0xb9);
        assert_eq!(&parts.reads[0].bytes[19..21], &[0xb9, 43]);
        assert_eq!(plan.images().next().unwrap().address(), target);
        assert_eq!(predecessor, saved);
    }
}

fn assert_changed(fixture: &Fixture, predecessor: &Composition, semantics: HookSemantics) {
    let saved = predecessor.clone();
    let failure = fixture.plan(predecessor, semantics).unwrap_err();
    assert_eq!(failure.reason, Refusal::ExpectedBytesChanged);
    assert_eq!(failure.attempts.len(), 1);
    assert_eq!(failure.attempts[0].tactic, fixture.tactic);
    assert_eq!(
        failure.attempts[0].refusal,
        Some(Refusal::ExpectedBytesChanged)
    );
    assert_eq!(*predecessor, saved);
}

#[test]
fn all_five_tactics_refuse_changed_selected_bytes_even_when_replacing() {
    for tactic in TACTICS {
        let fixture = Fixture::new(tactic);
        let selected_len = match tactic {
            Tactic::Relocation => 5,
            Tactic::GeneralizedPun | Tactic::SuccessorEviction => 3,
            Tactic::PrefixedPun | Tactic::NeighborEviction => 2,
        };
        let mut predecessor = fixture.predecessor();
        let last = 16 + selected_len - 1;
        append_edit(
            &mut predecessor,
            S + selected_len as u64 - 1,
            &[fixture.code[last] ^ 1],
        );
        for semantics in [HookSemantics::Observe, HookSemantics::ReplaceFirst] {
            assert_changed(&fixture, &predecessor, semantics);
        }
    }
}

#[test]
fn successor_and_neighbor_refuse_changed_original_victims() {
    for (tactic, offset, len) in [
        (Tactic::SuccessorEviction, 3, 8),
        (Tactic::NeighborEviction, 64, 10),
    ] {
        let fixture = Fixture::new(tactic);
        let mut predecessor = fixture.predecessor();
        let last = 16 + offset + len - 1;
        append_edit(
            &mut predecessor,
            S + (offset + len - 1) as u64,
            &[fixture.code[last] ^ 1],
        );
        for semantics in [HookSemantics::Observe, HookSemantics::ReplaceFirst] {
            assert_changed(&fixture, &predecessor, semantics);
        }
    }
}

#[test]
fn changed_same_site_window_keeps_the_bounded_upstream_candidate() {
    let fixture = Fixture::shape(
        Tactic::Relocation,
        vec![0x0f, 0x1f, 0, 0x66, 0x90, 0xb8, 42, 0, 0, 0, 0xc3],
        11,
        vec![0, 3, 5, 10],
        S + 5 + 0x0006_8000,
        S + 0x600_0000,
    );
    let mut predecessor = fixture.predecessor();
    append_edit(&mut predecessor, S + 9, &[1]); // Last byte of the following MOV5.
    let saved = predecessor.clone();
    let mut request = fixture.request(HookSemantics::Observe);
    request.site.logical_pc = S + 3;
    request.site.search.max_upstream_bytes = 3;
    request.site.search.max_sites = 2;
    let plan =
        engine::plan_with_emission_after(&request, &predecessor, &fixture.victim, fixture.policy())
            .unwrap();
    assert_current_steps(&fixture, &predecessor, &plan);
    let ArtifactMetrics::Engine(_, _, attempts) = plan.metrics() else {
        panic!("engine metrics missing")
    };
    let CandidateEvidence::Single(candidates) = &attempts[0].candidates else {
        panic!("B1 candidates missing")
    };
    assert_eq!(candidates.len(), 2);
    assert_eq!(
        (candidates[0].physical_pc, &candidates[0].refusal),
        (S + 3, &Some(Refusal::ExpectedBytesChanged))
    );
    assert_eq!(
        (candidates[1].physical_pc, &candidates[1].refusal),
        (S, &None)
    );
    let parts = plan.source_steps()[0].parts();
    assert_eq!(parts.displaced, AddressRange::new(S, 5).unwrap());
    assert_eq!(parts.logical_pc, S + 3);
    assert_eq!(parts.writes[0].bytes, [0xe9, 0, 0x80, 0x06, 0]);
    assert!(parts.obligations.iter().any(
        |obligation| matches!(obligation, EntryObligation::Routed(route) if route.original == S + 3)
    ));
    assert!(plan.images().any(|image| {
        image
            .entry_routes()
            .iter()
            .any(|&(original, _)| original == S + 3)
    }));
    assert_eq!(predecessor, saved);
}

// New-profile controls below do not change the fixtures or assertions above.
// This short literal reproduces site 215's physical PC and four entry-mask
// bytes; it is not a whole-program or executable/native qualification fixture.
fn current_placement_mask_fixture(
    seed: u64,
    held: &[AddressRange],
    current: bool,
) -> Result<ArtifactPlan, EngineFailure> {
    let pc = 11216;
    let code = [0x53, 0x4c, 0x8b, 0x0f, 0x48, 0x89, 0xfb, 0xc3];
    let source = AddressRange::new(pc, code.len()).unwrap();
    let entries = LegalEntrySet {
        identity: identity(),
        scope: source,
        provenance: EntryProvenance::Declared("literal physical/mask control only".into()),
        completeness: EntryCompleteness::AllInstructionHeads,
        entries: [0, 1, 4, 7]
            .map(|offset| LegalEntry {
                address: pc + offset,
                requires_endbr: false,
            })
            .to_vec(),
        resumes: ResumeObligation::NoneExist,
    };
    let allocation = AllocationPolicy {
        ranges: vec![AddressRange::new(262144, 2147483648 - 262144).unwrap()],
        preferred_address: Some(seed),
        max_candidates: 1,
        max_mappings: 1,
        max_mapped_bytes: 4096,
    };
    let mut occupied = vec![AddressRange::new(pc & !4095, 4096).unwrap()];
    occupied.extend_from_slice(held);
    let emission = ArtifactEmission::new(
        TargetProfile::linux_x86_64_legacy_evex(
            SavedExtendedStateLayout::describe_target_fxsave64(),
            7,
        )
        .unwrap(),
        SymbolicHook {
            identity: 11,
            address: Some(pc + 0x1000),
        },
        occupied,
    );
    let request = ArtifactRequest {
        site: PlanningSite {
            identity: identity(),
            code: &code,
            base_address: pc,
            function: source,
            block: source,
            logical_pc: pc,
            entries: &entries,
            semantics: HookSemantics::Observe,
            allocation: &allocation,
            search: SearchPolicy {
                max_upstream_bytes: 0,
                max_sites: 1,
                ..SearchPolicy::default()
            },
        },
        emission: &emission,
    };
    let predecessor = Composition::new(
        identity(),
        vec![ExpectedBytes {
            address: pc,
            bytes: code.to_vec(),
        }],
    )
    .unwrap();
    let policy = EnginePolicy {
        forced: Some(Tactic::Relocation),
        ..EnginePolicy::default()
    };
    if current {
        engine::plan_with_emission_after_and_current_placement(
            &request,
            &predecessor,
            &allocation,
            policy,
        )
    } else {
        engine::plan_with_emission_after_and_long_t3_ownership(
            &request,
            &predecessor,
            &allocation,
            policy,
        )
    }
}

#[test]
fn current_placement_preserves_seed_emits_once_and_keeps_real_extent_failure() {
    use crate::search::{RefusalClass, SearchDomain};
    let old = current_placement_mask_fixture(1905890, &[], false).unwrap();
    let same = current_placement_mask_fixture(1905890, &[], true).unwrap();
    assert_eq!(same.source_steps(), old.source_steps());
    assert_eq!(same.images().next().unwrap().address(), 102569179);
    assert_eq!(
        same.images().next().unwrap().bytes(),
        old.images().next().unwrap().bytes()
    );
    let occupied = [AddressRange::new(112996315 & !4095, 4096).unwrap()];
    let lower = current_placement_mask_fixture(12333056, &occupied, true).unwrap();
    let image = lower.images().next().unwrap();
    assert_eq!(image.address() % 4096, 219);
    assert!(image.bytes().len() <= 4096 - 219);
    assert!(!occupied[0].contains(image.address()));
    assert!(!lower.qualification_complete());
    for plan in [&same, &lower] {
        let ArtifactMetrics::Engine(
            Tactic::Relocation,
            engine::SelectedMetrics::Single(metrics),
            attempts,
        ) = plan.metrics()
        else {
            panic!("single B1 metrics")
        };
        assert_eq!(metrics.allocation_attempts, 1);
        assert_eq!(plan.images().count(), 1);
        let runs: Vec<_> = attempts[0]
            .search
            .runs
            .iter()
            .filter(|run| run.domain == SearchDomain::SelectedImages)
            .collect();
        assert_eq!(runs.len(), 1);
        assert_eq!((runs[0].limit, runs[0].examined), (1, 1));
    }
    // A geometrically available seed remains selected. Its real image needs
    // more than 37 remaining bytes: no second target is tried after emission.
    let failed = current_placement_mask_fixture(12333056, &[], true).unwrap_err();
    assert_eq!(failed.attempts.len(), 1);
    let runs: Vec<_> = failed.attempts[0]
        .search
        .runs
        .iter()
        .filter(|run| run.domain == SearchDomain::SelectedImages)
        .collect();
    assert_eq!(runs.len(), 1);
    assert_eq!((runs[0].limit, runs[0].examined), (1, 1));
    assert!(
        failed.attempts[0]
            .search
            .refusals
            .iter()
            .any(|r| r.class == RefusalClass::ResourceCapacity)
    );
}

#[test]
fn current_placement_uses_authenticated_pun_suffix_and_keeps_negative_window_refusal() {
    use crate::search::SearchDomain;
    let pc = 11289;
    let code = [0x89, 0xc0, 0xb8, 42, 0, 0, 0, 0xc3];
    let source = AddressRange::new(pc, code.len()).unwrap();
    let entries = LegalEntrySet {
        identity: identity(),
        scope: source,
        provenance: EntryProvenance::Declared(
            "original MOV/MOV/RET; synthetic suffix edit only".into(),
        ),
        completeness: EntryCompleteness::AllInstructionHeads,
        entries: [0, 2, 7]
            .map(|offset| LegalEntry {
                address: pc + offset,
                requires_endbr: false,
            })
            .to_vec(),
        resumes: ResumeObligation::NoneExist,
    };
    let allocation = AllocationPolicy {
        ranges: vec![AddressRange::new(262144, 2147483648 - 262144).unwrap()],
        preferred_address: Some(544978791),
        max_candidates: 1,
        max_mappings: 1,
        max_mapped_bytes: 4096,
    };
    let emission = ArtifactEmission::new(
        TargetProfile::linux_x86_64_legacy_evex(
            SavedExtendedStateLayout::describe_target_fxsave64(),
            7,
        )
        .unwrap(),
        SymbolicHook {
            identity: 11,
            address: Some(pc + 0x1000),
        },
        vec![AddressRange::new(pc & !4095, 4096).unwrap()],
    );
    let request = ArtifactRequest {
        site: PlanningSite {
            identity: identity(),
            code: &code,
            base_address: pc,
            function: source,
            block: source,
            logical_pc: pc,
            entries: &entries,
            semantics: HookSemantics::Observe,
            allocation: &allocation,
            search: SearchPolicy {
                max_upstream_bytes: 0,
                max_sites: 1,
                ..SearchPolicy::default()
            },
        },
        emission: &emission,
    };
    for (suffix, positive) in [
        ([0xe9, 0x10, 0xe9, 0x22], true),
        ([0xe9, 0xe0, 0xa3, 0xbb], false),
    ] {
        let mut predecessor = Composition::new(
            identity(),
            vec![ExpectedBytes {
                address: pc,
                bytes: code.to_vec(),
            }],
        )
        .unwrap();
        // Checked synthetic composition setup, not a semantic/native claim.
        let edit = PatchPlan::checked(PlanParts {
            identity: identity(),
            profile: ApplicationProfile::InstallOnce,
            kind: PlanKind::Relocation,
            logical_pc: pc + 2,
            physical_pc: pc + 2,
            displaced: AddressRange::new(pc + 2, 4).unwrap(),
            reads: predecessor.final_bytes().to_vec(),
            writes: vec![ByteEdit {
                address: pc + 2,
                bytes: suffix.to_vec(),
            }],
            dependencies: vec![source],
            entries: LegalEntrySet {
                completeness: EntryCompleteness::Complete,
                entries: vec![],
                ..entries.clone()
            },
            obligations: vec![],
            allocations: vec![],
            generated: vec![],
            requirements: PublicationRequirements {
                quiescent: true,
                sync_core: true,
                sigill_router: false,
            },
        })
        .unwrap();
        predecessor.append(&edit).unwrap();
        let saved = predecessor.clone();
        let result = engine::plan_with_emission_after_and_current_placement(
            &request,
            &predecessor,
            &allocation,
            EnginePolicy {
                forced: Some(Tactic::PrefixedPun),
                ..EnginePolicy::default()
            },
        );
        if positive {
            let plan = result.unwrap();
            assert_eq!(plan.images().next().unwrap().address(), 585710856);
            let PlanKind::PrefixedPun(pun) = &plan.source_steps()[0].parts().kind else {
                panic!("T1")
            };
            assert_eq!(pun.target_window, AddressRange::new(585710856, 1).unwrap());
            assert_eq!(
                plan.source_steps()[0].parts().reads,
                predecessor.final_bytes()
            );
            let mut composed = predecessor.clone();
            for step in plan.source_steps() {
                composed.append(step).unwrap();
            }
        } else {
            let failed = result.unwrap_err();
            assert_eq!(failed.reason, Refusal::AllocationUnavailable);
            assert_eq!(failed.attempts.len(), 1);
            assert!(
                failed.attempts[0]
                    .search
                    .runs
                    .iter()
                    .all(|run| run.domain != SearchDomain::SelectedImages)
            );
        }
        assert_eq!(predecessor, saved);
    }
}

#[test]
fn current_placement_keeps_successor_and_neighbor_placement_literal() {
    for tactic in [Tactic::SuccessorEviction, Tactic::NeighborEviction] {
        let mut fixture = Fixture::new(tactic);
        fixture.selected.max_candidates = 1;
        fixture.selected.max_mapped_bytes = 4096;
        let predecessor = fixture.predecessor();
        let request = fixture.request(HookSemantics::Observe);
        let old = engine::plan_with_emission_after_and_long_t3_ownership(
            &request,
            &predecessor,
            &fixture.victim,
            fixture.policy(),
        )
        .unwrap();
        let new = engine::plan_with_emission_after_and_current_placement(
            &request,
            &predecessor,
            &fixture.victim,
            fixture.policy(),
        )
        .unwrap();
        assert_eq!(new.source_steps(), old.source_steps());
        assert_eq!(
            new.images()
                .map(|i| (i.address(), i.bytes().to_vec()))
                .collect::<Vec<_>>(),
            old.images()
                .map(|i| (i.address(), i.bytes().to_vec()))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            format!("{:?}", new.metrics()),
            format!("{:?}", old.metrics())
        );
        assert_current_steps(&fixture, &predecessor, &new);
    }
}

#[test]
fn current_placement_generalized_pun_preserves_seed_and_uses_remaining_page_once() {
    use crate::search::{RefusalClass, SearchDomain};
    let mut fixture = Fixture::new(Tactic::GeneralizedPun);
    fixture.selected.max_candidates = 1;
    fixture.selected.max_mapped_bytes = 4096;
    let predecessor = fixture.predecessor();
    let saved = predecessor.clone();
    let seed = fixture.selected.preferred_address.unwrap();
    let seed_page = AddressRange::new(seed & !4095, 4096).unwrap();
    let remaining_page = AddressRange::new(seed_page.end(), 4096).unwrap();
    assert_eq!(seed % 4096, 0x85);
    assert_eq!(
        fixture.selected.ranges,
        [AddressRange::new(seed_page.start(), 8192).unwrap()]
    );
    let window = AddressRange::new(S + 5 + 0x2ab8_0000, 1 << 16).unwrap();
    let old = engine::plan_with_emission_after_and_long_t3_ownership(
        &fixture.request(HookSemantics::Observe),
        &predecessor,
        &fixture.victim,
        fixture.policy(),
    )
    .unwrap();
    let same = engine::plan_with_emission_after_and_current_placement(
        &fixture.request(HookSemantics::Observe),
        &predecessor,
        &fixture.victim,
        fixture.policy(),
    )
    .unwrap();
    assert_eq!(same.source_steps(), old.source_steps());
    assert_eq!(same.images().next().unwrap().address(), seed);
    assert_eq!(
        same.images().next().unwrap().bytes(),
        old.images().next().unwrap().bytes()
    );
    assert_eq!(
        format!("{:?}", same.metrics()),
        format!("{:?}", old.metrics())
    );

    let mut occupied = fixture.emission.occupied().to_vec();
    occupied.push(seed_page);
    fixture.emission = ArtifactEmission::new(
        fixture.emission.profile().clone(),
        fixture.emission.hook(),
        occupied,
    );
    let blocked = engine::plan_with_emission_after_and_long_t3_ownership(
        &fixture.request(HookSemantics::Observe),
        &predecessor,
        &fixture.victim,
        fixture.policy(),
    )
    .unwrap_err();
    assert_eq!(blocked.reason, Refusal::AllocationUnavailable);
    assert_eq!(blocked.attempts.len(), 1);
    assert_eq!(blocked.attempts[0].tactic, Tactic::GeneralizedPun);
    assert!(
        blocked.attempts[0]
            .search
            .refusals
            .iter()
            .any(|r| r.class == RefusalClass::AddressPolicy)
    );
    let blocked_runs: Vec<_> = blocked.attempts[0]
        .search
        .runs
        .iter()
        .filter(|run| run.domain == SearchDomain::SelectedImages)
        .collect();
    assert_eq!(blocked_runs.len(), 1);
    assert_eq!((blocked_runs[0].limit, blocked_runs[0].examined), (1, 1));
    let fallback = engine::plan_with_emission_after_and_current_placement(
        &fixture.request(HookSemantics::Observe),
        &predecessor,
        &fixture.victim,
        fixture.policy(),
    )
    .unwrap();
    assert_eq!(
        fallback.images().next().unwrap().address(),
        remaining_page.start()
    );
    for (plan, page) in [
        (&old, seed_page),
        (&same, seed_page),
        (&fallback, remaining_page),
    ] {
        assert_current_steps(&fixture, &predecessor, plan);
        let ArtifactMetrics::Engine(
            Tactic::GeneralizedPun,
            engine::SelectedMetrics::Single(metrics),
            attempts,
        ) = plan.metrics()
        else {
            panic!("single B2 metrics")
        };
        assert_eq!(metrics.allocation_attempts, 1);
        assert_eq!(attempts.len(), 1);
        let runs: Vec<_> = attempts[0]
            .search
            .runs
            .iter()
            .filter(|run| run.domain == SearchDomain::SelectedImages)
            .collect();
        assert_eq!(runs.len(), 1);
        assert_eq!((runs[0].limit, runs[0].examined), (1, 1));
        assert_eq!(plan.images().count(), 1);
        let image = plan.images().next().unwrap();
        assert!(!image.bytes().is_empty());
        assert!(page.covers(AddressRange::new(image.address(), image.bytes().len()).unwrap()));
        assert!(window.contains(image.address()));
        let parts = plan.source_steps()[0].parts();
        let PlanKind::GeneralizedPun(pun) = &parts.kind else {
            panic!("B2")
        };
        assert_eq!(pun.target_window, window);
        assert_eq!(parts.displaced, AddressRange::new(S, 3).unwrap());
        assert_eq!(pun.consumed, AddressRange::new(S, 5).unwrap());
        assert_eq!(
            parts.allocations,
            [AllocationRequest {
                range: page,
                alignment: 4096
            }]
        );
        assert_eq!(pun.store.address, S);
        assert_eq!(pun.store.bytes.len(), 4);
        assert_eq!(pun.store.bytes[3], 0xb8);
        assert_eq!(&parts.reads[0].bytes[19..], &fixture.code[19..]);
        let mut composed = predecessor.clone();
        composed.append(&plan.source_steps()[0]).unwrap();
        assert_eq!(&composed.final_bytes()[0].bytes[..16], &fixture.code[..16]);
        assert_eq!(&composed.final_bytes()[0].bytes[19..], &fixture.code[19..]);
    }
    assert!(!seed_page.overlaps(remaining_page));
    assert_eq!(predecessor, saved);
}
