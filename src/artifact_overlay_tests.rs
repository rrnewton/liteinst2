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
