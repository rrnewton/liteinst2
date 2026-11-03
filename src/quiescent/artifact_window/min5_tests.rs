//! Authored source/planner controls; no generated execution or native qualification.
use super::*;
use crate::emission::{ArtifactEmission, PlanningSite, SymbolicHook, TargetProfile};
use crate::search::SearchStop;
use crate::trampoline::{ArtifactObservationWindow, PreparedArtifact, SavedExtendedStateLayout};

const BASE: u64 = 0x0040_0000;
// Authored, not a claim about the unavailable final corpus byte.
const POP_RET: [u8; 5] = [0x5b, 0x5d, 0x41, 0x5c, 0xc3];
const PCS: [u64; 3] = [BASE, BASE + 1, BASE + 2];

struct Fixture {
    code: Vec<u8>,
    entries: LegalEntrySet,
    allocation: AllocationPolicy,
    emission: ArtifactEmission,
    search: SearchPolicy,
}
impl Fixture {
    fn new(code: &[u8]) -> Self {
        let identity = CodeIdentity {
            source: SourceIdentity([43; 32]),
            mapping: 7,
            generation: 1,
        };
        Self {
            code: code.to_vec(),
            entries: LegalEntrySet {
                identity,
                scope: AddressRange::new(BASE, code.len()).unwrap(),
                provenance: EntryProvenance::Declared("minimum-window geometry control".into()),
                completeness: EntryCompleteness::AllInstructionHeads,
                entries: vec![LegalEntry {
                    address: BASE,
                    requires_endbr: false,
                }],
                resumes: ResumeObligation::NoneExist,
            },
            allocation: AllocationPolicy {
                ranges: vec![AddressRange::new(0x0100_0000, 0x1f00_0000).unwrap()],
                preferred_address: None,
                max_candidates: 1,
                max_mappings: 1,
                max_mapped_bytes: 4096,
            },
            emission: Self::emission(Some(BASE + 4096)),
            search: SearchPolicy {
                tactics: TacticPolicy::RelocationOnly,
                max_upstream_bytes: 64,
                max_displaced_bytes: 256,
                max_sites: 64,
            },
        }
    }
    fn emission(address: Option<u64>) -> ArtifactEmission {
        ArtifactEmission::new(
            TargetProfile::linux_x86_64_legacy_evex(
                SavedExtendedStateLayout::describe_target_fxsave64(),
                7,
            )
            .unwrap(),
            SymbolicHook {
                identity: 23,
                address,
            },
            vec![],
        )
    }
    fn artifact(&self) -> ArtifactRequest<'_> {
        ArtifactRequest {
            site: PlanningSite {
                identity: self.entries.identity,
                code: &self.code,
                base_address: BASE,
                function: self.entries.scope,
                block: self.entries.scope,
                logical_pc: BASE,
                entries: &self.entries,
                semantics: HookSemantics::Observe,
                allocation: &self.allocation,
                search: self.search,
            },
            emission: &self.emission,
        }
    }
    fn predecessor(&self) -> Composition {
        Composition::new(
            self.entries.identity,
            vec![ExpectedBytes {
                address: BASE,
                bytes: self.code.clone(),
            }],
        )
        .unwrap()
    }
    fn seal(&self, pcs: &[u64]) -> Result<ArtifactObservationWindowSeal, PlanningFailure> {
        seal_artifact_observation_window_min5(&self.artifact(), pcs)
    }
    fn plan(
        &self,
        seal: &ArtifactObservationWindowSeal,
        predecessor: &Composition,
        pending: &[AddressRange],
    ) -> Result<ArtifactObservationPlan, PlanningFailure> {
        seal.matches_request(&self.artifact(), seal.observation_pcs())
            .unwrap();
        plan_artifact_observation_window_upstream_after(
            &ArtifactObservationSearchRequest {
                artifact: self.artifact(),
                end: seal.retained_span().end(),
                observation_pcs: seal.observation_pcs(),
            },
            predecessor,
            pending,
        )
    }
}
fn no_search(failure: &PlanningFailure, expected: Refusal) {
    assert_eq!(failure.reason, expected);
    assert!(failure.attempts.is_empty());
    assert!(failure.search.runs.is_empty());
    assert!(!failure.search.accepted);
    assert!(!failure.search.classification_complete);
}

#[test]
fn seal_stops_at_first_whole_end_without_conflating_selected_and_retained_spans() {
    for (bytes, pcs, selected, retained) in [
        (vec![0x5b, 0x5d, 0x41, 0x5c, 0xc3, 0x90], PCS.to_vec(), 4, 5),
        // The unselected LEA crosses the fifth byte; do not cut it or take the NOP.
        (
            vec![0x5b, 0x5d, 0x41, 0x5c, 0x48, 0x8d, 0x40, 0, 0x90],
            PCS.to_vec(),
            4,
            8,
        ),
        // A sufficient selected interval must not absorb the following RET.
        (
            vec![0x5b, 0x5d, 0x90, 0x41, 0x5c, 0xc3],
            vec![BASE, BASE + 1, BASE + 3],
            5,
            5,
        ),
    ] {
        let f = Fixture::new(&bytes);
        let seal = f.seal(&pcs).unwrap();
        assert_eq!(
            seal.selected_span(),
            AddressRange::new(BASE, selected).unwrap()
        );
        assert_eq!(
            seal.retained_span(),
            AddressRange::new(BASE, retained).unwrap()
        );
        assert_eq!(seal.observation_pcs(), pcs);
        assert_eq!(seal.original_bytes.as_ref(), &bytes[..retained]);
        assert_eq!(seal.matches_request(&f.artifact(), &pcs), Ok(()));
    }
}

#[test]
fn final_unselected_ret_uses_existing_encoder_routes_mask_and_continuation() {
    let f = Fixture::new(&POP_RET);
    let old = plan_artifact_observation_window_upstream_after(
        &ArtifactObservationSearchRequest {
            artifact: f.artifact(),
            end: BASE + 4,
            observation_pcs: &PCS,
        },
        &f.predecessor(),
        &[],
    )
    .unwrap_err();
    assert_eq!(old.reason, Refusal::NoPatchWindow);
    assert_eq!(old.attempts.len(), 1);
    let seal = f.seal(&PCS).unwrap();
    let before = f.predecessor();
    let group = f.plan(&seal, &before, &[]).unwrap();
    assert_eq!(before, f.predecessor());
    assert_eq!(group.observation_pcs(), PCS);
    assert_eq!(group.artifact().source_steps().len(), 1);
    assert_eq!(group.artifact().images().count(), 1);
    assert_eq!(
        group
            .search()
            .runs
            .iter()
            .map(|r| (r.domain, r.examined, r.stop))
            .collect::<Vec<_>>(),
        [
            (SearchDomain::PhysicalSites, 1, SearchStop::Accepted),
            (SearchDomain::SelectedImages, 1, SearchStop::Accepted),
        ]
    );
    let parts = group.artifact().source_steps()[0].parts();
    assert_eq!(parts.displaced, AddressRange::new(BASE, 5).unwrap());
    assert_eq!(
        parts.reads,
        [ExpectedBytes {
            address: BASE,
            bytes: POP_RET.to_vec()
        }]
    );
    assert_eq!(parts.allocations.len(), 1);
    assert_eq!(parts.allocations[0].range.len(), 4096);
    let image = group.artifact().images().next().unwrap();
    let heads = [BASE, BASE + 1, BASE + 2, BASE + 4];
    assert_eq!(
        image.entry_routes().iter().map(|r| r.0).collect::<Vec<_>>(),
        heads
    );
    assert_eq!(
        image
            .instruction_boundaries()
            .iter()
            .map(|r| r.0)
            .collect::<Vec<_>>(),
        heads
    );
    for (&(pc, entry), &(body_pc, body)) in image
        .entry_routes()
        .iter()
        .zip(image.instruction_boundaries())
    {
        assert_eq!(pc, body_pc);
        if pc == BASE + 4 {
            assert_eq!(entry, body);
        } else {
            assert!(entry < body);
        }
        assert!(
            image
                .program_counter_mappings()
                .iter()
                .any(|m| m.translate(body) == Some(pc))
        );
    }
    assert_eq!(
        image
            .metadata()
            .fields()
            .iter()
            .filter(|f| f.role == "LogicalPc")
            .map(|f| f.target)
            .collect::<Vec<_>>(),
        PCS.map(i128::from)
    );
    assert_eq!(
        image
            .metadata()
            .fields()
            .iter()
            .filter(|f| f.role == "HookCall")
            .map(|f| f.target)
            .collect::<Vec<_>>(),
        [i128::from(BASE + 4096); 3]
    );
    let ret = image.instruction_boundaries()[3].1;
    let decoded = crate::x86::decode64(ret, &image.bytes()[(ret - image.address()) as usize..]);
    assert_eq!(decoded.instruction.code(), iced_x86::Code::Retnq);
    assert_eq!(decoded.instruction.len(), 1);
    let return_pc = image.address() + image.bytes().len() as u64 - 5;
    let jump = crate::x86::decode64(return_pc, &image.bytes()[image.bytes().len() - 5..]);
    assert_eq!(jump.instruction.code(), iced_x86::Code::Jmp_rel32_64);
    assert_eq!(jump.instruction.near_branch_target(), BASE + 5);
    // All heads, including unselected RET at+4, constrain the source E9.
    let scan = InstructionScanner::default().scan(&POP_RET, BASE).unwrap();
    let window = ArtifactObservationWindow::checked(&scan, BASE, BASE + 5, &PCS).unwrap();
    let prepared = PreparedArtifact::for_observation_window(&window, &f.emission).unwrap();
    let target = BASE + 5 + 0x0601_0606;
    assert!(prepared.size_bound() <= 4096 - (target % 4096) as usize);
    assert_eq!(
        candidate_target(BASE, [true, true, false, true], None, 0),
        Some(target)
    );
    assert_eq!(image.address(), target);
    assert!(image.bytes().len() <= prepared.size_bound());
    assert_eq!(&parts.writes[0].bytes[..5], &[0xe9, 0x06, 0x06, 0x01, 0x06]);
    assert!(
        parts.allocations[0]
            .range
            .covers(AddressRange::new(image.address(), image.bytes().len()).unwrap())
    );
    assert!(!group.artifact().qualification_complete());
}

#[test]
fn owned_seal_joins_exact_geometry_identity_bytes_and_supplied_population() {
    let seal = {
        let temporary = Fixture::new(&POP_RET);
        temporary.seal(&PCS).unwrap()
    };
    // Entry/hook/source storage from construction is gone; only bounded data survived.
    let f = Fixture::new(&POP_RET);
    assert_eq!(seal.matches_request(&f.artifact(), &PCS), Ok(()));
    for pcs in [
        vec![],
        vec![BASE, BASE + 2],
        vec![BASE, BASE + 1, BASE + 2, BASE + 4],
        vec![BASE, BASE + 2, BASE + 1],
    ] {
        assert_eq!(
            seal.matches_request(&f.artifact(), &pcs),
            Err(Refusal::InvalidPlan)
        );
    }
    for identity in [
        CodeIdentity {
            source: SourceIdentity([44; 32]),
            ..f.entries.identity
        },
        CodeIdentity {
            mapping: 8,
            ..f.entries.identity
        },
        CodeIdentity {
            generation: 2,
            ..f.entries.identity
        },
    ] {
        let mut request = f.artifact();
        request.site.identity = identity;
        assert_eq!(
            seal.matches_request(&request, &PCS),
            Err(Refusal::StaleGeneration)
        );
    }
    let mut request = f.artifact();
    request.site.block = AddressRange::new(BASE, 4).unwrap();
    assert_eq!(
        seal.matches_request(&request, &PCS),
        Err(Refusal::InvalidRange)
    );
    let mut request = f.artifact();
    request.site.function = AddressRange::new(BASE, 4).unwrap();
    assert_eq!(
        seal.matches_request(&request, &PCS),
        Err(Refusal::InvalidRange)
    );
    let mut request = f.artifact();
    request.site.base_address += 1;
    assert_eq!(
        seal.matches_request(&request, &PCS),
        Err(Refusal::InvalidRange)
    );
    let mut request = f.artifact();
    request.site.logical_pc += 1;
    assert_eq!(
        seal.matches_request(&request, &PCS),
        Err(Refusal::InvalidRange)
    );
    let mut request = f.artifact();
    request.site.search.max_displaced_bytes = 255;
    assert_eq!(
        seal.matches_request(&request, &PCS),
        Err(Refusal::InvalidPlan)
    );
    let mut changed = Fixture::new(&POP_RET);
    changed.code[4] = 0x90;
    assert_eq!(
        seal.matches_request(&changed.artifact(), &PCS),
        Err(Refusal::ExpectedBytesChanged)
    );
    // Geometry cannot infer selection completeness: a different ordered subset
    // may itself seal, but cannot replay the original seal's supplied PC list.
    assert!(f.seal(&[BASE, BASE + 2]).is_ok());
}

#[test]
fn source_and_population_failures_precede_collection_without_search_credit() {
    let f = Fixture::new(&POP_RET);
    for (pcs, expected) in [
        (vec![], Refusal::InvalidPlan),
        (vec![BASE, BASE], Refusal::InvalidPlan),
        (vec![BASE + 1, BASE + 2], Refusal::InvalidPlan),
        (vec![BASE, BASE + 3], Refusal::NotInstructionHead),
        (vec![BASE, BASE + 5], Refusal::InvalidRange),
    ] {
        no_search(&f.seal(&pcs).unwrap_err(), expected);
    }
    let mut request = f.artifact();
    request.site.identity.generation += 1;
    let failure = seal_artifact_observation_window_min5(&request, &[]).unwrap_err();
    no_search(&failure, Refusal::StaleGeneration);
    assert_eq!(failure.search.refusals[0].reason, Refusal::StaleGeneration);
    let mut incomplete = Fixture::new(&POP_RET);
    incomplete.entries.completeness = EntryCompleteness::Complete;
    no_search(
        &incomplete.seal(&PCS).unwrap_err(),
        Refusal::UnresolvedEntry,
    );
    incomplete.entries.completeness = EntryCompleteness::AllInstructionHeads;
    incomplete.search.tactics = TacticPolicy::PreferGeneralizedPun;
    no_search(
        &incomplete.seal(&PCS).unwrap_err(),
        Refusal::UnsupportedSemantics(
            "artifact observation window requires explicit relocation-only policy".into(),
        ),
    );
    let mut request = f.artifact();
    request.site.semantics = HookSemantics::ReplaceFirst;
    no_search(
        &seal_artifact_observation_window_min5(&request, &PCS).unwrap_err(),
        Refusal::UnsupportedSemantics(
            "artifact observation window requires observing hooks".into(),
        ),
    );
    let truncated = Fixture::new(&[0x5b, 0x5d, 0x41]);
    no_search(
        &truncated.seal(&[BASE]).unwrap_err(),
        Refusal::Backend("invalid x86-64 instruction at 0x400002 (region offset 2)".into()),
    );
}

#[test]
fn block_and_displacement_bounds_keep_original_qualifier_precedence() {
    let f = Fixture::new(&POP_RET);
    let mut request = f.artifact();
    request.site.block = AddressRange::new(BASE, 4).unwrap();
    let failure = seal_artifact_observation_window_min5(&request, &PCS).unwrap_err();
    no_search(&failure, Refusal::NoPatchWindow);
    assert_eq!(
        failure.search.refusals.last().unwrap().reason,
        Refusal::NoPatchWindow
    );
    let mut short_bound = Fixture::new(&POP_RET);
    short_bound.search.max_displaced_bytes = 4;
    no_search(&short_bound.seal(&PCS).unwrap_err(), Refusal::NoPatchWindow);
    let mut call = Fixture::new(&[0x5b, 0x5d, 0x41, 0x5c, 0xe8, 0, 0, 0, 0]);
    call.search.max_displaced_bytes = 8;
    no_search(&call.seal(&PCS).unwrap_err(), Refusal::NoPatchWindow);
    call.search.max_displaced_bytes = 9;
    no_search(
        &call.seal(&PCS).unwrap_err(),
        Refusal::UnsupportedSemantics("Call has no qualified A1 relocation contract".into()),
    );
    let early_ret = Fixture::new(&[0x5b, 0xc3, 0x90, 0x90, 0x5d]);
    no_search(
        &early_ret.seal(&[BASE, BASE + 4]).unwrap_err(),
        Refusal::UnsupportedSemantics("control transfer before displaced end".into()),
    );
    let mut bytes = vec![0x90; 257];
    bytes[0] = 0x5b;
    bytes[255] = 0x5d;
    bytes[256] = 0x5e;
    let f = Fixture::new(&bytes);
    let seal = f.seal(&[BASE, BASE + 255]).unwrap();
    assert_eq!(seal.selected_span(), AddressRange::new(BASE, 256).unwrap());
    assert_eq!(seal.retained_span(), seal.selected_span());
    assert_eq!(seal.original_bytes.len(), 256);
    no_search(
        &f.seal(&[BASE, BASE + 256]).unwrap_err(),
        Refusal::NoPatchWindow,
    );
}

#[test]
fn seal_does_not_bypass_current_overlay_pending_or_terminal_entry_checks() {
    let mut f = Fixture::new(&POP_RET);
    let seal = f.seal(&PCS).unwrap();
    let original = f.predecessor();
    let group = f.plan(&seal, &original, &[]).unwrap();
    let mut current = original.clone();
    current.append(&group.artifact().source_steps()[0]).unwrap();
    let snapshot = current.clone();
    assert_eq!(seal.matches_request(&f.artifact(), &PCS), Ok(()));
    let failure = f.plan(&seal, &current, &[]).unwrap_err();
    assert_eq!(failure.reason, Refusal::ExpectedBytesChanged);
    assert_eq!(failure.attempts.len(), 1);
    assert_eq!(current, snapshot);
    let mut different = POP_RET;
    different[4] = 0x90;
    let wrong_original = Composition::new(
        f.entries.identity,
        vec![ExpectedBytes {
            address: BASE,
            bytes: different.to_vec(),
        }],
    )
    .unwrap();
    no_search(
        &f.plan(&seal, &wrong_original, &[]).unwrap_err(),
        Refusal::ExpectedBytesChanged,
    );
    let failure = f
        .plan(&seal, &original, &[AddressRange::new(BASE + 4, 1).unwrap()])
        .unwrap_err();
    assert_eq!(failure.reason, Refusal::OwnershipConflict);
    assert_eq!(failure.attempts.len(), 1);
    assert!(!failure.search.accepted);
    assert_eq!(original, f.predecessor());
    f.entries.entries.push(LegalEntry {
        address: BASE + 4,
        requires_endbr: true,
    });
    assert_eq!(seal.matches_request(&f.artifact(), &PCS), Ok(()));
    assert_eq!(
        f.plan(&seal, &original, &[]).unwrap_err().reason,
        Refusal::UnsupportedSemantics("CET IBT landing pad in displaced range".into())
    );
}

#[test]
fn seal_is_not_a_physical_budget_fitting_or_hook_binding_success() {
    let mut f = Fixture::new(&POP_RET);
    f.search.max_sites = 0;
    let seal = f.seal(&PCS).unwrap();
    let failure = f.plan(&seal, &f.predecessor(), &[]).unwrap_err();
    assert_eq!(failure.reason, Refusal::NoPatchWindow);
    assert!(failure.attempts.is_empty());
    assert_eq!(failure.search.runs.len(), 1);
    assert_eq!(
        failure.search.runs[0].stop,
        SearchStop::BudgetLimited {
            remaining_at_least: 1
        }
    );
    f.search.max_sites = 64;
    f.allocation.max_candidates = 2;
    no_search(
        &f.plan(&seal, &f.predecessor(), &[]).unwrap_err(),
        Refusal::InvalidRange,
    );
    f.allocation.max_candidates = 1;
    f.emission = Fixture::emission(None);
    let failure = f.plan(&seal, &f.predecessor(), &[]).unwrap_err();
    assert_eq!(
        failure.reason,
        Refusal::Backend("artifact TargetBinding: UnresolvedSymbol(23)".into())
    );
    assert_eq!(failure.attempts.len(), 1);
    let large = Fixture::new(&[0x58; 32]);
    let pcs: Vec<_> = (0..32).map(|i| BASE + i).collect();
    let seal = large.seal(&pcs).unwrap();
    let scan = InstructionScanner::default()
        .scan(&large.code, BASE)
        .unwrap();
    let window = ArtifactObservationWindow::checked(&scan, BASE, BASE + 32, &pcs).unwrap();
    let prepared = PreparedArtifact::for_observation_window(&window, &large.emission).unwrap();
    assert!(prepared.size_bound() > 4096);
    let failure = large.plan(&seal, &large.predecessor(), &[]).unwrap_err();
    assert_eq!(failure.reason, Refusal::AllocationUnavailable);
    assert_eq!(failure.attempts.len(), 1);
    assert_eq!(failure.search.runs.len(), 1);
    assert!(!failure.search.accepted);
}
