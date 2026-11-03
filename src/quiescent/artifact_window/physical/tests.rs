//! Authored geometry and actual shared-planner controls; no native execution.
use super::*;
use crate::emission::{ArtifactEmission, PlanningSite, SymbolicHook, TargetProfile};
use crate::search::SearchStop;
use crate::trampoline::{ArtifactObservationWindow, PreparedArtifact, SavedExtendedStateLayout};

const BASE: u64 = 0x0040_0000;
const P: u64 = BASE + 0x8f5;
const SHORT: [u8; 5] = [0x66, 0x90, 0x5b, 0x5d, 0xc3];

struct Fixture {
    base: u64,
    code: Vec<u8>,
    entries: LegalEntrySet,
    allocation: AllocationPolicy,
    emission: ArtifactEmission,
    search: SearchPolicy,
}
impl Fixture {
    fn new(base: u64, code: &[u8]) -> Self {
        let identity = CodeIdentity {
            source: SourceIdentity([73; 32]),
            mapping: 7,
            generation: 1,
        };
        Self {
            base,
            code: code.to_vec(),
            entries: LegalEntrySet {
                identity,
                scope: AddressRange::new(base, code.len()).unwrap(),
                provenance: EntryProvenance::Declared("physical-window control".into()),
                completeness: EntryCompleteness::AllInstructionHeads,
                entries: vec![LegalEntry {
                    address: base,
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
            emission: Self::emission(Some(base + 4096)),
            search: SearchPolicy {
                tactics: TacticPolicy::RelocationOnly,
                max_upstream_bytes: 64,
                max_displaced_bytes: 256,
                max_sites: 64,
            },
        }
    }
    fn short() -> Self {
        let mut f = Self::new(P, &SHORT);
        f.allocation.ranges = vec![AddressRange::new(0x0646_0000, 8192).unwrap()];
        f
    }
    fn emission(address: Option<u64>) -> ArtifactEmission {
        ArtifactEmission::new(
            TargetProfile::linux_x86_64_legacy_evex(
                SavedExtendedStateLayout::describe_target_fxsave64(),
                7,
            )
            .unwrap(),
            SymbolicHook {
                identity: 73,
                address,
            },
            vec![],
        )
    }
    fn artifact(&self, logical: u64) -> ArtifactRequest<'_> {
        ArtifactRequest {
            site: PlanningSite {
                identity: self.entries.identity,
                code: &self.code,
                base_address: self.base,
                function: self.entries.scope,
                block: self.entries.scope,
                logical_pc: logical,
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
                address: self.base,
                bytes: self.code.clone(),
            }],
        )
        .unwrap()
    }
    fn seal(&self, pcs: &[u64]) -> ArtifactPhysicalWindowSchedule {
        seal_artifact_observation_windows_upstream_min5(&self.artifact(pcs[0]), pcs).unwrap()
    }
    fn plan(
        &self,
        seal: &ArtifactPhysicalWindowSchedule,
        prior: &Composition,
        pending: &[AddressRange],
        placement: ArtifactRelocationPlacement,
    ) -> Result<ArtifactObservationPlan, PlanningFailure> {
        plan_artifact_observation_windows_upstream_after_with_placement(
            &self.artifact(seal.selected_span().start()),
            seal,
            prior,
            pending,
            placement,
        )
    }
}
fn no_search(failed: &PlanningFailure, reason: Refusal) {
    assert_eq!(failed.reason, reason);
    assert!(failed.attempts.is_empty());
    assert!(failed.search.runs.is_empty());
    assert!(!failed.search.accepted);
    assert!(!failed.search.classification_complete);
}

#[test]
fn earlier_physical_head_recovers_short_span_with_actual_alphabet_image_and_all_routes() {
    let f = Fixture::short();
    let pcs = [P + 2, P + 3];
    let prior = f.predecessor();
    let old = seal_artifact_observation_window_min5(&f.artifact(pcs[0]), &pcs).unwrap_err();
    no_search(&old, Refusal::NoPatchWindow);
    let seal = f.seal(&pcs);
    assert_eq!(seal.selected_span(), AddressRange::new(P + 2, 2).unwrap());
    assert_eq!(seal.physical_domain(), [P + 2, P]);
    assert_eq!(seal.rows().len(), 2);
    assert_eq!(seal.rows()[0].outcome(), Err(&Refusal::NoPatchWindow));
    assert_eq!(seal.rows()[1].outcome(), Ok(P + 5));
    assert_eq!(
        seal.source_dependency(),
        Some((f.entries.scope, SHORT.as_slice()))
    );
    assert_eq!(seal.rows()[0].qualification().len(), 1);
    assert!(seal.rows()[1].qualification().is_empty());
    let scan = InstructionScanner::default().scan(&SHORT, P).unwrap();
    let window = ArtifactObservationWindow::checked(&scan, P, P + 5, &pcs).unwrap();
    let prepared = PreparedArtifact::for_observation_window(&window, &f.emission).unwrap();
    let bound = prepared.size_bound();
    assert!(262 < bound && bound <= 4096);
    assert_eq!(
        crate::emission::placement::fitting_for_relocation(
            &f.allocation,
            P,
            [false, true, true, true],
            &[],
            f.entries.scope,
            bound
        )
        .unwrap_err(),
        Refusal::AllocationUnavailable
    );
    let fixed = f
        .plan(&seal, &prior, &[], ArtifactRelocationPlacement::Fixed06)
        .unwrap_err();
    assert_eq!(fixed.reason, Refusal::AllocationUnavailable);
    assert_eq!(fixed.attempts.len(), 2);
    let group = f
        .plan(
            &seal,
            &prior,
            &[],
            ArtifactRelocationPlacement::EntryAlphabetV1,
        )
        .unwrap();
    assert_eq!(group.observation_pcs(), pcs);
    assert_eq!(group.artifact().source_steps().len(), 1);
    assert_eq!(group.artifact().images().count(), 1);
    let parts = group.artifact().source_steps()[0].parts();
    assert_eq!(
        (parts.logical_pc, parts.physical_pc, parts.displaced),
        (P + 2, P, AddressRange::new(P, 5).unwrap())
    );
    assert_eq!(
        parts.reads,
        [ExpectedBytes {
            address: P,
            bytes: SHORT.to_vec()
        }]
    );
    assert_eq!(parts.writes.len(), 1);
    assert_eq!(parts.writes[0].bytes, [0xe9, 0x06, 0x07, 0x06, 0x06]);
    let image = group.artifact().images().next().unwrap();
    assert_eq!(image.address(), 0x0646_1000);
    assert!(image.bytes().len() <= bound);
    assert_eq!(parts.allocations.len(), 1);
    assert_eq!(
        parts.allocations[0].range,
        AddressRange::new(image.address(), 4096).unwrap()
    );
    let heads = [P, P + 2, P + 3, P + 4];
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
        if pcs.contains(&pc) {
            assert!(entry < body);
        } else {
            assert_eq!(entry, body);
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
        pcs.map(i128::from)
    );
    assert_eq!(
        image
            .metadata()
            .fields()
            .iter()
            .filter(|f| f.role == "HookCall")
            .map(|f| f.target)
            .collect::<Vec<_>>(),
        [i128::from(P + 4096); 2]
    );
    let ret = image.instruction_boundaries()[3].1;
    assert_eq!(
        crate::x86::decode64(ret, &image.bytes()[(ret - image.address()) as usize..])
            .instruction
            .code(),
        iced_x86::Code::Retnq
    );
    let tail = image.address() + image.bytes().len() as u64 - 5;
    assert_eq!(
        crate::x86::decode64(tail, &image.bytes()[image.bytes().len() - 5..])
            .instruction
            .near_branch_target(),
        P + 5
    );
    assert_eq!(
        group
            .search()
            .runs
            .iter()
            .map(|r| (r.domain, r.limit, r.examined, r.stop))
            .collect::<Vec<_>>(),
        [
            (SearchDomain::PhysicalSites, 64, 2, SearchStop::Accepted),
            (SearchDomain::SelectedImages, 1, 1, SearchStop::Accepted)
        ]
    );
    assert_eq!(group.search().runs[0].finite_total, Some(2));
    assert_eq!(group.search().runs[1].finite_total, None);
    assert_eq!(group.search().runs[1].candidates, None);
    assert_eq!(group.search().refusals, seal.rows()[0].qualification());
    assert_eq!(prior, f.predecessor());
    assert!(!group.artifact().qualification_complete());
}

#[test]
fn refused_call_suffix_is_custodied_and_qualified_once_without_retained_authority() {
    let bytes = [0x48, 0x8d, 0x00, 0x5b, 0x5d, 0xe8, 0, 0, 0, 0];
    let pcs = [BASE + 3, BASE + 4];
    let f = Fixture::new(BASE, &bytes);
    let seal = f.seal(&pcs);
    let reason =
        Refusal::UnsupportedSemantics("Call has no qualified A1 relocation contract".into());
    assert_eq!(seal.physical_domain(), [BASE + 3, BASE]);
    assert_eq!(seal.rows()[0].outcome(), Err(&reason));
    assert_eq!(seal.rows()[1].outcome(), Ok(BASE + 5));
    assert_eq!(
        seal.source_dependency(),
        Some((f.entries.scope, bytes.as_slice()))
    );
    assert_eq!(seal.rows()[0].qualification().len(), 1);
    assert_eq!(seal.rows()[0].qualification()[0].reason, reason);
    let group = f
        .plan(
            &seal,
            &f.predecessor(),
            &[],
            ArtifactRelocationPlacement::Fixed06,
        )
        .unwrap();
    assert_eq!(group.artifact().source_steps().len(), 1);
    let parts = group.artifact().source_steps()[0].parts();
    assert_eq!(parts.displaced, AddressRange::new(BASE, 5).unwrap());
    // The shared emitter guards the complete source snapshot. Read dependency
    // is distinct from displacement: the refused CALL must remain unmodified
    // and absent from the generated instruction boundaries.
    assert_eq!(
        parts.reads,
        [ExpectedBytes {
            address: BASE,
            bytes: bytes.to_vec()
        }]
    );
    assert_eq!(parts.dependencies, [f.entries.scope]);
    assert_eq!(parts.writes.len(), 1);
    assert_eq!(parts.writes[0].address, BASE);
    assert_eq!(parts.writes[0].bytes.len(), 5);
    assert_eq!(group.artifact().images().count(), 1);
    let image = group.artifact().images().next().unwrap();
    assert_eq!(
        image
            .instruction_boundaries()
            .iter()
            .map(|entry| entry.0)
            .collect::<Vec<_>>(),
        [BASE, BASE + 3, BASE + 4]
    );
    let tail = image.address() + image.bytes().len() as u64 - 5;
    assert_eq!(
        crate::x86::decode64(tail, &image.bytes()[image.bytes().len() - 5..])
            .instruction
            .near_branch_target(),
        BASE + 5
    );
    assert_eq!(group.search().refusals, seal.rows()[0].qualification());
    assert_eq!(group.search().runs[0].examined, 2);
    let mut changed = Fixture::new(BASE, &bytes);
    changed.code[9] = 1; // CALL immediate changes, heads and precise refusal do not.
    let fresh = changed.seal(&pcs);
    assert_eq!(fresh.rows()[0].outcome(), seal.rows()[0].outcome());
    assert_eq!(
        fresh.rows()[0].qualification(),
        seal.rows()[0].qualification()
    );
    assert_eq!(fresh.rows()[1].outcome(), seal.rows()[1].outcome());
    assert_eq!(
        seal.matches_request(&changed.artifact(pcs[0]), &pcs),
        Err(Refusal::ExpectedBytesChanged)
    );
    no_search(
        &changed
            .plan(
                &seal,
                &changed.predecessor(),
                &[],
                ArtifactRelocationPlacement::Fixed06,
            )
            .unwrap_err(),
        Refusal::ExpectedBytesChanged,
    );
}

#[test]
fn cap_start_fifteen_byte_dependency_keeps_one_sixty_four_of_sixty_five_run() {
    let mut code = vec![0x90; 320];
    code.extend_from_slice(&[0x66; 14]);
    code.push(0x90);
    let pcs = [BASE + 64, BASE + 320];
    let mut f = Fixture::new(BASE, &code);
    let seal = f.seal(&pcs);
    let mut expected = vec![BASE + 64];
    expected.extend((0..=56).rev().map(|n| BASE + n));
    expected.extend((57..=63).rev().map(|n| BASE + n));
    assert_eq!(seal.physical_domain(), expected);
    assert_eq!(seal.rows().len(), 64);
    assert_eq!(seal.physical_domain()[64], BASE + 57);
    assert_eq!(
        seal.source_dependency(),
        Some((AddressRange::new(BASE, 335).unwrap(), code.as_slice()))
    );
    for (ordinal, row) in seal.rows().iter().enumerate() {
        assert_eq!(
            (row.ordinal(), row.physical_pc()),
            (ordinal, expected[ordinal])
        );
        assert_eq!(row.outcome(), Err(&Refusal::NoPatchWindow));
        assert_eq!(row.qualification().len(), 1);
    }
    let failed = f
        .plan(
            &seal,
            &f.predecessor(),
            &[],
            ArtifactRelocationPlacement::EntryAlphabetV1,
        )
        .unwrap_err();
    assert_eq!(failed.reason, Refusal::NoPatchWindow);
    assert_eq!(failed.attempts.len(), 64);
    assert_eq!(failed.search.refusals.len(), 64);
    assert_eq!(failed.search.runs.len(), 1);
    let run = &failed.search.runs[0];
    assert_eq!(
        (
            run.domain,
            run.limit,
            run.examined,
            run.finite_total,
            run.stop
        ),
        (
            SearchDomain::PhysicalSites,
            64,
            64,
            Some(65),
            SearchStop::BudgetLimited {
                remaining_at_least: 1
            }
        )
    );
    assert!(!failed.search.accepted);
    f.search.max_sites = 0;
    let zero = f.seal(&pcs);
    assert_eq!(zero.physical_domain(), expected);
    assert!(zero.rows().is_empty());
    assert_eq!(zero.source_dependency(), None);
    let failed = f
        .plan(
            &zero,
            &f.predecessor(),
            &[],
            ArtifactRelocationPlacement::EntryAlphabetV1,
        )
        .unwrap_err();
    assert_eq!(failed.reason, Refusal::NoPatchWindow);
    assert!(failed.attempts.is_empty());
    assert!(failed.search.refusals.is_empty());
    assert_eq!(failed.search.runs.len(), 1);
    assert_eq!(
        (failed.search.runs[0].examined, failed.search.runs[0].stop),
        (
            0,
            SearchStop::BudgetLimited {
                remaining_at_least: 65
            }
        )
    );
}

#[test]
fn owned_schedule_binds_source_policy_population_and_domain_without_borrowed_authority() {
    let pcs = [P + 2, P + 3];
    let seal = {
        let temporary = Fixture::short();
        temporary.seal(&pcs)
    };
    let f = Fixture::short();
    assert_eq!(seal.matches_request(&f.artifact(pcs[0]), &pcs), Ok(()));
    for wrong in [
        vec![],
        vec![P + 2],
        vec![P + 2, P + 3, P + 4],
        vec![P + 3, P + 2],
    ] {
        assert_eq!(
            seal.matches_request(&f.artifact(pcs[0]), &wrong),
            Err(Refusal::InvalidPlan)
        );
    }
    // This valid subset can have its own geometry: FULL selection is not inferred.
    assert!(seal_artifact_observation_windows_upstream_min5(&f.artifact(P + 2), &[P + 2]).is_ok());
    for field in 0..3 {
        let mut input = f.artifact(pcs[0]);
        match field {
            0 => input.site.identity.source = SourceIdentity([74; 32]),
            1 => input.site.identity.mapping += 1,
            2 => input.site.identity.generation += 1,
            _ => unreachable!(),
        }
        assert_eq!(
            seal.matches_request(&input, &pcs),
            Err(Refusal::StaleGeneration)
        );
    }
    for field in 0..4 {
        let mut input = f.artifact(pcs[0]);
        match field {
            0 => input.site.base_address += 1,
            1 => input.site.function = AddressRange::new(P, 4).unwrap(),
            2 => input.site.block = AddressRange::new(P, 4).unwrap(),
            3 => input.site.logical_pc += 1,
            _ => unreachable!(),
        }
        assert_eq!(
            seal.matches_request(&input, &pcs),
            Err(Refusal::InvalidRange)
        );
    }
    for field in 0..4 {
        let mut input = f.artifact(pcs[0]);
        match field {
            0 => input.site.search.max_upstream_bytes -= 1,
            1 => input.site.search.max_displaced_bytes -= 1,
            2 => input.site.search.max_sites -= 1,
            3 => input.site.search.tactics = TacticPolicy::PreferGeneralizedPun,
            _ => unreachable!(),
        }
        assert_eq!(
            seal.matches_request(&input, &pcs),
            Err(Refusal::InvalidPlan)
        );
    }
    for field in 0..5 {
        let mut changed = seal.clone();
        match field {
            0 => changed.domain.swap(0, 1),
            1 => changed.rows = changed.rows[..1].to_vec().into_boxed_slice(),
            2 => changed.rows[0].ordinal = 1,
            3 => changed.rows[0].physical_pc = P,
            4 => changed.selected = AddressRange::new(P + 2, 3).unwrap(),
            _ => unreachable!(),
        }
        no_search(
            &f.plan(
                &changed,
                &f.predecessor(),
                &[],
                ArtifactRelocationPlacement::EntryAlphabetV1,
            )
            .unwrap_err(),
            Refusal::InvalidPlan,
        );
    }
    assert!(
        f.plan(
            &seal,
            &f.predecessor(),
            &[],
            ArtifactRelocationPlacement::EntryAlphabetV1
        )
        .is_ok()
    );
}

#[test]
fn reached_row_mismatch_aborts_instead_of_skipping_or_double_counting() {
    let f = Fixture::short();
    let seal = f.seal(&[P + 2, P + 3]);
    for field in 0..3 {
        let mut changed = seal.clone();
        match field {
            0 => changed.rows[0].outcome = Ok(P + 5),
            1 => changed.rows[0].outcome = Err(Refusal::OwnershipConflict),
            2 => changed.rows[0].qualification = Box::new([]),
            _ => unreachable!(),
        }
        let failed = f
            .plan(
                &changed,
                &f.predecessor(),
                &[],
                ArtifactRelocationPlacement::EntryAlphabetV1,
            )
            .unwrap_err();
        assert_eq!(failed.reason, Refusal::InvalidPlan);
        assert!(failed.attempts.is_empty());
        assert_eq!(failed.search.runs.len(), 1);
        assert_eq!(
            (failed.search.runs[0].examined, failed.search.runs[0].stop),
            (1, SearchStop::Interrupted)
        );
        assert_eq!(failed.search.refusals, seal.rows()[0].qualification());
    }
    let mut changed = seal.clone();
    changed.rows[1].outcome = Ok(P + 4);
    let failed = f
        .plan(
            &changed,
            &f.predecessor(),
            &[],
            ArtifactRelocationPlacement::EntryAlphabetV1,
        )
        .unwrap_err();
    assert_eq!(failed.reason, Refusal::InvalidPlan);
    assert_eq!(failed.attempts.len(), 1);
    assert_eq!(failed.attempts[0].refusal, Some(Refusal::NoPatchWindow));
    assert_eq!(failed.search.runs.len(), 1);
    assert_eq!(
        (failed.search.runs[0].examined, failed.search.runs[0].stop),
        (2, SearchStop::Interrupted)
    );
    assert_eq!(failed.search.refusals, seal.rows()[0].qualification());
}

#[test]
fn fixed06_same_extent_preserves_complete_existing_plan_and_failure_results() {
    let bytes = [0x5b, 0x5d, 0x41, 0x5c, 0xc3];
    for base in [BASE, P] {
        let mut f = Fixture::new(base, &bytes);
        let pcs = [base, base + 1, base + 2];
        if base == P {
            f.allocation.ranges = vec![AddressRange::new(0x0640_0000, 8192).unwrap()];
        }
        let seal = f.seal(&pcs);
        let prior = f.predecessor();
        let old = plan_artifact_observation_window_upstream_after(
            &ArtifactObservationSearchRequest {
                artifact: f.artifact(base),
                end: base + 5,
                observation_pcs: &pcs,
            },
            &prior,
            &[],
        );
        let new = f.plan(&seal, &prior, &[], ArtifactRelocationPlacement::Fixed06);
        assert_eq!(format!("{old:?}"), format!("{new:?}"));
        let scan = InstructionScanner::default().scan(&bytes, base).unwrap();
        let window = ArtifactObservationWindow::checked(&scan, base, base + 5, &pcs).unwrap();
        let bound = PreparedArtifact::for_observation_window(&window, &f.emission)
            .unwrap()
            .size_bound();
        assert!(256 < bound && bound <= 4096);
        if base == BASE {
            let group = new.unwrap();
            let target = BASE + 5 + 0x0601_0606;
            assert_eq!(group.artifact().images().next().unwrap().address(), target);
            assert!(bound <= 4096 - (target % 4096) as usize);
        } else {
            assert_eq!((base + 5 + 0x0601_0606) % 4096, 0xf00);
            assert_eq!(new.unwrap_err().reason, Refusal::AllocationUnavailable);
        }
        assert_eq!(prior, f.predecessor());
    }
}

#[test]
fn fresh_overlay_entry_pending_and_image_errors_keep_shared_order_and_atomicity() {
    let mut f = Fixture::short();
    let pcs = [P + 2, P + 3];
    let seal = f.seal(&pcs);
    let prior = f.predecessor();
    let group = f
        .plan(
            &seal,
            &prior,
            &[],
            ArtifactRelocationPlacement::EntryAlphabetV1,
        )
        .unwrap();
    let mut changed = prior.clone();
    changed.append(&group.artifact().source_steps()[0]).unwrap();
    let snapshot = changed.clone();
    assert_eq!(
        f.plan(
            &seal,
            &changed,
            &[],
            ArtifactRelocationPlacement::EntryAlphabetV1
        )
        .unwrap_err()
        .reason,
        Refusal::ExpectedBytesChanged
    );
    assert_eq!(changed, snapshot);
    let pending = [AddressRange::new(P + 4, 1).unwrap()];
    let failed = f
        .plan(
            &seal,
            &prior,
            &pending,
            ArtifactRelocationPlacement::EntryAlphabetV1,
        )
        .unwrap_err();
    assert_eq!(failed.reason, Refusal::OwnershipConflict);
    assert_eq!(failed.attempts.len(), 2);
    assert_eq!(failed.search.runs.len(), 2);
    assert_eq!(failed.search.runs[1].stop, SearchStop::Accepted);
    assert_eq!(failed.search.runs[1].examined, 1);
    assert_eq!(failed.search.runs[1].candidates, None);
    assert!(!failed.search.accepted);
    assert_eq!(prior, f.predecessor());
    f.entries.entries.push(LegalEntry {
        address: P + 4,
        requires_endbr: true,
    });
    assert_eq!(
        f.plan(
            &seal,
            &prior,
            &[],
            ArtifactRelocationPlacement::EntryAlphabetV1
        )
        .unwrap_err()
        .reason,
        Refusal::UnsupportedSemantics("CET IBT landing pad in displaced range".into())
    );
    f.entries.entries.pop();
    f.emission = Fixture::emission(None);
    let failed = f
        .plan(
            &seal,
            &prior,
            &[],
            ArtifactRelocationPlacement::EntryAlphabetV1,
        )
        .unwrap_err();
    assert_eq!(
        failed.reason,
        Refusal::Backend("artifact TargetBinding: UnresolvedSymbol(73)".into())
    );
    assert_eq!(failed.search.runs.len(), 2);
    assert_eq!(
        (
            failed.search.runs[1].domain,
            failed.search.runs[1].examined,
            failed.search.runs[1].stop
        ),
        (
            SearchDomain::SelectedImages,
            1,
            SearchStop::UnclassifiedBoundedStop
        )
    );
    assert_eq!(failed.search.runs[1].candidates, None);
    f.allocation.max_candidates = 2;
    let mut mismatched = seal.clone();
    mismatched.domain.swap(0, 1);
    no_search(
        &f.plan(
            &mismatched,
            &prior,
            &[],
            ArtifactRelocationPlacement::EntryAlphabetV1,
        )
        .unwrap_err(),
        Refusal::InvalidRange,
    );
}

#[test]
fn immutable_global_guards_and_collector_early_breaks_keep_exact_dependencies() {
    let mut f = Fixture::new(BASE, &[0x5b, 0x5d, 0x41, 0x5c, 0xc3, 0x90]);
    let pcs = [BASE, BASE + 1, BASE + 2];
    let seal = f.seal(&pcs);
    assert_eq!(
        seal.source_dependency(),
        Some((AddressRange::new(BASE, 5).unwrap(), &f.code[..5]))
    );
    let mut input = f.artifact(BASE);
    input.site.block = AddressRange::new(BASE, 4).unwrap();
    let stopped = seal_artifact_observation_windows_upstream_min5(&input, &pcs).unwrap();
    assert_eq!(stopped.rows()[0].outcome(), Err(&Refusal::NoPatchWindow));
    assert_eq!(
        stopped.source_dependency(),
        Some((AddressRange::new(BASE, 4).unwrap(), &f.code[..4]))
    );
    let mut input = f.artifact(BASE);
    input.site.identity.generation += 1;
    no_search(
        &seal_artifact_observation_windows_upstream_min5(&input, &[]).unwrap_err(),
        Refusal::StaleGeneration,
    );
    for (supplied, reason) in [
        (vec![], Refusal::InvalidPlan),
        (vec![BASE, BASE], Refusal::InvalidPlan),
        (vec![BASE, BASE + 3], Refusal::NotInstructionHead),
        (vec![BASE, BASE + 6], Refusal::InvalidRange),
    ] {
        no_search(
            &seal_artifact_observation_windows_upstream_min5(&f.artifact(BASE), &supplied)
                .unwrap_err(),
            reason,
        );
    }
    f.entries.completeness = EntryCompleteness::Complete;
    no_search(
        &seal_artifact_observation_windows_upstream_min5(&f.artifact(BASE), &pcs).unwrap_err(),
        Refusal::UnresolvedEntry,
    );
    f.entries.completeness = EntryCompleteness::AllInstructionHeads;
    f.search.tactics = TacticPolicy::PreferGeneralizedPun;
    no_search(
        &seal_artifact_observation_windows_upstream_min5(&f.artifact(BASE), &pcs).unwrap_err(),
        Refusal::UnsupportedSemantics(
            "artifact observation window requires explicit relocation-only policy".into(),
        ),
    );
    f.search.tactics = TacticPolicy::RelocationOnly;
    let mut input = f.artifact(BASE);
    input.site.semantics = HookSemantics::ReplaceFirst;
    no_search(
        &seal_artifact_observation_windows_upstream_min5(&input, &pcs).unwrap_err(),
        Refusal::UnsupportedSemantics(
            "artifact observation window requires observing hooks".into(),
        ),
    );
    f.search.max_displaced_bytes = 4;
    let bounded = f.seal(&pcs);
    assert_eq!(bounded.rows()[0].outcome(), Err(&Refusal::NoPatchWindow));
    assert_eq!(
        bounded.source_dependency(),
        Some((AddressRange::new(BASE, 5).unwrap(), &f.code[..5]))
    );
    let transfer = Fixture::new(BASE, &[0xeb, 0x00, 0x5b, 0x5d, 0xc3]);
    let refused = transfer.seal(&[BASE + 2, BASE + 3]);
    assert_eq!(refused.rows()[0].outcome(), Err(&Refusal::NoPatchWindow));
    assert_eq!(
        refused.rows()[1].outcome(),
        Err(&Refusal::UnsupportedSemantics(
            "control transfer before displaced end".into()
        ))
    );
}

// A complete selected group in an eight-byte block, followed by a distinct
// pending block. All source bytes remain authenticated even when only eight
// bytes are displaced. The interior suffix contains selected and unselected
// heads, while the four E9 displacement heads remain constrained by placement.
fn routed_suffix_artifact(f: &Fixture) -> ArtifactRequest<'_> {
    let mut input = f.artifact(f.base);
    input.site.block = AddressRange::new(f.base, 8).unwrap();
    input
}

fn routed_suffix_plan(
    input: &ArtifactRequest<'_>,
    schedule: &ArtifactPhysicalWindowSchedule,
    prior: &Composition,
    pending: &[AddressRange],
    placement: ArtifactRelocationPlacement,
    suffix: ArtifactRoutedSuffix,
) -> Result<ArtifactObservationPlan, PlanningFailure> {
    plan_artifact_observation_windows_upstream_after_with_placement_and_suffix(
        input, schedule, prior, pending, placement, suffix,
    )
}

fn assert_suffix_images_equal(left: &ArtifactObservationPlan, right: &ArtifactObservationPlan) {
    assert_eq!(left.artifact().images().count(), 1);
    assert_eq!(right.artifact().images().count(), 1);
    let left_image = left.artifact().images().next().unwrap();
    let right_image = right.artifact().images().next().unwrap();
    assert_eq!(left_image.address(), right_image.address());
    assert_eq!(left_image.bytes(), right_image.bytes());
    assert_eq!(left_image.entry_routes(), right_image.entry_routes());
    assert_eq!(
        left_image.instruction_boundaries(),
        right_image.instruction_boundaries()
    );
    assert_eq!(
        left_image.program_counter_mappings(),
        right_image.program_counter_mappings()
    );
    assert_eq!(left_image.metadata(), right_image.metadata());
    assert_eq!(left.observation_pcs(), right.observation_pcs());
    assert_eq!(left.search(), right.search());
    assert!(!left.artifact().qualification_complete());
    assert!(!right.artifact().qualification_complete());
}

#[test]
fn single_byte_suffix_preserves_exact_plan_and_releases_only_real_fetch_footprint() {
    let f = Fixture::new(BASE, &[0x90; 32]);
    let input = routed_suffix_artifact(&f);
    let pcs = [BASE, BASE + 7];
    let schedule = seal_artifact_observation_windows_upstream_min5(&input, &pcs).unwrap();
    assert_eq!(schedule.physical_domain(), [BASE]);
    assert_eq!(schedule.rows()[0].outcome(), Ok(BASE + 8));
    let prior = f.predecessor();
    let pending = [AddressRange::new(BASE + 8, 1).unwrap()];
    assert_eq!(prior.require_unclaimed_ranges(&pending), Ok(()));
    for placement in [
        ArtifactRelocationPlacement::Fixed06,
        ArtifactRelocationPlacement::EntryAlphabetV1,
    ] {
        let default = plan_artifact_observation_windows_upstream_after_with_placement(
            &input,
            &schedule,
            &prior,
            &[],
            placement,
        )
        .unwrap();
        let explicit = routed_suffix_plan(
            &input,
            &schedule,
            &prior,
            &[],
            placement,
            ArtifactRoutedSuffix::Qualified62,
        )
        .unwrap();
        assert_eq!(
            default.artifact().source_steps(),
            explicit.artifact().source_steps()
        );
        assert_suffix_images_equal(&default, &explicit);
        let old_step = &default.artifact().source_steps()[0];
        let old_parts = old_step.parts();
        assert_eq!(default.artifact().source_steps().len(), 1);
        assert_eq!(old_parts.displaced, AddressRange::new(BASE, 8).unwrap());
        assert_eq!(
            old_parts.reads,
            [ExpectedBytes {
                address: BASE,
                bytes: f.code.clone()
            }]
        );
        assert_eq!(old_parts.dependencies, [f.entries.scope]);
        assert_eq!(old_parts.writes.len(), 1);
        assert_eq!(old_parts.writes[0].address, BASE);
        assert_eq!(
            old_parts.writes[0].bytes,
            [0xe9, 0x06, 0x06, 0x06, 0x06, 0x62, 0x62, 0x62]
        );
        let mut old_joined = prior.clone();
        old_joined.append(old_step).unwrap();
        // Three actual 0x62 heads retain all 15 bytes; the last ends at +22.
        assert_eq!(old_joined.locks(), [AddressRange::new(BASE, 22).unwrap()]);
        assert_eq!(
            old_joined.require_unclaimed_ranges(&pending),
            Err(Refusal::OwnershipConflict)
        );
        let refused = routed_suffix_plan(
            &input,
            &schedule,
            &prior,
            &pending,
            placement,
            ArtifactRoutedSuffix::Qualified62,
        )
        .unwrap_err();
        assert_eq!(refused.reason, Refusal::OwnershipConflict);
        assert_eq!(refused.attempts.len(), 1);
        assert_eq!(refused.attempts[0].physical_pc, BASE);
        assert_eq!(
            refused.attempts[0].refusal,
            Some(Refusal::OwnershipConflict)
        );
        assert_eq!(refused.search.runs.len(), 2);
        assert_eq!(refused.search.runs[0].stop, SearchStop::DomainComplete);
        assert_eq!(refused.search.runs[0].examined, 1);
        assert_eq!(refused.search.runs[1].stop, SearchStop::Accepted);
        assert_eq!(refused.search.runs[1].examined, 1);
        assert!(!refused.search.accepted);
        let single = routed_suffix_plan(
            &input,
            &schedule,
            &prior,
            &pending,
            placement,
            ArtifactRoutedSuffix::SingleByte60,
        )
        .unwrap();
        let mut expected = old_parts.clone();
        expected.writes[0].bytes[5..8].copy_from_slice(&[0x60; 3]);
        assert_eq!(single.artifact().source_steps().len(), 1);
        assert_eq!(single.artifact().source_steps()[0].parts(), &expected);
        assert_suffix_images_equal(&default, &single);
        let mut joined = prior.clone();
        joined.append(&single.artifact().source_steps()[0]).unwrap();
        assert_eq!(joined.locks(), [AddressRange::new(BASE, 8).unwrap()]);
        assert_eq!(joined.require_unclaimed_ranges(&pending), Ok(()));
        assert_eq!(&joined.final_bytes()[0].bytes[8..], &f.code[8..]);
        assert_eq!(pending, [AddressRange::new(BASE + 8, 1).unwrap()]);
        assert_eq!(prior, f.predecessor());
    }
}

#[test]
fn single_byte_suffix_never_exempts_true_overlap_or_already_claimed_pending() {
    let f = Fixture::new(BASE, &[0x90; 32]);
    let input = routed_suffix_artifact(&f);
    let pcs = [BASE, BASE + 7];
    let schedule = seal_artifact_observation_windows_upstream_min5(&input, &pcs).unwrap();
    let prior = f.predecessor();
    for suffix in [
        ArtifactRoutedSuffix::Qualified62,
        ArtifactRoutedSuffix::SingleByte60,
    ] {
        for offset in [0, 4, 5, 7] {
            let pending = [AddressRange::new(BASE + offset, 1).unwrap()];
            let refused = routed_suffix_plan(
                &input,
                &schedule,
                &prior,
                &pending,
                ArtifactRelocationPlacement::EntryAlphabetV1,
                suffix,
            )
            .unwrap_err();
            assert_eq!(refused.reason, Refusal::OwnershipConflict);
            assert_eq!(refused.attempts.len(), 1);
            assert_eq!(
                refused.attempts[0].refusal,
                Some(Refusal::OwnershipConflict)
            );
            assert_eq!(refused.search.runs[1].stop, SearchStop::Accepted);
            assert_eq!(prior, f.predecessor());
        }
    }
    let mut upper = f.artifact(BASE + 8);
    upper.site.block = AddressRange::new(BASE + 8, 8).unwrap();
    let upper_schedule =
        seal_artifact_observation_windows_upstream_min5(&upper, &[BASE + 8, BASE + 15]).unwrap();
    let upper_group = routed_suffix_plan(
        &upper,
        &upper_schedule,
        &prior,
        &[],
        ArtifactRelocationPlacement::EntryAlphabetV1,
        ArtifactRoutedSuffix::SingleByte60,
    )
    .unwrap();
    let mut claimed = prior.clone();
    claimed
        .append(&upper_group.artifact().source_steps()[0])
        .unwrap();
    let before = claimed.clone();
    let pending = [AddressRange::new(BASE + 8, 1).unwrap()];
    for suffix in [
        ArtifactRoutedSuffix::Qualified62,
        ArtifactRoutedSuffix::SingleByte60,
    ] {
        no_search(
            &routed_suffix_plan(
                &input,
                &schedule,
                &claimed,
                &pending,
                ArtifactRelocationPlacement::EntryAlphabetV1,
                suffix,
            )
            .unwrap_err(),
            Refusal::OwnershipConflict,
        );
        assert_eq!(claimed, before);
    }
}

#[test]
fn single_byte_suffix_keeps_full_source_staleness_and_coverage_guards() {
    let f = Fixture::new(BASE, &[0x90; 32]);
    let input = routed_suffix_artifact(&f);
    let schedule =
        seal_artifact_observation_windows_upstream_min5(&input, &[BASE, BASE + 7]).unwrap();
    for suffix in [
        ArtifactRoutedSuffix::Qualified62,
        ArtifactRoutedSuffix::SingleByte60,
    ] {
        // Both a changed routed suffix and a byte beyond every displaced/fetch
        // interval remain covered by the complete original-source read guard.
        for offset in [5, 31] {
            let mut stale_bytes = f.code.clone();
            stale_bytes[offset] = 0x91;
            let stale = Composition::new(
                f.entries.identity,
                vec![ExpectedBytes {
                    address: BASE,
                    bytes: stale_bytes,
                }],
            )
            .unwrap();
            let before = stale.clone();
            no_search(
                &routed_suffix_plan(
                    &input,
                    &schedule,
                    &stale,
                    &[],
                    ArtifactRelocationPlacement::EntryAlphabetV1,
                    suffix,
                )
                .unwrap_err(),
                Refusal::ExpectedBytesChanged,
            );
            assert_eq!(stale, before);
        }
        for len in [5, 8, 22, 31] {
            let short = Composition::new(
                f.entries.identity,
                vec![ExpectedBytes {
                    address: BASE,
                    bytes: f.code[..len].to_vec(),
                }],
            )
            .unwrap();
            let before = short.clone();
            no_search(
                &routed_suffix_plan(
                    &input,
                    &schedule,
                    &short,
                    &[],
                    ArtifactRelocationPlacement::EntryAlphabetV1,
                    suffix,
                )
                .unwrap_err(),
                Refusal::DependencyNotHeld,
            );
            assert_eq!(short, before);
        }
    }
}

#[test]
fn single_byte_suffix_keeps_default_fallback_and_short_window_bytes_exact() {
    assert_eq!(
        ArtifactRoutedSuffix::default(),
        ArtifactRoutedSuffix::Qualified62
    );
    // Source coverage, executable-page edge, and invalid-P1 qualification keep
    // the old fallback behavior. SingleByte60 does not change generated code.
    for (base, mut bytes) in [
        (BASE, vec![0x90; 8]),
        (BASE + 4088, vec![0x90; 32]),
        (BASE, vec![0x90; 32]),
    ] {
        if base == BASE && bytes.len() == 32 {
            bytes[9] = 0x94; // Last suffix P1 bit 2 is set: use the old fallback.
        }
        let f = Fixture::new(base, &bytes);
        let input = routed_suffix_artifact(&f);
        let schedule =
            seal_artifact_observation_windows_upstream_min5(&input, &[base, base + 7]).unwrap();
        let prior = f.predecessor();
        let default = plan_artifact_observation_windows_upstream_after_with_placement(
            &input,
            &schedule,
            &prior,
            &[],
            ArtifactRelocationPlacement::EntryAlphabetV1,
        )
        .unwrap();
        let explicit = routed_suffix_plan(
            &input,
            &schedule,
            &prior,
            &[],
            ArtifactRelocationPlacement::EntryAlphabetV1,
            ArtifactRoutedSuffix::Qualified62,
        )
        .unwrap();
        assert_eq!(
            default.artifact().source_steps(),
            explicit.artifact().source_steps()
        );
        assert_suffix_images_equal(&default, &explicit);
        assert_eq!(
            default.artifact().source_steps()[0].parts().writes[0].bytes[7],
            0x60
        );
        let single = routed_suffix_plan(
            &input,
            &schedule,
            &prior,
            &[],
            ArtifactRelocationPlacement::EntryAlphabetV1,
            ArtifactRoutedSuffix::SingleByte60,
        )
        .unwrap();
        let mut expected = default.artifact().source_steps()[0].parts().clone();
        expected.writes[0].bytes[5..8].copy_from_slice(&[0x60; 3]);
        assert_eq!(single.artifact().source_steps()[0].parts(), &expected);
        assert_suffix_images_equal(&default, &single);
    }
    let f = Fixture::short();
    let schedule = f.seal(&[P + 2, P + 3]);
    let prior = f.predecessor();
    let input = f.artifact(P + 2);
    let default = f
        .plan(
            &schedule,
            &prior,
            &[],
            ArtifactRelocationPlacement::EntryAlphabetV1,
        )
        .unwrap();
    let single = routed_suffix_plan(
        &input,
        &schedule,
        &prior,
        &[],
        ArtifactRelocationPlacement::EntryAlphabetV1,
        ArtifactRoutedSuffix::SingleByte60,
    )
    .unwrap();
    assert_eq!(
        default.artifact().source_steps(),
        single.artifact().source_steps()
    );
    assert_suffix_images_equal(&default, &single);
}
