//! Real planner/emitter controls; no allocation, generated execution or host probe.
use super::*;
use crate::emission::{
    ArtifactEmission, ArtifactMetrics, ArtifactRequirement, PlanningSite, SymbolicHook,
    TargetProfile,
};
use crate::search::SearchStop;
use crate::trampoline::SavedExtendedStateLayout;

const PC: u64 = 0x402f3f;
// Exact CLOSED cat [0x402f3f,0x402f4f), fixture authority a69a624e.
// POP RBX; POP RBP; XOR EAX,1; POP R12; POP R13; MOVZX EAX,AL; POP R14; POP R15.
const CAT: [u8; 16] = [
    0x5b, 0x5d, 0x83, 0xf0, 1, 0x41, 0x5c, 0x41, 0x5d, 0x0f, 0xb6, 0xc0, 0x41, 0x5e, 0x41, 0x5f,
];
const SELECTED: [u64; 6] = [PC, PC + 1, PC + 5, PC + 7, PC + 12, PC + 14];
const HEADS: [u64; 8] = [PC, PC + 1, PC + 2, PC + 5, PC + 7, PC + 9, PC + 12, PC + 14];

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
            source: SourceIdentity([17; 32]),
            mapping: 7,
            generation: 1,
        };
        Self {
            code: code.to_vec(),
            entries: LegalEntrySet {
                identity,
                scope: AddressRange::new(PC, code.len()).unwrap(),
                provenance: EntryProvenance::Declared("artifact group control".into()),
                completeness: EntryCompleteness::AllInstructionHeads,
                // The profile itself requires every decoded head, including
                // the two unselected heads absent from this explicit list.
                entries: vec![LegalEntry {
                    address: PC,
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
            emission: Self::emission(Some(PC + 4096), vec![]),
            search: SearchPolicy {
                tactics: TacticPolicy::RelocationOnly,
                max_upstream_bytes: 64,
                max_displaced_bytes: 256,
                max_sites: 64,
            },
        }
    }
    fn emission(address: Option<u64>, occupied: Vec<AddressRange>) -> ArtifactEmission {
        ArtifactEmission::new(
            TargetProfile::linux_x86_64_legacy_evex(
                SavedExtendedStateLayout::describe_target_fxsave64(),
                7,
            )
            .unwrap(),
            SymbolicHook {
                identity: 11,
                address,
            },
            occupied,
        )
    }
    fn predecessor(&self) -> Composition {
        Composition::new(
            self.entries.identity,
            vec![ExpectedBytes {
                address: PC,
                bytes: self.code.clone(),
            }],
        )
        .unwrap()
    }
    fn request<'a>(&'a self, pcs: &'a [u64], end: usize) -> ArtifactObservationRequest<'a> {
        let source = AddressRange::new(PC, self.code.len()).unwrap();
        ArtifactObservationRequest {
            artifact: ArtifactRequest {
                site: PlanningSite {
                    identity: self.entries.identity,
                    code: &self.code,
                    base_address: PC,
                    function: source,
                    block: source,
                    logical_pc: PC,
                    entries: &self.entries,
                    semantics: HookSemantics::Observe,
                    allocation: &self.allocation,
                    search: self.search,
                },
                emission: &self.emission,
            },
            physical_pc: PC,
            end: PC + end as u64,
            observation_pcs: pcs,
        }
    }
    fn plan(&self, pcs: &[u64], end: usize) -> Result<ArtifactObservationPlan, PlanningFailure> {
        plan_artifact_observation_window_after(&self.request(pcs, end), &self.predecessor(), &[])
    }
}

#[test]
fn exact_six_pop_has_one_plan_and_all_selected_and_unselected_entry_routes() {
    let f = Fixture::new(&CAT);
    let before = f.predecessor();
    let group =
        plan_artifact_observation_window_after(&f.request(&SELECTED, 16), &before, &[]).unwrap();
    assert_eq!(before, f.predecessor());
    assert_eq!(group.observation_pcs(), SELECTED);
    let artifact = group.artifact();
    assert_eq!(artifact.source_steps().len(), 1);
    assert_eq!(artifact.images().count(), 1);
    let step = &artifact.source_steps()[0];
    let parts = step.parts();
    assert_eq!(parts.kind, PlanKind::Relocation);
    assert_eq!(parts.displaced, AddressRange::new(PC, 16).unwrap());
    assert_eq!((parts.physical_pc, parts.logical_pc), (PC, PC));
    assert_eq!(
        parts.reads,
        [ExpectedBytes {
            address: PC,
            bytes: CAT.to_vec()
        }]
    );
    assert_eq!(parts.writes.len(), 1);
    assert_eq!(parts.allocations.len(), 1);
    assert_eq!(parts.allocations[0].range.len(), 4096);
    assert_eq!(parts.generated.len(), 1);
    let image = artifact.images().next().unwrap();
    assert_eq!(
        image.entry_routes().iter().map(|r| r.0).collect::<Vec<_>>(),
        HEADS
    );
    assert_eq!(
        image
            .instruction_boundaries()
            .iter()
            .map(|r| r.0)
            .collect::<Vec<_>>(),
        HEADS
    );
    for (&(pc, entry), &(body_pc, body)) in image
        .entry_routes()
        .iter()
        .zip(image.instruction_boundaries())
    {
        assert_eq!(pc, body_pc);
        if SELECTED.contains(&pc) {
            assert!(entry < body);
        } else {
            assert_eq!(entry, body);
        }
    }
    assert_eq!(
        image
            .metadata()
            .fields()
            .iter()
            .filter(|f| f.role == "LogicalPc")
            .map(|f| f.target)
            .collect::<Vec<_>>(),
        SELECTED.map(i128::from)
    );
    assert_eq!(
        image
            .metadata()
            .fields()
            .iter()
            .filter(|f| f.role == "HookCall")
            .map(|f| f.target)
            .collect::<Vec<_>>(),
        vec![i128::from(PC + 4096); 6]
    );
    let routed: Vec<_> = parts
        .obligations
        .iter()
        .filter_map(|o| match o {
            EntryObligation::Routed(route) => Some(route.original),
            _ => None,
        })
        .collect();
    assert_eq!(routed, HEADS[1..]);
    assert!(
        image
            .metadata()
            .requirements()
            .contains(&ArtifactRequirement::EntryRouterBootstrap)
    );
    assert!(!image.metadata().qualification_complete());
    assert!(!artifact.qualification_complete());
    let ArtifactMetrics::Single(metrics) = artifact.metrics() else {
        panic!("one B1 metric");
    };
    assert_eq!(metrics.allocation_attempts, 1);
    assert_eq!(metrics.displaced_bytes, 16);
    assert_eq!(metrics.attempts.len(), 1);
    assert_eq!(metrics.attempts[0].refusal, None);
    assert_eq!(&metrics.search, group.search());
    assert!(group.search().accepted);
    assert!(!group.search().classification_complete);
    assert_eq!(
        group
            .search()
            .runs
            .iter()
            .map(|r| (r.domain, r.examined, r.stop))
            .collect::<Vec<_>>(),
        [
            (SearchDomain::PhysicalSites, 1, SearchStop::Accepted),
            (SearchDomain::SelectedImages, 1, SearchStop::Accepted)
        ]
    );
    let mut composed = before;
    composed.append(step).unwrap();
    assert_ne!(composed, f.predecessor());
}

#[test]
fn outside_branch_entries_keep_both_head_kinds_and_an_internal_transfer_still_refuses() {
    let mut bytes = CAT.to_vec();
    // Outside the displaced window: JMP to unselected XOR, then JMP to selected POP R12.
    bytes.extend_from_slice(&[0xeb, 0xf0, 0xeb, 0xf1]);
    let f = Fixture::new(&bytes);
    let group = f.plan(&SELECTED, 16).unwrap();
    let routes = group
        .artifact()
        .images()
        .next()
        .unwrap()
        .entry_routes()
        .to_vec();
    assert!(routes.iter().any(|r| r.0 == PC + 2));
    assert!(routes.iter().any(|r| r.0 == PC + 5));
    // A selected conditional before the declared end is not trimmed or skipped.
    let f = Fixture::new(&[0x53, 0x75, 2, 0x31, 0xc0, 0x5b]);
    let failure = f.plan(&[PC, PC + 1, PC + 5], 6).unwrap_err();
    assert_eq!(
        failure.reason,
        Refusal::UnsupportedSemantics("control transfer before displaced end".into())
    );
    assert_eq!(failure.attempts.len(), 1);
    assert_eq!(failure.attempts[0].refusal, Some(failure.reason.clone()));
    assert!(!failure.search.accepted);
}

#[test]
fn explicit_population_and_profile_guards_refuse_before_any_physical_attempt() {
    let f = Fixture::new(&CAT);
    for (pcs, end, expected) in [
        (vec![], 16, Refusal::InvalidPlan),
        (vec![PC, PC], 16, Refusal::InvalidPlan),
        (vec![PC + 1, PC], 16, Refusal::InvalidPlan),
        (vec![PC + 1], 16, Refusal::InvalidPlan),
        (vec![PC, PC + 3], 16, Refusal::NotInstructionHead),
        (vec![PC, PC + 16], 16, Refusal::InvalidRange),
        (vec![PC], 17, Refusal::InvalidRange),
    ] {
        let failure = f.plan(&pcs, end).unwrap_err();
        assert_eq!(failure.reason, expected);
        assert!(failure.attempts.is_empty());
        assert!(failure.search.runs.is_empty());
        assert!(!failure.search.accepted);
    }
    let mut f = Fixture::new(&CAT);
    f.entries.completeness = EntryCompleteness::Complete;
    assert_eq!(
        f.plan(&SELECTED, 16).unwrap_err().reason,
        Refusal::UnresolvedEntry
    );
    f.entries.completeness = EntryCompleteness::AllInstructionHeads;
    f.search.tactics = TacticPolicy::PreferGeneralizedPun;
    assert_eq!(
        f.plan(&SELECTED, 16).unwrap_err().reason,
        Refusal::UnsupportedSemantics(
            "artifact observation window requires explicit relocation-only policy".into()
        )
    );
    f.search.tactics = TacticPolicy::RelocationOnly;
    let mut input = f.request(&SELECTED, 16);
    input.artifact.site.semantics = HookSemantics::ReplaceFirst;
    assert_eq!(
        plan_artifact_observation_window_after(&input, &f.predecessor(), &[])
            .unwrap_err()
            .reason,
        Refusal::UnsupportedSemantics(
            "artifact observation window requires observing hooks".into()
        )
    );
}

#[test]
fn identity_current_bytes_and_cet_refuse_at_their_original_stages() {
    let f = Fixture::new(&CAT);
    let before = f.predecessor();
    let mut input = f.request(&SELECTED, 16);
    input.artifact.site.identity.generation += 1;
    assert_eq!(
        plan_artifact_observation_window_after(&input, &before, &[])
            .unwrap_err()
            .reason,
        Refusal::StaleGeneration
    );
    let mut different = CAT;
    different[0] = 0x5a;
    let changed_original = Composition::new(
        f.entries.identity,
        vec![ExpectedBytes {
            address: PC,
            bytes: different.to_vec(),
        }],
    )
    .unwrap();
    assert_eq!(
        plan_artifact_observation_window_after(&f.request(&SELECTED, 16), &changed_original, &[])
            .unwrap_err()
            .reason,
        Refusal::ExpectedBytesChanged
    );
    // Real earlier plan, authenticated original bytes but a changed current overlay.
    let first = f.plan(&[PC], 5).unwrap();
    let mut changed_current = before.clone();
    changed_current
        .append(&first.artifact().source_steps()[0])
        .unwrap();
    let snapshot = changed_current.clone();
    let mut unresolved = Fixture::new(&CAT);
    unresolved.emission = Fixture::emission(None, vec![]);
    let failure = plan_artifact_observation_window_after(
        &unresolved.request(&SELECTED, 16),
        &changed_current,
        &[],
    )
    .unwrap_err();
    assert_eq!(failure.reason, Refusal::ExpectedBytesChanged);
    assert_eq!(
        failure.search.refusals.last().unwrap().reason,
        Refusal::ExpectedBytesChanged
    );
    assert_eq!(changed_current, snapshot);
    unresolved.entries.entries.push(LegalEntry {
        address: PC + 1,
        requires_endbr: true,
    });
    assert_eq!(
        plan_artifact_observation_window_after(
            &unresolved.request(&SELECTED, 16),
            &changed_current,
            &[]
        )
        .unwrap_err()
        .reason,
        Refusal::UnsupportedSemantics("CET IBT landing pad in displaced range".into())
    );
    assert_eq!(changed_current, snapshot);
}

#[test]
fn pending_outsider_is_checked_after_candidate_append_without_mutating_predecessor() {
    let f = Fixture::new(&CAT);
    let before = f.predecessor();
    // A pending unselected original instruction may not be consumed by this group.
    let outsider = AddressRange::new(PC + 2, 3).unwrap();
    before.require_unclaimed_ranges(&[outsider]).unwrap();
    let failure =
        plan_artifact_observation_window_after(&f.request(&SELECTED, 16), &before, &[outsider])
            .unwrap_err();
    assert_eq!(failure.reason, Refusal::OwnershipConflict);
    assert_eq!(failure.attempts.len(), 1);
    assert!(!failure.search.accepted);
    assert_eq!(
        failure.search.runs.last().unwrap().stop,
        SearchStop::Accepted
    );
    assert_eq!(before, f.predecessor());
    let outside = AddressRange::new(PC + 16, 1).unwrap();
    let failure =
        plan_artifact_observation_window_after(&f.request(&SELECTED, 16), &before, &[outside])
            .unwrap_err();
    assert_eq!(failure.reason, Refusal::DependencyNotHeld);
    assert!(failure.attempts.is_empty());
    let failure = plan_artifact_observation_window_after(
        &f.request(&SELECTED, 16),
        &before,
        &[AddressRange::new(PC + 5, 2).unwrap(), outsider],
    )
    .unwrap_err();
    assert_eq!(failure.reason, Refusal::InvalidRange);
    assert!(failure.attempts.is_empty());
    assert_eq!(before, f.predecessor());
}

#[test]
fn exact_end_and_displacement_bounds_precede_unchanged_call_qualification() {
    // A last CALL still has no qualified relocation contract; it is never omitted.
    let mut f = Fixture::new(&[0x53, 0xe8, 0, 0, 0, 0]);
    f.emission = Fixture::emission(None, vec![]);
    f.search.max_displaced_bytes = 5;
    let failure = f.plan(&[PC, PC + 1], 6).unwrap_err();
    assert_eq!(failure.reason, Refusal::NoPatchWindow);
    assert_eq!(
        failure.search.refusals.last().unwrap().reason,
        Refusal::NoPatchWindow
    );
    f.search.max_displaced_bytes = 6;
    assert_eq!(
        f.plan(&[PC, PC + 1], 5).unwrap_err().reason,
        Refusal::NotInstructionHead
    );
    assert_eq!(
        f.plan(&[PC, PC + 1], 6).unwrap_err().reason,
        Refusal::UnsupportedSemantics("Call has no qualified A1 relocation contract".into())
    );
}

#[test]
fn one_page_one_candidate_and_symbol_limits_remain_hard_refusals() {
    let mut f = Fixture::new(&CAT);
    f.search.max_sites = 0;
    let failure = f.plan(&SELECTED, 16).unwrap_err();
    assert_eq!(failure.reason, Refusal::NoPatchWindow);
    assert!(failure.attempts.is_empty());
    assert_eq!(
        failure.search.runs[0].stop,
        SearchStop::BudgetLimited {
            remaining_at_least: 1
        }
    );
    f.search.max_sites = 64;
    f.allocation.max_candidates = 2;
    assert_eq!(
        f.plan(&SELECTED, 16).unwrap_err().reason,
        Refusal::InvalidRange
    );
    f.allocation.max_candidates = 1;
    f.emission = Fixture::emission(Some(PC + 4096), f.allocation.ranges.clone());
    let failure = f.plan(&SELECTED, 16).unwrap_err();
    assert_eq!(failure.reason, Refusal::AllocationUnavailable);
    assert_eq!(failure.attempts.len(), 1);
    assert!(!failure.search.accepted);
    assert_eq!(
        failure.search.refusals.last().unwrap().class,
        RefusalClass::AddressPolicy
    );
    f.emission = Fixture::emission(None, vec![]);
    let failure = f.plan(&SELECTED, 16).unwrap_err();
    assert_eq!(
        failure.reason,
        Refusal::Backend("artifact TargetBinding: UnresolvedSymbol(11)".into())
    );
    assert_eq!(failure.attempts.len(), 1);
    assert_eq!(
        failure
            .search
            .runs
            .iter()
            .filter(|r| r.domain == SearchDomain::SelectedImages)
            .map(|r| r.examined)
            .collect::<Vec<_>>(),
        [1]
    );
    assert!(!failure.search.accepted);
    // Actual prepared size, not a guessed estimate: the unchanged page
    // certificate refuses before unresolved-hook final linking is attempted.
    let mut large = Fixture::new(&[0x58; 32]);
    large.emission = Fixture::emission(None, vec![]);
    let pcs: Vec<_> = (0..32).map(|i| PC + i).collect();
    let scan = InstructionScanner::default().scan(&large.code, PC).unwrap();
    let window =
        crate::trampoline::ArtifactObservationWindow::checked(&scan, PC, PC + 32, &pcs).unwrap();
    let prepared =
        crate::trampoline::PreparedArtifact::for_observation_window(&window, &large.emission)
            .unwrap();
    assert!(prepared.size_bound() > 4096);
    let failure = large.plan(&pcs, 32).unwrap_err();
    assert_eq!(failure.reason, Refusal::AllocationUnavailable);
    assert_eq!(failure.attempts.len(), 1);
    assert_eq!(failure.search.runs.len(), 1);
    assert!(!failure.search.accepted);
}
