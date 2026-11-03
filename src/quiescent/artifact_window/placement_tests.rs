//! Actual shared planner/prepared-encoder controls, never generated execution.
use super::*;
use crate::emission::{
    ArtifactEmission, EmissionContext, PlanningSite, SymbolicHook, TargetProfile,
};
use crate::search::SearchStop;
use crate::trampoline::{ArtifactObservationWindow, PreparedArtifact, SavedExtendedStateLayout};

const PC: u64 = 0x0040_08f5;
const CODE: [u8; 5] = [0x5b, 0x5d, 0x41, 0x5c, 0xc3];
const PCS: [u64; 3] = [PC, PC + 1, PC + 2];
const TARGET: u64 = 0x0640_1000;

struct Fixture {
    code: Vec<u8>,
    entries: LegalEntrySet,
    allocation: AllocationPolicy,
    emission: ArtifactEmission,
    search: SearchPolicy,
}
impl Fixture {
    fn new() -> Self {
        let identity = CodeIdentity {
            source: SourceIdentity([51; 32]),
            mapping: 7,
            generation: 1,
        };
        Self {
            code: CODE.to_vec(),
            entries: LegalEntrySet {
                identity,
                scope: AddressRange::new(PC, CODE.len()).unwrap(),
                provenance: EntryProvenance::Declared("alphabet artifact control".into()),
                completeness: EntryCompleteness::AllInstructionHeads,
                entries: vec![LegalEntry {
                    address: PC,
                    requires_endbr: false,
                }],
                resumes: ResumeObligation::NoneExist,
            },
            allocation: AllocationPolicy {
                ranges: vec![AddressRange::new(0x0640_0000, 8192).unwrap()],
                preferred_address: None,
                max_candidates: 1,
                max_mappings: 1,
                max_mapped_bytes: 4096,
            },
            emission: Self::emission(Some(PC + 4096)),
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
                identity: 31,
                address,
            },
            vec![],
        )
    }
    fn request<'a>(&'a self, pcs: &'a [u64]) -> ArtifactObservationSearchRequest<'a> {
        let source = AddressRange::new(PC, self.code.len()).unwrap();
        ArtifactObservationSearchRequest {
            artifact: ArtifactRequest {
                site: PlanningSite {
                    identity: self.entries.identity,
                    code: &self.code,
                    base_address: PC,
                    function: source,
                    block: source,
                    logical_pc: pcs[0],
                    entries: &self.entries,
                    semantics: HookSemantics::Observe,
                    allocation: &self.allocation,
                    search: self.search,
                },
                emission: &self.emission,
            },
            end: source.end(),
            observation_pcs: pcs,
        }
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
    fn plan(
        &self,
        predecessor: &Composition,
        pending: &[AddressRange],
    ) -> Result<ArtifactObservationPlan, PlanningFailure> {
        plan_artifact_observation_window_upstream_after_with_placement(
            &self.request(&PCS),
            predecessor,
            pending,
            ArtifactRelocationPlacement::EntryAlphabetV1,
        )
    }
}

#[test]
fn actual_prepared_window_uses_non06_target_with_all_entries_and_observations() {
    let f = Fixture::new();
    let original = f.predecessor();
    let scan = InstructionScanner::default().scan(&CODE, PC).unwrap();
    let window = ArtifactObservationWindow::checked(&scan, PC, PC + 5, &PCS).unwrap();
    let prepared = PreparedArtifact::for_observation_window(&window, &f.emission).unwrap();
    let bound = prepared.size_bound();
    assert!(bound > 256 && bound <= 4096);
    let mask = [true, true, false, true];
    assert!(matches!(
        crate::emission::placement::fitting_for_relocation(
            &f.allocation,
            PC,
            mask,
            &[],
            f.entries.scope,
            bound,
        ),
        Err(Refusal::AllocationUnavailable)
    ));
    let old = plan_artifact_observation_window_upstream_after(&f.request(&PCS), &original, &[])
        .unwrap_err();
    assert_eq!(old.reason, Refusal::AllocationUnavailable);
    assert_eq!(old.attempts.len(), 1);
    assert_eq!(old.search.runs.len(), 1);
    let group = f.plan(&original, &[]).unwrap();
    assert_eq!(original, f.predecessor());
    assert_eq!(group.observation_pcs(), PCS);
    assert_eq!(group.artifact().source_steps().len(), 1);
    assert_eq!(group.artifact().images().count(), 1);
    let parts = group.artifact().source_steps()[0].parts();
    let image = group.artifact().images().next().unwrap();
    assert_eq!(parts.logical_pc, PC);
    assert_eq!(parts.physical_pc, PC);
    assert_eq!(parts.displaced, f.entries.scope);
    assert_eq!(
        parts.reads,
        [ExpectedBytes {
            address: PC,
            bytes: CODE.to_vec()
        }]
    );
    assert_eq!(parts.writes.len(), 1);
    assert_eq!(parts.writes[0].bytes, [0xe9, 0x06, 0x07, 0, 0x06]);
    assert_eq!(image.address(), TARGET);
    assert!(image.bytes().len() <= bound);
    assert_eq!(parts.allocations.len(), 1);
    assert_eq!(
        parts.allocations[0].range,
        AddressRange::new(TARGET, 4096).unwrap()
    );
    assert!(
        parts.allocations[0]
            .range
            .covers(AddressRange::new(image.address(), image.bytes().len()).unwrap())
    );
    assert_eq!(
        candidate_target(PC, mask, Some(TARGET), 0),
        Some(0x0640_0f00)
    );
    let heads = [PC, PC + 1, PC + 2, PC + 4];
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
        if pc == PC + 4 {
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
        [i128::from(PC + 4096); 3]
    );
    let ret = image.instruction_boundaries()[3].1;
    assert_eq!(
        crate::x86::decode64(ret, &image.bytes()[(ret - image.address()) as usize..])
            .instruction
            .code(),
        iced_x86::Code::Retnq
    );
    let continuation = image.address() + image.bytes().len() as u64 - 5;
    assert_eq!(
        crate::x86::decode64(continuation, &image.bytes()[image.bytes().len() - 5..])
            .instruction
            .near_branch_target(),
        PC + 5
    );
    assert_eq!(
        group
            .search()
            .runs
            .iter()
            .map(|r| (r.domain, r.limit, r.examined, r.stop))
            .collect::<Vec<_>>(),
        [
            (SearchDomain::PhysicalSites, 64, 1, SearchStop::Accepted),
            (SearchDomain::SelectedImages, 1, 1, SearchStop::Accepted),
        ]
    );
    assert_eq!(group.search().runs[1].finite_total, None);
    assert_eq!(group.search().runs[1].candidates, None);
    assert!(!group.search().classification_complete);
    assert!(!group.artifact().qualification_complete());
}

#[test]
fn explicit_fixed06_is_identical_to_legacy_success_and_refusal() {
    // The original negative geometry fixes offset 0xf00 under every Fixed06
    // target, independent of arena width. Translate the positive source by
    // 0x100: next low12=0x9fa, so the unchanged transformed seed lands at offset0.
    for (pc, arena, fits) in [(PC, 0x0640_0000, false), (PC + 0x100, 0x0641_0000, true)] {
        let mut f = Fixture::new();
        let source = AddressRange::new(pc, CODE.len()).unwrap();
        f.entries.scope = source;
        f.entries.entries[0].address = pc;
        f.allocation.ranges = vec![AddressRange::new(arena, 8192).unwrap()];
        f.emission = Fixture::emission(Some(pc + 4096));
        let pcs = [pc, pc + 1, pc + 2];
        let mut input = f.request(&pcs);
        input.artifact.site.base_address = pc;
        input.artifact.site.function = source;
        input.artifact.site.block = source;
        input.end = source.end();
        let before = Composition::new(
            f.entries.identity,
            vec![ExpectedBytes {
                address: pc,
                bytes: CODE.to_vec(),
            }],
        )
        .unwrap();
        let snapshot = before.clone();
        let scan = InstructionScanner::default().scan(&CODE, pc).unwrap();
        let window = ArtifactObservationWindow::checked(&scan, pc, pc + 5, &pcs).unwrap();
        let prepared = PreparedArtifact::for_observation_window(&window, &f.emission).unwrap();
        let bound = prepared.size_bound();
        assert!(bound > 256 && bound <= 4096);
        let seed = pc + 5 + 0x0601_0606;
        assert_eq!(
            candidate_target(pc, [true, true, false, true], None, 0),
            Some(seed)
        );
        if fits {
            assert_eq!(seed, 0x0641_1000);
            assert_eq!(seed % 4096, 0);
            assert!(bound <= 4096 - (seed % 4096) as usize);
            assert!(f.allocation.ranges[0].covers(AddressRange::new(seed, 4096).unwrap()));
        } else {
            assert_eq!(seed % 4096, 0xf00);
            assert!(bound > 4096 - (seed % 4096) as usize);
        }
        let old = plan_artifact_observation_window_upstream_after(&input, &before, &[]);
        let explicit = plan_artifact_observation_window_upstream_after_with_placement(
            &input,
            &before,
            &[],
            ArtifactRelocationPlacement::Fixed06,
        );
        // Complete owned plans, image bytes/metadata, metrics and search evidence.
        assert_eq!(format!("{old:?}"), format!("{explicit:?}"));
        if fits {
            assert!(old.is_ok());
            let plan = old.unwrap();
            let image = plan.artifact().images().next().unwrap();
            assert_eq!(image.address(), seed);
            assert!(image.bytes().len() <= bound);
        } else {
            assert_eq!(old.unwrap_err().reason, Refusal::AllocationUnavailable);
        }
        assert_eq!(before, snapshot);
    }
    assert_eq!(
        ArtifactRelocationPlacement::default(),
        ArtifactRelocationPlacement::Fixed06
    );
}

#[test]
fn one_failed_encode_has_no_indexed_proof_and_append_failure_keeps_image_acceptance() {
    let mut f = Fixture::new();
    f.emission = Fixture::emission(None);
    let before = f.predecessor();
    let failed = f.plan(&before, &[]).unwrap_err();
    assert_eq!(
        failed.reason,
        Refusal::Backend("artifact TargetBinding: UnresolvedSymbol(31)".into())
    );
    assert_eq!(failed.attempts.len(), 1);
    assert_eq!(failed.search.runs.len(), 2);
    let image = &failed.search.runs[1];
    assert_eq!(
        (
            image.domain,
            image.limit,
            image.examined,
            image.finite_total,
            image.stop
        ),
        (
            SearchDomain::SelectedImages,
            1,
            1,
            None,
            SearchStop::UnclassifiedBoundedStop
        )
    );
    assert_eq!(image.candidates, None);
    assert!(!failed.search.accepted);
    assert!(!failed.search.classification_complete);
    f.emission = Fixture::emission(Some(PC + 4096));
    let pending = [AddressRange::new(PC + 4, 1).unwrap()];
    before.require_unclaimed_ranges(&pending).unwrap();
    let refused = f.plan(&before, &pending).unwrap_err();
    assert_eq!(refused.reason, Refusal::OwnershipConflict);
    assert_eq!(refused.attempts.len(), 1);
    assert_eq!(refused.search.runs.len(), 2);
    assert_eq!(refused.search.runs[1].stop, SearchStop::Accepted);
    assert_eq!(refused.search.runs[1].examined, 1);
    assert_eq!(refused.search.runs[1].candidates, None);
    assert!(!refused.search.accepted);
    assert_eq!(before, f.predecessor());
}

#[test]
fn source_entry_current_overlay_and_size_refusals_keep_original_precedence() {
    let mut f = Fixture::new();
    let before = f.predecessor();
    let first = f.plan(&before, &[]).unwrap();
    let mut changed = before.clone();
    changed.append(&first.artifact().source_steps()[0]).unwrap();
    let snapshot = changed.clone();
    f.emission = Fixture::emission(None);
    let mut request = f.request(&PCS);
    request.artifact.site.identity.generation += 1;
    let stale = plan_artifact_observation_window_upstream_after_with_placement(
        &request,
        &changed,
        &[],
        ArtifactRelocationPlacement::EntryAlphabetV1,
    )
    .unwrap_err();
    assert_eq!(stale.reason, Refusal::StaleGeneration);
    assert!(stale.search.runs.is_empty());
    assert_eq!(
        f.plan(&changed, &[]).unwrap_err().reason,
        Refusal::ExpectedBytesChanged
    );
    f.entries.entries.push(LegalEntry {
        address: PC + 1,
        requires_endbr: true,
    });
    assert_eq!(
        f.plan(&changed, &[]).unwrap_err().reason,
        Refusal::UnsupportedSemantics("CET IBT landing pad in displaced range".into())
    );
    assert_eq!(changed, snapshot);
    f.entries.entries.pop();
    f.entries.completeness = EntryCompleteness::Incomplete;
    assert_eq!(
        f.plan(&before, &[]).unwrap_err().reason,
        Refusal::UnresolvedEntry
    );
    f.entries.completeness = EntryCompleteness::AllInstructionHeads;
    f.search.max_displaced_bytes = 4;
    let bounded = f.plan(&before, &[]).unwrap_err();
    assert_eq!(bounded.reason, Refusal::NoPatchWindow);
    assert_eq!(bounded.search.runs.len(), 1);
    f.search.max_displaced_bytes = 256;
    f.search.max_sites = 0;
    let zero = f.plan(&before, &[]).unwrap_err();
    assert_eq!(zero.reason, Refusal::NoPatchWindow);
    assert!(zero.attempts.is_empty());
    assert_eq!(
        zero.search.runs[0].stop,
        SearchStop::BudgetLimited {
            remaining_at_least: 1
        }
    );
    f.allocation.max_candidates = 2;
    let policy = f.plan(&before, &[]).unwrap_err();
    assert_eq!(policy.reason, Refusal::InvalidRange);
    assert!(policy.search.runs.is_empty());
    let mut large = Fixture::new();
    large.code = vec![0x58; 32];
    large.entries.scope = AddressRange::new(PC, 32).unwrap();
    large.emission = Fixture::emission(None);
    let pcs: Vec<_> = (0..32).map(|i| PC + i).collect();
    let scan = InstructionScanner::default().scan(&large.code, PC).unwrap();
    let window = ArtifactObservationWindow::checked(&scan, PC, PC + 32, &pcs).unwrap();
    assert!(
        PreparedArtifact::for_observation_window(&window, &large.emission)
            .unwrap()
            .size_bound()
            > 4096
    );
    let refused = plan_artifact_observation_window_upstream_after_with_placement(
        &large.request(&pcs),
        &large.predecessor(),
        &[],
        ArtifactRelocationPlacement::EntryAlphabetV1,
    )
    .unwrap_err();
    assert_eq!(refused.reason, Refusal::AllocationUnavailable);
    assert_eq!(refused.attempts.len(), 1);
    assert_eq!(refused.search.runs.len(), 1);
    assert_eq!(
        refused.search.refusals.last().unwrap().class,
        RefusalClass::AddressPolicy
    );
}

#[test]
fn alphabet_authority_refuses_live_unprepared_and_mixed_control_paths() {
    unsafe extern "C" fn unused_hook(_: *mut crate::trampoline::HookContext) {}
    let f = Fixture::new();
    let input = f.request(&PCS);
    let original = PlanningRequest::artifact(&input.artifact).with_fitting_placement();
    let (source, scan) = validated_source_core(&original).unwrap();
    for mode in 0..3 {
        let mut request = original;
        let mut search = SearchEvidence::default();
        let mut window =
            collect_relocation_window(&request, &scan, PC, PC + 2, Some(PC + 5), &mut search)
                .unwrap();
        window.authority = RelocationAuthority::ArtifactObservations {
            pcs: &PCS,
            placement: ArtifactRelocationPlacement::EntryAlphabetV1,
            suffix: ArtifactRoutedSuffix::Qualified62,
        };
        let controls = match mode {
            0 => {
                request.emission = EmissionContext::Live(unused_hook);
                None
            }
            1 => {
                request.emission = EmissionContext::Artifact(&f.emission);
                None
            }
            2 => Some(CoalescedActions::Controlled(&[])),
            _ => unreachable!(),
        };
        assert_eq!(
            emit_relocation_window(
                &request,
                &scan,
                source,
                &[],
                (controls, None),
                window,
                &mut search
            )
            .unwrap_err(),
            Refusal::InvalidPlan
        );
        assert!(search.runs.is_empty());
    }
}
