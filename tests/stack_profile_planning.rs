#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
//! Pure source planning: no executable mappings, publication or native calls.
use liteinst2::bundle::{BundleBudget, PlannedBundle};
use liteinst2::composition::Composition;
use liteinst2::contracts::*;
use liteinst2::controls::{ControlledAction, ProbeControl};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy, plan_coalesced_detailed,
    plan_coalesced_detailed_after_with_stack_profile, plan_coalesced_detailed_with_stack_profile,
};
use liteinst2::search::SearchDomain;
use liteinst2::trampoline::{HookContext, ObservationStackProfile};

const PAGE: u64 = 0x2000_0000;
const PC: u64 = PAGE + 128;
// Real E8 remains at +9; its saved next PC is exactly +14. This test plans
// only the root windows; it does not certify or execute the child/call tree.
const ROOT: [u8; 23] = [
    0x48, 0x83, 0xec, 8, 0xb8, 0, 0, 0, 0, 0xe8, 18, 0, 0, 0, 0x48, 0x83, 0xc0, 1, 0x48, 0x83,
    0xc4, 8, 0xc3,
];
unsafe extern "C" fn callback(_: *mut HookContext) {}
fn range(start: u64, len: usize) -> AddressRange {
    AddressRange::new(start, len).unwrap()
}
struct Fixture {
    entries: LegalEntrySet,
    allocation: [AllocationPolicy; 2],
    actions: [ControlledAction; 3],
    originals: Vec<ExpectedBytes>,
}
impl Fixture {
    fn new() -> Self {
        let mut bytes = vec![0xa5; 4096];
        bytes[128..128 + ROOT.len()].copy_from_slice(&ROOT);
        Self {
            entries: LegalEntrySet {
                identity: CodeIdentity {
                    source: SourceIdentity([94; 32]),
                    mapping: 94,
                    generation: 1,
                },
                scope: range(PC, ROOT.len()),
                provenance: EntryProvenance::Declared(
                    "fixed root entry and actual CALL resume".into(),
                ),
                completeness: EntryCompleteness::Complete,
                entries: vec![LegalEntry {
                    address: PC,
                    requires_endbr: false,
                }],
                resumes: ResumeObligation::Enumerated(vec![PC + 14]),
            },
            allocation: [PC + 0x10000, PC + 0x30000].map(|target| AllocationPolicy {
                ranges: vec![range(target & !4095, 8192)],
                preferred_address: Some(target),
                max_candidates: 1,
                max_mappings: 1,
                max_mapped_bytes: 8192,
            }),
            actions: [0, 14, 22].map(|offset| ControlledAction {
                logical_pc: PC + offset,
                control: ProbeControl::new(callback, true),
            }),
            originals: vec![ExpectedBytes {
                address: PAGE,
                bytes,
            }],
        }
    }
    fn request(&self, index: usize) -> InstallRequest<'_> {
        InstallRequest {
            identity: self.entries.identity,
            code: &ROOT,
            base_address: PC,
            function: self.entries.scope,
            block: if index == 0 {
                range(PC, 9)
            } else {
                range(PC + 14, 9)
            },
            logical_pc: if index == 0 { PC } else { PC + 14 },
            entries: &self.entries,
            hook: callback,
            semantics: HookSemantics::Observe,
            allocation: &self.allocation[index],
            search: SearchPolicy {
                tactics: TacticPolicy::RelocationOnly,
                max_displaced_bytes: 80,
                max_upstream_bytes: 0,
                max_sites: 1,
            },
        }
    }
    fn actions(&self, index: usize) -> &[ControlledAction] {
        if index == 0 {
            &self.actions[..1]
        } else {
            &self.actions[1..]
        }
    }
}

#[test]
fn profiled_overlay_preserves_original_call_resume_and_both_coalesced_roles() {
    let f = Fixture::new();
    let mut predecessor = Composition::new(f.entries.identity, f.originals.clone()).unwrap();
    let mut plans = Vec::new();
    for index in 0..2 {
        let before = predecessor.final_bytes().to_vec();
        let plan = plan_coalesced_detailed_after_with_stack_profile(
            &f.request(index),
            f.actions(index),
            &predecessor,
            ObservationStackProfile::Tree144,
        )
        .unwrap();
        assert_eq!(predecessor.final_bytes(), before); // Planning does not append.
        assert_eq!(
            plan.image().layout().observation_stack_profile,
            ObservationStackProfile::Tree144
        );
        assert_eq!(
            plan.plan().parts().reads[0].bytes,
            before[0].bytes[128..151]
        );
        assert!(!plan.plan().parts().displaced.overlaps(range(PC + 9, 5)));
        predecessor.append(plan.plan()).unwrap();
        plans.push(plan);
    }
    assert_eq!(plans[0].plan().parts().displaced, range(PC, 9));
    assert_eq!(plans[1].plan().parts().displaced, range(PC + 14, 9));
    assert_eq!(&predecessor.final_bytes()[0].bytes[137..142], &ROOT[9..14]);
    let bundle = PlannedBundle::compose(f.originals, plans, BundleBudget::default()).unwrap();
    assert_eq!(bundle.images().len(), 2);
    assert!(
        bundle
            .images()
            .iter()
            .all(|image| image.layout().observation_stack_profile
                == ObservationStackProfile::Tree144)
    );
    assert_eq!(bundle.plan().final_bytes(), predecessor.final_bytes());
}

#[test]
fn explicit_legacy_planner_retains_old_image_and_contract() {
    let f = Fixture::new();
    for index in 0..2 {
        let old = plan_coalesced_detailed(&f.request(index), f.actions(index)).unwrap();
        let new = plan_coalesced_detailed_with_stack_profile(
            &f.request(index),
            f.actions(index),
            ObservationStackProfile::Legacy128,
        )
        .unwrap();
        assert_eq!(old.image(), new.image());
        assert_eq!(old.plan(), new.plan());
    }
}

#[test]
fn changed_original_and_reused_window_refuse_before_image_search() {
    let f = Fixture::new();
    let mut predecessor = Composition::new(f.entries.identity, f.originals.clone()).unwrap();
    let mut stale = f.request(0);
    stale.identity.generation += 1;
    let failure = plan_coalesced_detailed_after_with_stack_profile(
        &stale,
        f.actions(0),
        &predecessor,
        ObservationStackProfile::Tree144,
    )
    .unwrap_err();
    assert_eq!(failure.reason, Refusal::StaleGeneration);
    assert!(failure.search.runs.is_empty());
    let mut changed = ROOT;
    changed[5] = 1;
    let mut request = f.request(0);
    request.code = &changed;
    let failure = plan_coalesced_detailed_after_with_stack_profile(
        &request,
        f.actions(0),
        &predecessor,
        ObservationStackProfile::Tree144,
    )
    .unwrap_err();
    assert_eq!(failure.reason, Refusal::ExpectedBytesChanged);
    assert!(failure.search.runs.is_empty());
    let first = plan_coalesced_detailed_after_with_stack_profile(
        &f.request(0),
        f.actions(0),
        &predecessor,
        ObservationStackProfile::Tree144,
    )
    .unwrap();
    predecessor.append(first.plan()).unwrap();
    let before = predecessor.final_bytes().to_vec();
    let failure = plan_coalesced_detailed_after_with_stack_profile(
        &f.request(0),
        f.actions(0),
        &predecessor,
        ObservationStackProfile::Tree144,
    )
    .unwrap_err();
    assert_eq!(failure.reason, Refusal::ExpectedBytesChanged);
    assert_eq!(failure.search.runs.len(), 1);
    assert_eq!(failure.search.runs[0].domain, SearchDomain::PhysicalSites);
    assert_eq!(predecessor.final_bytes(), before);
}

#[test]
fn unsupported_modes_bad_actions_and_bounds_still_refuse() {
    let f = Fixture::new();
    for replacement in [false, true] {
        let mut request = f.request(0);
        if replacement {
            request.semantics = HookSemantics::ReplaceFirst;
        } else {
            request.search.tactics = TacticPolicy::GeneralizedPunOnly;
        }
        let failure = plan_coalesced_detailed_with_stack_profile(
            &request,
            f.actions(0),
            ObservationStackProfile::Tree144,
        )
        .unwrap_err();
        assert!(matches!(failure.reason, Refusal::UnsupportedSemantics(_)));
        assert!(failure.search.runs.is_empty());
    }
    for actions in [
        vec![],
        vec![f.actions[1].clone(), f.actions[0].clone()],
        vec![f.actions[0].clone(), f.actions[0].clone()],
    ] {
        assert!(
            plan_coalesced_detailed_with_stack_profile(
                &f.request(0),
                &actions,
                ObservationStackProfile::Tree144
            )
            .is_err()
        );
    }
    let mut request = f.request(0);
    request.block = f.entries.scope;
    let spanning = [f.actions[0].clone(), f.actions[2].clone()];
    let failure = plan_coalesced_detailed_with_stack_profile(
        &request,
        &spanning,
        ObservationStackProfile::Tree144,
    )
    .unwrap_err();
    assert!(matches!(failure.reason, Refusal::UnsupportedSemantics(_)));
    let mut unresolved = f.entries.clone();
    unresolved.resumes = ResumeObligation::Unresolved;
    let mut request = f.request(0);
    request.entries = &unresolved;
    assert_eq!(
        plan_coalesced_detailed_with_stack_profile(
            &request,
            f.actions(0),
            ObservationStackProfile::Tree144
        )
        .unwrap_err()
        .reason,
        Refusal::UnresolvedEntry
    );
    let mut request = f.request(0);
    request.search.max_displaced_bytes = 8;
    assert!(
        plan_coalesced_detailed_with_stack_profile(
            &request,
            f.actions(0),
            ObservationStackProfile::Tree144
        )
        .is_err()
    );
    let mut allocation = f.allocation[0].clone();
    allocation.max_candidates = 0;
    let mut request = f.request(0);
    request.allocation = &allocation;
    assert!(
        plan_coalesced_detailed_with_stack_profile(
            &request,
            f.actions(0),
            ObservationStackProfile::Tree144
        )
        .is_err()
    );
}
