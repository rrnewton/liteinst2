#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
//! Structural planner qualification; no generated code is executed here.

use liteinst2::contracts::*;
use liteinst2::controls::{ControlledAction, PointObservationAction, ProbeControl};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy, plan_point_observations_detailed,
};
use liteinst2::trampoline::HookContext;

const BASE: u64 = 0x5c00_0000_0000;
const TARGET: u64 = BASE + 0x0400_0100;
const CODE: [u8; 16] = [0xb8, 1, 0, 0, 0, 0xb9, 2, 0, 0, 0, 0xba, 3, 0, 0, 0, 0xc3];

unsafe extern "C" fn observe(_: *mut HookContext) {}

fn entries() -> LegalEntrySet {
    LegalEntrySet {
        identity: CodeIdentity {
            source: SourceIdentity([0x5c; 32]),
            mapping: 1,
            generation: 1,
        },
        scope: AddressRange::new(BASE, CODE.len()).unwrap(),
        provenance: EntryProvenance::Declared("literal MOV/MOV/MOV/RET heads".into()),
        completeness: EntryCompleteness::AllInstructionHeads,
        entries: [0, 5, 10, 15]
            .map(|offset| LegalEntry {
                address: BASE + offset,
                requires_endbr: false,
            })
            .to_vec(),
        resumes: ResumeObligation::NoneExist,
    }
}

fn allocation(bytes: usize) -> AllocationPolicy {
    AllocationPolicy {
        ranges: vec![AddressRange::new(TARGET & !4095, 8192).unwrap()],
        preferred_address: Some(TARGET),
        max_candidates: 1,
        max_mappings: 4,
        max_mapped_bytes: bytes,
    }
}

fn actions() -> Vec<PointObservationAction> {
    [0, 5, 10]
        .map(|offset| {
            let action = ControlledAction {
                logical_pc: BASE + offset,
                control: ProbeControl::new(observe, offset == 10),
            };
            if offset == 10 {
                PointObservationAction::AfterCapture(action)
            } else {
                PointObservationAction::EarlyIfEnabled(action)
            }
        })
        .to_vec()
}

fn request<'a>(entries: &'a LegalEntrySet, allocation: &'a AllocationPolicy) -> InstallRequest<'a> {
    InstallRequest {
        identity: entries.identity,
        code: &CODE,
        base_address: BASE,
        function: entries.scope,
        block: entries.scope,
        logical_pc: BASE,
        entries,
        hook: observe,
        semantics: HookSemantics::Observe,
        allocation,
        search: SearchPolicy {
            tactics: TacticPolicy::RelocationOnly,
            max_upstream_bytes: 0,
            max_displaced_bytes: 15,
            max_sites: 1,
        },
    }
}

#[test]
fn mixed_point_plan_retains_routes_controls_and_smaller_allocation_caps() {
    let entries = entries();
    let actions = actions();
    let mut baseline = None;
    for cap in [4096, 8192, 65_536] {
        let allocation = allocation(cap);
        let planned = plan_point_observations_detailed(&request(&entries, &allocation), &actions)
            .expect("required mixed point plan");
        let parts = planned.plan().parts();
        assert_eq!(parts.kind, PlanKind::Relocation);
        assert_eq!(parts.displaced, AddressRange::new(BASE, 15).unwrap());
        assert_eq!(parts.allocations.len(), 1);
        assert_eq!(parts.allocations[0].range.len(), 4096);
        assert_eq!(planned.image().address(), TARGET);
        assert_eq!(planned.image().entry_routes().len(), 3);
        assert_eq!(planned.image().instruction_boundaries().len(), 3);
        assert_eq!(
            planned
                .image()
                .early_control_gates()
                .iter()
                .map(|g| g.logical_pc)
                .collect::<Vec<_>>(),
            [BASE, BASE + 5]
        );
        let expected = baseline.get_or_insert_with(|| planned.image().bytes().to_vec());
        assert_eq!(planned.image().bytes(), expected.as_slice());
        assert_eq!(
            allocation.max_mapped_bytes, cap,
            "caller policy stays unchanged"
        );
        assert_eq!(allocation.max_mappings, 4);
    }
}

#[test]
fn point_planning_refuses_bad_geometry_semantics_and_resource_limits() {
    let entries = entries();
    let allocation = allocation(8192);
    let actions = actions();
    let original = request(&entries, &allocation);
    let refusal = |r: &InstallRequest<'_>, a: &[PointObservationAction]| {
        plan_point_observations_detailed(r, a).unwrap_err().reason
    };
    let mut changed = request(&entries, &allocation);
    changed.semantics = HookSemantics::ReplaceFirst;
    assert!(matches!(
        refusal(&changed, &actions),
        Refusal::UnsupportedSemantics(_)
    ));
    changed = request(&entries, &allocation);
    changed.search.tactics = TacticPolicy::PreferGeneralizedPun;
    assert!(matches!(
        refusal(&changed, &actions),
        Refusal::UnsupportedSemantics(_)
    ));
    assert_eq!(refusal(&original, &[]), Refusal::InvalidPlan);
    let mut invalid = actions.clone();
    invalid.swap(1, 2);
    assert_eq!(refusal(&original, &invalid), Refusal::InvalidPlan);
    invalid = actions.clone();
    invalid[1] = PointObservationAction::EarlyIfEnabled(ControlledAction {
        logical_pc: BASE + 5,
        control: actions[0].controlled_action().control.clone(),
    });
    assert_eq!(refusal(&original, &invalid), Refusal::InvalidPlan);
    invalid = actions.clone();
    invalid[1] = PointObservationAction::EarlyIfEnabled(ControlledAction {
        logical_pc: BASE + 6,
        control: actions[1].controlled_action().control.clone(),
    });
    assert_eq!(refusal(&original, &invalid), Refusal::NotInstructionHead);
    for (mappings, bytes, candidates) in [(0, 8192, 1), (1, 4095, 1), (1, 8192, 0)] {
        let mut limit = allocation.clone();
        limit.max_mappings = mappings;
        limit.max_mapped_bytes = bytes;
        limit.max_candidates = candidates;
        assert_eq!(
            refusal(&request(&entries, &limit), &actions),
            Refusal::AllocationUnavailable
        );
    }
    changed = original;
    changed.search.max_sites = 0;
    assert_eq!(refusal(&changed, &actions), Refusal::NoPatchWindow);
}
