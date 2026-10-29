//! Pure block planning and byte composition only. No loader certificate is
//! fabricated, and no source/image is mapped, published or executed.
use super::super::{SiteError, groups, whole};
use liteinst2::bundle::{BundleBudget, PlannedBundle};
use liteinst2::composition::Composition;
use liteinst2::contracts::*;
use liteinst2::controls::{ControlledAction, ProbeControl};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy, plan_coalesced_detailed_after,
};
use liteinst2::trampoline::ObservationStackProfile;

const PAGE: u64 = 0x2800_0000;
const ENTRY: u64 = PAGE + 128;
unsafe extern "C" fn callback(_: *mut liteinst2::trampoline::HookContext) {}
fn range(start: u64, len: usize) -> AddressRange {
    AddressRange::new(start, len).unwrap()
}

#[test]
fn certified_blocks_compose_all_roles_beyond_whole_extent() {
    // TEST RSI,RSI; JE +79. The fallthrough has thirteen six-byte ADD RAX,1
    // instructions and RET; the taken block is MOV EAX,0; RET. All 90 bytes
    // belong to reachable instructions; there is no padding or CALL.
    let mut code = vec![0x48, 0x85, 0xf6, 0x74, 79];
    for _ in 0..13 {
        code.extend_from_slice(&[0x48, 0x05, 1, 0, 0, 0]);
    }
    code.extend_from_slice(&[0xc3, 0xb8, 0, 0, 0, 0, 0xc3]);
    assert_eq!(code.len(), 90);
    let blocks = [
        (ENTRY, ENTRY + 5),
        (ENTRY + 5, ENTRY + 84),
        (ENTRY + 84, ENTRY + 90),
    ];
    let returns = [ENTRY + 83, ENTRY + 89];
    let edges = [(ENTRY + 3, ENTRY + 5), (ENTRY + 3, ENTRY + 84)];
    let selected = groups(ENTRY, &returns, &blocks, &edges).unwrap();
    assert_eq!(
        selected
            .iter()
            .map(|group| group.roles.clone())
            .collect::<Vec<_>>(),
        [vec![0], vec![1], vec![2]]
    );
    assert!(matches!(
        whole::groups(range(ENTRY, code.len()), &returns, &blocks, &edges),
        Err(SiteError::Core(Refusal::NoPatchWindow))
    ));

    let entries = LegalEntrySet {
        identity: CodeIdentity {
            source: SourceIdentity([116; 32]),
            mapping: 116,
            generation: 1,
        },
        scope: range(ENTRY, code.len()),
        provenance: EntryProvenance::Declared(
            "test-only complete scalar block fixture; no loader or execution authority".into(),
        ),
        completeness: EntryCompleteness::Complete,
        entries: [ENTRY, ENTRY + 5, ENTRY + 84]
            .into_iter()
            .map(|address| LegalEntry {
                address,
                requires_endbr: false,
            })
            .collect(),
        resumes: ResumeObligation::NoneExist,
    };
    let pcs = [ENTRY, returns[0], returns[1]];
    let controls = pcs.map(|_| ProbeControl::new(callback, true));
    let mut page = vec![0xa5; 4096];
    page[128..218].copy_from_slice(&code);
    let originals = vec![ExpectedBytes {
        address: PAGE,
        bytes: page.clone(),
    }];
    let mut predecessor = Composition::new(entries.identity, originals.clone()).unwrap();
    let mut overlay = code.clone();
    let mut reserved = vec![range(PAGE, 4096)];
    let mut members = Vec::new();
    let displacements = [range(ENTRY, 5), range(ENTRY + 77, 7), range(ENTRY + 84, 6)];
    let heads = [
        [ENTRY, ENTRY + 3],
        [ENTRY + 77, ENTRY + 83],
        [ENTRY + 84, ENTRY + 89],
    ];
    for (index, group) in selected.iter().enumerate() {
        let target = ENTRY + 0x1_0000 + index as u64 * 0x2_0000;
        let allocation = AllocationPolicy {
            ranges: vec![range(target & !4095, 8192)],
            preferred_address: Some(target),
            max_candidates: 1,
            max_mappings: 1,
            max_mapped_bytes: 8192,
        };
        let actions: Vec<_> = group
            .roles
            .iter()
            .map(|&role| ControlledAction {
                logical_pc: pcs[role],
                control: controls[role].clone(),
            })
            .collect();
        let request = InstallRequest {
            identity: entries.identity,
            code: &code,
            base_address: ENTRY,
            function: entries.scope,
            block: group.block,
            logical_pc: actions[0].logical_pc,
            entries: &entries,
            hook: callback,
            semantics: HookSemantics::Observe,
            allocation: &allocation,
            search: SearchPolicy {
                tactics: TacticPolicy::RelocationOnly,
                max_upstream_bytes: if index == 0 { 0 } else { 64 },
                max_displaced_bytes: 80,
                max_sites: if index == 0 { 1 } else { 65 },
            },
        };
        let before = predecessor.final_bytes().to_vec();
        let member = plan_coalesced_detailed_after(&request, &actions, &predecessor).unwrap();
        assert_eq!(predecessor.final_bytes(), before);
        let plan = member.plan().parts();
        assert_eq!(plan.displaced, displacements[index]);
        assert_eq!(plan.entries, entries);
        assert_eq!(plan.logical_pc, pcs[index]);
        assert_eq!(
            plan.reads,
            [ExpectedBytes {
                address: ENTRY,
                bytes: overlay.clone()
            }]
        );
        assert_eq!(
            member.image().controls(),
            std::slice::from_ref(&controls[index])
        );
        assert_eq!(
            member.image().layout().observation_stack_profile,
            ObservationStackProfile::Legacy128
        );
        assert_eq!(
            member
                .image()
                .instruction_boundaries()
                .iter()
                .map(|&(pc, _)| pc)
                .collect::<Vec<_>>(),
            heads[index]
        );
        assert_eq!(plan.allocations.len(), 1);
        let mapped = plan.allocations[0].range;
        assert!(mapped.len() <= 8192 && reserved.iter().all(|prior| !mapped.overlaps(*prior)));
        reserved.push(mapped);
        assert_eq!(plan.writes.len(), 1);
        let edit = &plan.writes[0];
        assert_eq!(edit.address, plan.displaced.start());
        assert_eq!(edit.bytes.len() as u64, plan.displaced.len());
        let offset = (edit.address - ENTRY) as usize;
        overlay[offset..offset + edit.bytes.len()].copy_from_slice(&edit.bytes);
        page[128 + offset..128 + offset + edit.bytes.len()].copy_from_slice(&edit.bytes);
        predecessor.append(member.plan()).unwrap();
        members.push(member);
    }
    let bundle = PlannedBundle::compose(
        originals.clone(),
        members,
        BundleBudget {
            max_steps: 5,
            max_mappings: 5,
            max_virtual_bytes: 5 * 8192,
            max_backing_bytes: 5 * 8192,
            max_virtual_span: 1 << 32,
        },
    )
    .unwrap();
    assert_eq!(bundle.images().len(), 3);
    assert_eq!(bundle.plan().memory().mappings, 3);
    assert_eq!(bundle.plan().originals(), originals);
    assert_eq!(bundle.plan().final_bytes(), predecessor.final_bytes());
    assert_eq!(
        bundle.plan().final_bytes(),
        [ExpectedBytes {
            address: PAGE,
            bytes: page
        }]
    );
}
