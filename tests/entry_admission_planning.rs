#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
//! Source/role/planner checks only: never publish or execute generated code.

use liteinst::composition::Composition;
use liteinst::contracts::*;
use liteinst::controls::{
    ControlIdentity, EntryAdmissionAction, EntryAdmissionRole, ManagedControl,
};
use liteinst::planner::HookSemantics;
use liteinst::quiescent::{
    AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy, WholeFunctionRequest,
    plan_entry_admission_detailed, plan_entry_admission_detailed_after,
    plan_whole_function_entry_admission_detailed,
    plan_whole_function_entry_admission_detailed_after,
};
use liteinst::scanner::InstructionScanner;
use liteinst::trampoline::{HookContext, TrampolinePlan};

const BASE: u64 = 0x5d40_0000_0000;
const TARGET: u64 = BASE + 0x0400_0100;
const CODE: &[u8] = &[0xb8, 1, 0, 0, 0, 0xb9, 2, 0, 0, 0, 0xc3];
// XOR; TEST; JE +5; INC; RET; two original unreachable NOPs; RET.
const BRANCH: &[u8] = &[
    0x31, 0xc0, 0x85, 0xf6, 0x74, 5, 0xff, 0xc0, 0xc3, 0x90, 0x90, 0xc3,
];

unsafe extern "C" fn callback(_: *mut HookContext, _: ControlIdentity<'_>) {}
unsafe extern "C" fn unused(_: *mut HookContext) {}

fn range(offset: u64, len: usize) -> AddressRange {
    AddressRange::new(BASE + offset, len).unwrap()
}

fn entries(code: &[u8], leaders: &[u64]) -> LegalEntrySet {
    LegalEntrySet {
        identity: CodeIdentity {
            source: SourceIdentity([0xd4; 32]),
            mapping: BASE,
            generation: 1,
        },
        scope: range(0, code.len()),
        provenance: EntryProvenance::Declared("complete scalar fixture; no execution".into()),
        completeness: EntryCompleteness::Complete,
        entries: leaders
            .iter()
            .map(|&offset| LegalEntry {
                address: BASE + offset,
                requires_endbr: false,
            })
            .collect(),
        resumes: ResumeObligation::NoneExist,
    }
}

fn actions(returns: &[u64]) -> Vec<EntryAdmissionAction> {
    // SAFETY: source-only fixture. Nothing is published or executed.
    let (entry, writer) = unsafe { EntryAdmissionAction::entry(BASE, callback, false) };
    drop(writer);
    std::iter::once(entry)
        .chain(
            returns.iter().map(|&offset| {
                EntryAdmissionAction::mandatory_return(BASE, BASE + offset, callback)
            }),
        )
        .collect()
}

fn allocation(bytes: usize) -> AllocationPolicy {
    AllocationPolicy {
        ranges: vec![AddressRange::new(TARGET & !4095, 8192).unwrap()],
        preferred_address: Some(TARGET),
        max_candidates: 1,
        max_mappings: 1,
        max_mapped_bytes: bytes,
    }
}

fn request<'a>(entries: &'a LegalEntrySet, allocation: &'a AllocationPolicy) -> InstallRequest<'a> {
    InstallRequest {
        identity: entries.identity,
        code: CODE,
        base_address: BASE,
        function: entries.scope,
        block: entries.scope,
        logical_pc: BASE,
        entries,
        hook: unused,
        semantics: HookSemantics::Observe,
        allocation,
        search: SearchPolicy {
            tactics: TacticPolicy::RelocationOnly,
            max_upstream_bytes: 0,
            max_displaced_bytes: 80,
            max_sites: 1,
        },
    }
}

fn whole<'a>(
    code: &'a [u8],
    entries: &'a LegalEntrySet,
    allocation: &'a AllocationPolicy,
) -> WholeFunctionRequest<'a> {
    WholeFunctionRequest {
        identity: entries.identity,
        code,
        base_address: BASE,
        entries,
        allocation,
    }
}

#[test]
fn entry_writer_cannot_change_the_permanent_return_or_escape_through_a_clone() {
    let (entry, mut writer) = unsafe { EntryAdmissionAction::entry(BASE, callback, false) };
    let clone = entry.clone();
    let ret = EntryAdmissionAction::mandatory_return(BASE, BASE + 10, callback);
    assert_eq!(entry.role(), EntryAdmissionRole::Entry);
    assert_eq!(ret.role(), EntryAdmissionRole::Return);
    assert_eq!(entry.function_entry(), ret.function_entry());
    assert_ne!(entry.control(), ret.control());
    assert_eq!(entry.control().try_set_enabled(true), Err(ManagedControl));
    assert_eq!(ret.control().try_set_enabled(false), Err(ManagedControl));
    assert!(!clone.control().is_enabled());
    writer.set_enabled(true);
    assert!(clone.control().is_enabled());
    writer.set_enabled(false);
    assert!(!clone.control().is_enabled());
    assert!(ret.control().is_enabled());
    assert_eq!(entry, clone);
}

#[test]
fn certified_block_keeps_all_roles_heads_originals_and_one_entry_gate() {
    let entries = entries(CODE, &[0]);
    let actions = actions(&[10]);
    let scan = InstructionScanner::default().scan(CODE, BASE).unwrap();
    let heads: Vec<_> = scan.instructions().iter().map(|i| i.address()).collect();
    let mut baseline = None;
    for cap in [4096, 8192, 65_536] {
        let allocation = allocation(cap);
        let planned =
            unsafe { plan_entry_admission_detailed(&request(&entries, &allocation), &actions) }
                .unwrap();
        let p = planned.plan().parts();
        assert_eq!(p.kind, PlanKind::Relocation);
        assert_eq!(p.entries, entries);
        assert_eq!(p.displaced, range(0, CODE.len()));
        assert_eq!(
            p.reads,
            [ExpectedBytes {
                address: BASE,
                bytes: CODE.to_vec()
            }]
        );
        assert_eq!(p.allocations.len(), 1);
        assert_eq!(p.allocations[0].range.len(), 4096);
        assert_eq!(planned.image().address(), TARGET);
        assert_eq!(
            planned.image().controls(),
            actions
                .iter()
                .map(|a| a.control().clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            planned
                .image()
                .entry_routes()
                .iter()
                .map(|x| x.0)
                .collect::<Vec<_>>(),
            heads
        );
        assert_eq!(
            planned
                .image()
                .instruction_boundaries()
                .iter()
                .map(|x| x.0)
                .collect::<Vec<_>>(),
            heads
        );
        let [gate] = planned.image().early_control_gates() else {
            panic!("exactly one required entry gate")
        };
        assert_eq!(gate.logical_pc, BASE);
        assert_eq!(planned.image().entry_routes()[0], (BASE, gate.entry));
        assert_eq!(
            planned.image().instruction_boundaries()[0],
            (BASE, gate.original_body)
        );
        let ret = planned.image().instruction_boundaries().last().unwrap().1;
        assert_eq!(planned.image().bytes()[(ret - TARGET) as usize], 0xc3);
        assert_eq!(
            planned.image().bytes(),
            baseline
                .get_or_insert_with(|| planned.image().bytes().to_vec())
                .as_slice()
        );
        assert_eq!(allocation.max_mapped_bytes, cap);
    }
}

#[test]
fn return_only_successor_group_keeps_complete_current_overlay_without_a_gate() {
    let entries = entries(CODE, &[0, 5]);
    let actions = actions(&[10]);
    let allocation = allocation(8192);
    let mut predecessor = Composition::new(
        entries.identity,
        vec![ExpectedBytes {
            address: BASE,
            bytes: CODE.to_vec(),
        }],
    )
    .unwrap();
    let mut first_request = request(&entries, &allocation);
    first_request.block = range(0, 5);
    let first =
        unsafe { plan_entry_admission_detailed_after(&first_request, &actions[..1], &predecessor) }
            .unwrap();
    assert_eq!(first.plan().parts().displaced, range(0, 5));
    predecessor.append(first.plan()).unwrap();
    let before = predecessor.clone();
    let mut second_allocation = allocation.clone();
    second_allocation.preferred_address = Some(TARGET + 0x1_0000);
    second_allocation.ranges = vec![AddressRange::new((TARGET + 0x1_0000) & !4095, 8192).unwrap()];
    let mut second_request = request(&entries, &second_allocation);
    second_request.block = range(5, 6);
    second_request.logical_pc = BASE + 10;
    second_request.search.max_upstream_bytes = 5;
    second_request.search.max_sites = 6;
    let second = unsafe {
        plan_entry_admission_detailed_after(&second_request, &actions[1..], &predecessor)
    }
    .unwrap();
    assert_eq!(predecessor, before);
    assert_eq!(second.plan().parts().reads, before.final_bytes());
    assert_eq!(second.plan().parts().displaced, range(5, 6));
    assert!(second.image().early_control_gates().is_empty());
    assert_eq!(second.image().controls(), [actions[1].control().clone()]);
    assert!(second.image().controls()[0].is_enabled());
    predecessor.append(second.plan()).unwrap();
    let error =
        unsafe { plan_entry_admission_detailed_after(&first_request, &actions[..1], &predecessor) }
            .unwrap_err();
    assert_eq!(error.reason, Refusal::ExpectedBytesChanged);
}

#[test]
fn whole_function_preserves_closed_cfg_all_returns_and_every_original_head() {
    let entries = entries(BRANCH, &[0, 6, 11]);
    let actions = actions(&[8, 11]);
    let allocation = allocation(8192);
    let source = Composition::new(
        entries.identity,
        vec![ExpectedBytes {
            address: BASE,
            bytes: BRANCH.to_vec(),
        }],
    )
    .unwrap();
    let planned = unsafe {
        plan_whole_function_entry_admission_detailed_after(
            &whole(BRANCH, &entries, &allocation),
            &actions,
            &source,
        )
    }
    .unwrap();
    assert_eq!(planned.plan().parts().displaced, range(0, BRANCH.len()));
    assert_eq!(planned.plan().parts().entries, entries);
    assert_eq!(planned.plan().parts().reads, source.final_bytes());
    assert_eq!(
        planned.image().controls(),
        actions
            .iter()
            .map(|a| a.control().clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        planned
            .image()
            .early_control_gates()
            .iter()
            .map(|g| g.logical_pc)
            .collect::<Vec<_>>(),
        [BASE]
    );
    let heads: Vec<_> = InstructionScanner::default()
        .scan(BRANCH, BASE)
        .unwrap()
        .instructions()
        .iter()
        .map(|i| i.address())
        .collect();
    assert_eq!(
        planned
            .image()
            .entry_routes()
            .iter()
            .map(|x| x.0)
            .collect::<Vec<_>>(),
        heads
    );
    assert_eq!(
        planned
            .image()
            .instruction_boundaries()
            .iter()
            .map(|x| x.0)
            .collect::<Vec<_>>(),
        heads
    );
    for offset in [8, 11] {
        let body = planned
            .image()
            .instruction_boundaries()
            .iter()
            .find(|x| x.0 == BASE + offset)
            .unwrap()
            .1;
        assert_eq!(
            planned.image().bytes()[(body - planned.image().address()) as usize],
            0xc3
        );
    }
    let mut changed = source.clone();
    changed.append(planned.plan()).unwrap();
    let failure = unsafe {
        plan_whole_function_entry_admission_detailed_after(
            &whole(BRANCH, &entries, &allocation),
            &actions,
            &changed,
        )
    }
    .unwrap_err();
    assert_eq!(failure.reason, Refusal::ExpectedBytesChanged);
    assert!(failure.attempts.is_empty() && failure.search.runs.is_empty());
}

#[test]
fn incorrect_function_head_role_order_and_missing_return_refuse() {
    let entries = entries(CODE, &[0]);
    let allocation = allocation(8192);
    let good = actions(&[10]);
    let error = |actions: &[EntryAdmissionAction]| {
        unsafe { plan_entry_admission_detailed(&request(&entries, &allocation), actions) }
            .unwrap_err()
            .reason
    };
    assert_eq!(error(&[]), Refusal::InvalidPlan);
    let mut bad = good.clone();
    bad.swap(0, 1);
    assert_eq!(error(&bad), Refusal::InvalidPlan);
    bad = good.clone();
    bad[1] = EntryAdmissionAction::mandatory_return(BASE + 1, BASE + 10, callback);
    assert_eq!(error(&bad), Refusal::InvalidPlan);
    bad[1] = EntryAdmissionAction::mandatory_return(BASE, BASE + 5, callback);
    assert_eq!(error(&bad), Refusal::InvalidPlan);
    bad[1] = EntryAdmissionAction::mandatory_return(BASE, BASE + 6, callback);
    assert_eq!(error(&bad), Refusal::NotInstructionHead);
    bad[1] = good[0].clone();
    assert_eq!(error(&bad), Refusal::InvalidPlan);
    let scan = InstructionScanner::default().scan(CODE, BASE).unwrap();
    let missing_ret = unsafe {
        TrampolinePlan::from_entry_admission_actions(
            &scan,
            BASE,
            BASE + CODE.len() as u64,
            &good[..1],
        )
    }
    .unwrap_err();
    assert!(
        missing_ret
            .to_string()
            .contains("displaced entry/RET role is missing")
    );
    let missing_entry = unsafe {
        TrampolinePlan::from_entry_admission_actions(
            &scan,
            BASE,
            BASE + CODE.len() as u64,
            &good[1..],
        )
    }
    .unwrap_err();
    assert!(
        missing_entry
            .to_string()
            .contains("displaced entry/RET role is missing")
    );
    let branch_entries = entries_for_branch();
    let branch_actions = actions(&[8, 11]);
    for roles in [&branch_actions[..2], &branch_actions[1..]] {
        let failure = unsafe {
            plan_whole_function_entry_admission_detailed(
                &whole(BRANCH, &branch_entries, &allocation),
                roles,
            )
        }
        .unwrap_err();
        assert_eq!(failure.reason, Refusal::InvalidPlan);
        assert!(failure.attempts.is_empty());
    }
}

fn entries_for_branch() -> LegalEntrySet {
    entries(BRANCH, &[0, 6, 11])
}

#[test]
fn semantic_entry_resume_and_small_resource_caps_fail_before_any_fallback() {
    let entries = entries(CODE, &[0]);
    let actions = actions(&[10]);
    let allocation = allocation(8192);
    for change in 0..5 {
        let mut modified_entries = entries.clone();
        match change {
            0 => modified_entries.completeness = EntryCompleteness::Incomplete,
            1 => modified_entries.completeness = EntryCompleteness::AllInstructionHeads,
            2 => modified_entries.resumes = ResumeObligation::Unresolved,
            3 => modified_entries.resumes = ResumeObligation::Enumerated(vec![BASE]),
            4 => modified_entries.entries[0].requires_endbr = true,
            _ => unreachable!(),
        }
        let failure = unsafe {
            plan_entry_admission_detailed(&request(&modified_entries, &allocation), &actions)
        }
        .unwrap_err();
        assert_eq!(failure.reason, Refusal::UnresolvedEntry);
        assert!(failure.attempts.is_empty());
    }
    for replacement in [false, true] {
        let mut request = request(&entries, &allocation);
        if replacement {
            request.semantics = HookSemantics::ReplaceFirst;
        } else {
            request.search.tactics = TacticPolicy::PreferGeneralizedPun;
        }
        let failure = unsafe { plan_entry_admission_detailed(&request, &actions) }.unwrap_err();
        assert!(matches!(failure.reason, Refusal::UnsupportedSemantics(_)));
        assert!(failure.attempts.is_empty());
    }
    for (mappings, bytes, candidates) in [(0, 8192, 1), (1, 4095, 1), (1, 8192, 0)] {
        let mut allocation = allocation.clone();
        allocation.max_mappings = mappings;
        allocation.max_mapped_bytes = bytes;
        allocation.max_candidates = candidates;
        let failure =
            unsafe { plan_entry_admission_detailed(&request(&entries, &allocation), &actions) }
                .unwrap_err();
        assert_eq!(failure.reason, Refusal::AllocationUnavailable);
        let failure = unsafe {
            plan_whole_function_entry_admission_detailed(
                &whole(CODE, &entries, &allocation),
                &actions,
            )
        }
        .unwrap_err();
        assert_eq!(failure.reason, Refusal::AllocationUnavailable);
    }
    let scan = InstructionScanner::default().scan(CODE, BASE).unwrap();
    let plan = unsafe {
        TrampolinePlan::from_entry_admission_actions(
            &scan,
            BASE,
            BASE + CODE.len() as u64,
            &actions,
        )
    }
    .unwrap();
    assert!(plan.emit_with_frame_trace_at(TARGET).is_err());
}

#[test]
fn entry_admission_refuses_call_pair_indirect_entry_backedge_and_nonliteral_returns() {
    let cases: &[&[u8]] = &[
        &[0xe8, 0, 0, 0, 0, 0xc3],
        &[0xff, 0xe0, 0x90, 0x90, 0x90, 0xc3],
        &[0x90, 0x90, 0x90, 0xeb, 0xfb, 0xc3],
        &[0x90, 0x90, 0x90, 0x90, 0x90, 0xf3, 0xc3],
        &[0xc3, 0x90, 0x90, 0x90, 0x90, 0xc3],
        &[0x90, 0x90, 0x90, 0x90, 0x90, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3],
        &[0xb8, 1, 0, 0, 0, 0x90],
        &[0xeb, 0x7f, 0x90, 0x90, 0xc3],
    ];
    for code in cases {
        let scan = InstructionScanner::default().scan(code, BASE).unwrap();
        let roles = actions(&[(code.len() - 1) as u64]);
        let failure = unsafe {
            TrampolinePlan::from_entry_admission_actions(
                &scan,
                BASE,
                BASE + code.len() as u64,
                &roles,
            )
        }
        .unwrap_err();
        assert!(
            failure.to_string().contains("entry-admission role:"),
            "{code:02x?}: {failure}"
        );
    }
    let mut oversized = vec![0x90; 257];
    oversized[256] = 0xc3;
    let scan = InstructionScanner::default()
        .scan(&oversized, BASE)
        .unwrap();
    let roles = actions(&[256]);
    let failure =
        unsafe { TrampolinePlan::from_entry_admission_actions(&scan, BASE, BASE + 257, &roles) }
            .unwrap_err();
    assert!(
        failure
            .to_string()
            .contains("entry-admission role: InvalidRange")
    );
}
