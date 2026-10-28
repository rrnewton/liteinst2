#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
//! Planning/encoding only: no mapping, publication, callback or native execution.
use liteinst2::bundle::{BundleBudget, PlannedBundle};
use liteinst2::composition::Composition;
use liteinst2::contracts::*;
use liteinst2::controls::ControlIdentity;
use liteinst2::grouping::{GroupingBudget, GroupingPlan};
use liteinst2::planner::HookSemantics;
use liteinst2::precontext::{PreContextAction, PreContextRole, PreContextSelector};
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, PlannedInstall, PlanningFailure, SearchPolicy, TacticPolicy,
    plan_precontext_coalesced_detailed, plan_precontext_coalesced_detailed_after,
};
use liteinst2::scanner::{InstructionScanner, ScanError};
use liteinst2::search::{RefusalClass, SearchDomain, SearchStop};
use liteinst2::trampoline::{HookContext, TrampolineImage};

const PAGE: u64 = 0x2000_0000;
const PC: u64 = PAGE + 128;
const STRAIGHT: [u8; 6] = [0x31, 0xc0, 0x31, 0xc9, 0x90, 0xc3];
// The unchanged coalesced-composition fixture: XOR2/XOR2/NOP4/JMP2; MOV5/RET1.
const BODY: [u8; 16] = [
    0x31, 0xc0, 0x31, 0xd2, 0x0f, 0x1f, 0x40, 0, 0xeb, 0, 0xb8, 42, 0, 0, 0, 0xc3,
];
unsafe extern "C" fn callback(_: *mut HookContext) {}
unsafe extern "C" fn preserving(_: *mut HookContext, _: ControlIdentity<'_>) {}
fn range(start: u64, len: usize) -> AddressRange {
    AddressRange::new(start, len).unwrap()
}
struct Fixture {
    code: Vec<u8>,
    entries: LegalEntrySet,
    allocations: [AllocationPolicy; 2],
    selector: PreContextSelector,
    actions: [PreContextAction; 2],
    originals: Vec<ExpectedBytes>,
}
impl Fixture {
    fn new(code: &[u8], heads: &[u64]) -> Self {
        let (selector, _) = PreContextSelector::new(false);
        let mut page = vec![0xa5; 4096];
        page[128..128 + code.len()].copy_from_slice(code);
        Self {
            code: code.to_vec(),
            entries: LegalEntrySet {
                identity: CodeIdentity {
                    source: SourceIdentity([93; 32]),
                    mapping: 93,
                    generation: 1,
                },
                scope: range(PC, code.len()),
                provenance: EntryProvenance::Declared(
                    "complete original fixture and direct targets".into(),
                ),
                completeness: EntryCompleteness::Complete,
                entries: heads
                    .iter()
                    .map(|&address| LegalEntry {
                        address,
                        requires_endbr: false,
                    })
                    .collect(),
                resumes: ResumeObligation::NoneExist,
            },
            allocations: [PC + 0x1_0000, PC + 0x3_0000].map(|target| AllocationPolicy {
                ranges: vec![range(target & !4095, 8192)],
                preferred_address: Some(target),
                max_candidates: 1,
                max_mappings: 1,
                max_mapped_bytes: 8192,
            }),
            actions: [
                PreContextAction::new(PC, PreContextRole::Entry, &selector, preserving),
                PreContextAction::new(
                    PC + code.len() as u64 - 1,
                    PreContextRole::Return,
                    &selector,
                    preserving,
                ),
            ],
            selector,
            originals: vec![ExpectedBytes {
                address: PAGE,
                bytes: page,
            }],
        }
    }
    fn split() -> Self {
        Self::new(&BODY, &[PC, PC + 10])
    }
    fn predecessor(&self) -> Composition {
        Composition::new(self.entries.identity, self.originals.clone()).unwrap()
    }
    fn request(&self, index: usize) -> InstallRequest<'_> {
        let split = self.code == BODY;
        InstallRequest {
            identity: self.entries.identity,
            code: &self.code,
            base_address: PC,
            function: range(PC, self.code.len()),
            block: if split {
                if index == 0 {
                    range(PC, 10)
                } else {
                    range(PC + 10, 6)
                }
            } else {
                range(PC, self.code.len())
            },
            logical_pc: self.actions[index].logical_pc(),
            entries: &self.entries,
            hook: callback,
            semantics: HookSemantics::Observe,
            allocation: &self.allocations[index],
            search: SearchPolicy {
                tactics: TacticPolicy::RelocationOnly,
                max_displaced_bytes: 80,
                max_upstream_bytes: if index == 0 { 0 } else { 5 },
                max_sites: if index == 0 { 1 } else { 2 },
            },
        }
    }
}
// Safety: these controls only construct plans. None publishes or invokes an
// image. Negative cases deliberately falsify planning inputs, never execute a
// leaf lacking the unsafe caller's frame/whole-CFG/physical-return certificate.
fn plan(r: &InstallRequest<'_>, a: &[PreContextAction]) -> Result<PlannedInstall, PlanningFailure> {
    unsafe { plan_precontext_coalesced_detailed(r, a) }
}
fn after(
    r: &InstallRequest<'_>,
    a: &[PreContextAction],
    c: &Composition,
) -> Result<PlannedInstall, PlanningFailure> {
    unsafe { plan_precontext_coalesced_detailed_after(r, a, c) }
}
fn qualification(f: PlanningFailure, reason: Refusal) {
    assert_eq!(f.reason, reason);
    assert!(f.attempts.is_empty());
    assert!(f.search.runs.is_empty());
    assert!(!f.search.accepted && !f.search.classification_complete);
    assert_eq!(f.search.refusals.len(), 1);
    assert_eq!(f.search.refusals[0].reason, reason);
}
fn no_images(f: &PlanningFailure) {
    assert!(!f.search.accepted);
    assert!(
        f.search
            .runs
            .iter()
            .all(|r| r.domain != SearchDomain::SelectedImages)
    );
}
fn gate(image: &TrampolineImage, action: &PreContextAction) {
    assert_eq!(image.precontext_selector(), Some(action.selector()));
    let g = image
        .precontext_gates()
        .iter()
        .find(|g| g.logical_pc == action.logical_pc())
        .unwrap();
    assert_eq!(g.role, action.role());
    assert!(image.controls().contains(action.control()));
    assert!(action.control().is_enabled());
    assert!(action.control().try_set_enabled(false).is_err());
    assert!(
        image
            .entry_routes()
            .contains(&(action.logical_pc(), g.entry))
    );
    assert!(
        image
            .instruction_boundaries()
            .contains(&(action.logical_pc(), g.original_body))
    );
    assert_ne!(g.entry, g.observing_entry);
    assert_ne!(g.entry, g.original_body);
    assert!(
        image
            .entry_routes()
            .iter()
            .all(|&(original, _)| original != g.fault)
    );
    let offset = (g.fault - image.address()) as usize;
    assert_eq!(&image.bytes()[offset..offset + 2], &[0x0f, 0x0b]);
}

#[test]
fn typed_entry_and_ret_keep_exact_original_bodies_and_owners() {
    let f = Fixture::new(&STRAIGHT, &[PC]);
    assert_ne!(f.actions[0].control(), f.actions[1].control());
    let p = plan(&f.request(0), &f.actions).unwrap();
    assert_eq!(p.plan().parts().displaced, range(PC, 6));
    assert_eq!(p.image().precontext_gates().len(), 2);
    assert_eq!(
        p.image().controls(),
        &[
            f.actions[0].control().clone(),
            f.actions[1].control().clone()
        ]
    );
    for a in &f.actions {
        gate(p.image(), a);
    }
    // Independent literal heads/bytes, not a second invocation of the scanner.
    for (offset, bytes) in [
        (0, &STRAIGHT[0..2]),
        (2, &STRAIGHT[2..4]),
        (4, &STRAIGHT[4..5]),
        (5, &STRAIGHT[5..6]),
    ] {
        let generated = p
            .image()
            .instruction_boundaries()
            .iter()
            .find(|&&(pc, _)| pc == PC + offset)
            .unwrap()
            .1;
        let at = (generated - p.image().address()) as usize;
        assert_eq!(&p.image().bytes()[at..at + bytes.len()], bytes);
    }
    assert_eq!(
        p.plan().parts().reads,
        [ExpectedBytes {
            address: PC,
            bytes: STRAIGHT.to_vec()
        }]
    );
    assert!(p.metrics().search.accepted);
}

fn two_members(f: &Fixture) -> (Composition, PlannedInstall, PlannedInstall) {
    let mut c = f.predecessor();
    let first = after(&f.request(0), &f.actions[..1], &c).unwrap();
    assert_eq!(c, f.predecessor());
    c.append(first.plan()).unwrap();
    let before = c.clone();
    let second = after(&f.request(1), &f.actions[1..], &c).unwrap();
    assert_eq!(c, before);
    (c, first, second)
}

#[test]
fn return_only_uses_original_scan_and_complete_current_reads_in_order() {
    let f = Fixture::split();
    let (mut c, first, second) = two_members(&f);
    assert_eq!(first.plan().parts().displaced, range(PC, 8));
    assert_eq!(
        first.plan().parts().reads,
        [ExpectedBytes {
            address: PC,
            bytes: BODY.to_vec()
        }]
    );
    let mut current = BODY.to_vec();
    current[..8].copy_from_slice(&first.plan().parts().writes[0].bytes);
    assert_eq!(&current[5..8], &[0x1f, 0x40, 0]);
    assert!(matches!(InstructionScanner::default().scan(&current, PC),
        Err(ScanError::InvalidInstruction { address, offset: 5 }) if address == PC + 5));
    let mut wrong = f.request(1);
    wrong.code = &current;
    qualification(
        after(&wrong, &f.actions[1..], &c).unwrap_err(),
        Refusal::ExpectedBytesChanged,
    );
    let bad = plan(&wrong, &f.actions[1..]).unwrap_err();
    assert!(matches!(bad.reason, Refusal::Backend(_)));
    assert!(bad.attempts.is_empty());
    assert_eq!(second.plan().parts().displaced, range(PC + 10, 6));
    assert_eq!(
        second.plan().parts().reads,
        [ExpectedBytes {
            address: PC,
            bytes: current
        }]
    );
    assert_eq!(second.metrics().attempts.len(), 2);
    assert_eq!(
        second.metrics().attempts[0].refusal,
        Some(Refusal::NoPatchWindow)
    );
    assert_eq!(second.metrics().attempts[1].refusal, None);
    for (member, action) in [(&first, &f.actions[0]), (&second, &f.actions[1])] {
        assert_eq!(member.image().precontext_gates().len(), 1);
        gate(member.image(), action);
    }
    c.append(second.plan()).unwrap();
    let mut expected = f.originals.clone();
    for member in [&first, &second] {
        for edit in &member.plan().parts().writes {
            let at = (edit.address - PAGE) as usize;
            expected[0].bytes[at..at + edit.bytes.len()].copy_from_slice(&edit.bytes);
        }
    }
    assert_eq!(c.final_bytes(), expected);
    for members in [vec![second.clone()], vec![second.clone(), first.clone()]] {
        assert_eq!(
            PlannedBundle::compose(f.originals.clone(), members, BundleBudget::default())
                .unwrap_err(),
            Refusal::ExpectedBytesChanged
        );
    }
    let b = PlannedBundle::compose(
        f.originals.clone(),
        vec![first, second],
        BundleBudget::default(),
    )
    .unwrap();
    assert_eq!(b.plan().originals(), f.originals);
    assert_eq!(b.plan().final_bytes(), expected);
    assert_eq!(b.plan().memory().mappings, 2);
}

#[test]
fn explicit_profile_refusals_precede_search_without_fallback() {
    let f = Fixture::split();
    for completeness in [
        EntryCompleteness::Incomplete,
        EntryCompleteness::AllInstructionHeads,
    ] {
        let mut entries = f.entries.clone();
        entries.completeness = completeness;
        let mut r = f.request(0);
        r.entries = &entries;
        qualification(
            plan(&r, &f.actions[..1]).unwrap_err(),
            Refusal::UnresolvedEntry,
        );
    }
    for resumes in [
        ResumeObligation::Unresolved,
        ResumeObligation::Enumerated(vec![]),
        ResumeObligation::Enumerated(vec![PC]),
    ] {
        let mut entries = f.entries.clone();
        entries.resumes = resumes;
        let mut r = f.request(0);
        r.entries = &entries;
        qualification(
            plan(&r, &f.actions[..1]).unwrap_err(),
            Refusal::UnresolvedEntry,
        );
    }
    let mut entries = f.entries.clone();
    entries.scope = range(PC, 10);
    let mut r = f.request(0);
    r.entries = &entries;
    qualification(
        plan(&r, &f.actions[..1]).unwrap_err(),
        Refusal::InvalidRange,
    );
    let mut r = f.request(0);
    r.function = range(PC, 10);
    qualification(
        plan(&r, &f.actions[..1]).unwrap_err(),
        Refusal::InvalidRange,
    );
    let mut r = f.request(0);
    r.code = &f.originals[0].bytes;
    r.base_address = PAGE;
    qualification(
        plan(&r, &f.actions[..1]).unwrap_err(),
        Refusal::InvalidRange,
    );
    let mut entries = f.entries.clone();
    entries.entries[1].requires_endbr = true;
    let mut r = f.request(0);
    r.entries = &entries; // Outside first displacement is still disallowed.
    qualification(
        plan(&r, &f.actions[..1]).unwrap_err(),
        Refusal::UnsupportedSemantics(
            "pre-context planning excludes ENDBR-required entries".into(),
        ),
    );
    let reason = Refusal::UnsupportedSemantics(
        "pre-context planning requires Observe and RelocationOnly".into(),
    );
    let mut r = f.request(0);
    r.semantics = HookSemantics::ReplaceFirst;
    qualification(plan(&r, &f.actions[..1]).unwrap_err(), reason.clone());
    for tactic in [
        TacticPolicy::PreferGeneralizedPun,
        TacticPolicy::GeneralizedPunOnly,
        TacticPolicy::PrefixPunOnly,
    ] {
        let mut r = f.request(0);
        r.search.tactics = tactic;
        qualification(plan(&r, &f.actions[..1]).unwrap_err(), reason.clone());
    }
}

#[test]
fn original_authentication_and_changed_window_refuse_before_images() {
    let f = Fixture::split();
    let stale = Composition::new(
        CodeIdentity {
            generation: 2,
            ..f.entries.identity
        },
        f.originals.clone(),
    )
    .unwrap();
    qualification(
        after(&f.request(0), &f.actions[..1], &stale).unwrap_err(),
        Refusal::StaleGeneration,
    );
    let mut changed = BODY;
    changed[11] ^= 1; // Same heads, changed MOV immediate.
    let mut r = f.request(0);
    r.code = &changed;
    qualification(
        after(&r, &f.actions[..1], &f.predecessor()).unwrap_err(),
        Refusal::ExpectedBytesChanged,
    );
    let gap = Composition::new(
        f.entries.identity,
        vec![ExpectedBytes {
            address: PC,
            bytes: BODY[..15].to_vec(),
        }],
    )
    .unwrap();
    qualification(
        after(&f.request(0), &f.actions[..1], &gap).unwrap_err(),
        Refusal::DependencyNotHeld,
    );
    let (c, _, _) = two_members(&f);
    let before = c.clone();
    let failure = after(&f.request(0), &f.actions[..1], &c).unwrap_err();
    assert_eq!(failure.reason, Refusal::ExpectedBytesChanged);
    assert_eq!(failure.attempts.len(), 1);
    assert_eq!(
        failure.attempts[0].refusal,
        Some(Refusal::ExpectedBytesChanged)
    );
    assert_eq!(failure.search.runs.len(), 1);
    assert_eq!(failure.search.runs[0].domain, SearchDomain::PhysicalSites);
    assert_eq!(failure.search.runs[0].examined, 1);
    assert_eq!(failure.search.runs[0].stop, SearchStop::DomainComplete);
    assert_eq!(
        failure.search.refusals[0].reason,
        Refusal::ExpectedBytesChanged
    );
    no_images(&failure);
    assert_eq!(c, before);
}

#[test]
fn action_identity_role_and_block_errors_never_become_mandatory_images() {
    let f = Fixture::new(&STRAIGHT, &[PC]);
    // Cloning an action repeats its PC AND identity; no public API can splice
    // one permanent control into a different action at an unrelated PC.
    for actions in [
        vec![],
        vec![f.actions[1].clone(), f.actions[0].clone()],
        vec![f.actions[0].clone(), f.actions[0].clone()],
    ] {
        let failure = plan(&f.request(0), &actions).unwrap_err();
        assert_eq!(failure.reason, Refusal::InvalidPlan);
        assert!(failure.attempts.is_empty());
        no_images(&failure);
    }
    let (foreign, _) = PreContextSelector::new(false);
    let wrong_selector = [
        f.actions[0].clone(),
        PreContextAction::new(PC + 5, PreContextRole::Return, &foreign, preserving),
    ];
    let non_ret = [
        f.actions[0].clone(),
        PreContextAction::new(PC + 4, PreContextRole::Return, &f.selector, preserving),
    ];
    for actions in [&wrong_selector[..], &non_ret[..]] {
        let failure = plan(&f.request(0), actions).unwrap_err();
        assert!(matches!(failure.reason, Refusal::Backend(_)));
        assert_eq!(failure.attempts.len(), 1);
        no_images(&failure);
    }
    let interior = [
        PreContextAction::new(PC + 2, PreContextRole::Entry, &f.selector, preserving),
        f.actions[1].clone(),
    ];
    let mut r = f.request(0);
    r.logical_pc = PC + 2;
    r.search.max_upstream_bytes = 2;
    r.search.max_sites = 2;
    let failure = plan(&r, &interior).unwrap_err();
    assert!(matches!(failure.reason, Refusal::Backend(_)));
    assert_eq!(failure.attempts.len(), 2);
    assert_eq!(failure.attempts[0].refusal, Some(Refusal::NoPatchWindow));
    no_images(&failure);
    let nonhead = [
        f.actions[0].clone(),
        PreContextAction::new(PC + 1, PreContextRole::Return, &f.selector, preserving),
    ];
    let failure = plan(&f.request(0), &nonhead).unwrap_err();
    assert_eq!(failure.reason, Refusal::NotInstructionHead);
    assert!(failure.attempts.is_empty());
    no_images(&failure);
    let split = Fixture::split();
    let failure = plan(&split.request(0), &split.actions).unwrap_err();
    assert_eq!(failure.reason, Refusal::InvalidRange);
    assert!(failure.attempts.is_empty());
    no_images(&failure);
    let mut r = split.request(1);
    r.block = range(PC + 15, 1);
    r.search.max_upstream_bytes = 0;
    let failure = plan(&r, &split.actions[1..]).unwrap_err();
    assert_eq!(failure.reason, Refusal::NoPatchWindow);
    assert_eq!(failure.attempts.len(), 1);
    no_images(&failure);
    // An otherwise patchable complete leaf uses RBX as a source operand.
    let rbx = Fixture::new(&[0x48, 0x89, 0xd8, 0x90, 0x90, 0xc3], &[PC]);
    let failure = plan(&rbx.request(0), &rbx.actions).unwrap_err();
    assert!(matches!(failure.reason, Refusal::Backend(_)));
    assert_eq!(failure.attempts.len(), 1);
    no_images(&failure);
}

#[test]
fn finite_search_and_resource_refusals_keep_their_evidence() {
    let f = Fixture::new(&STRAIGHT, &[PC]);
    let mut r = f.request(0);
    r.search.max_sites = 0;
    let failure = plan(&r, &f.actions).unwrap_err();
    assert_eq!(failure.reason, Refusal::NoPatchWindow);
    assert!(failure.attempts.is_empty());
    assert_eq!(failure.search.runs.len(), 1);
    assert_eq!(failure.search.runs[0].domain, SearchDomain::PhysicalSites);
    assert_eq!(failure.search.runs[0].limit, 0);
    assert_eq!(failure.search.runs[0].examined, 0);
    assert_eq!(
        failure.search.runs[0].stop,
        SearchStop::BudgetLimited {
            remaining_at_least: 1
        }
    );
    for (candidates, ranges, examined, refusals) in [
        (0, f.allocations[0].ranges.clone(), 0, 0),
        (1, vec![], 1, 1),
    ] {
        let allocation = AllocationPolicy {
            max_candidates: candidates,
            ranges,
            ..f.allocations[0].clone()
        };
        let mut r = f.request(0);
        r.allocation = &allocation;
        let failure = plan(&r, &f.actions).unwrap_err();
        assert_eq!(failure.reason, Refusal::AllocationUnavailable);
        assert_eq!(failure.attempts.len(), 1);
        assert_eq!(failure.search.runs.len(), 2);
        let images = &failure.search.runs[1];
        assert_eq!(images.domain, SearchDomain::SelectedImages);
        assert_eq!(images.limit, candidates);
        assert_eq!(images.examined, examined);
        assert_eq!(
            images.stop,
            SearchStop::BudgetLimited {
                remaining_at_least: 1
            }
        );
        assert_eq!(failure.search.refusals.len(), refusals);
        if refusals != 0 {
            assert_eq!(
                failure.search.refusals[0].class,
                RefusalClass::AddressPolicy
            );
        }
    }
    for (mappings, bytes) in [(0, 8192), (1, 4095)] {
        let allocation = AllocationPolicy {
            max_mappings: mappings,
            max_mapped_bytes: bytes,
            ..f.allocations[0].clone()
        };
        let mut r = f.request(0);
        r.allocation = &allocation;
        let failure = plan(&r, &f.actions).unwrap_err();
        assert_eq!(failure.reason, Refusal::AllocationUnavailable);
        assert_eq!(
            failure.search.refusals[0].class,
            RefusalClass::ResourceCapacity
        );
        no_images(&failure);
    }
    let mut r = f.request(0);
    r.search.max_displaced_bytes = 4;
    let failure = plan(&r, &f.actions).unwrap_err();
    assert_eq!(failure.reason, Refusal::NoPatchWindow);
    assert_eq!(failure.search.refusals[0].reason, Refusal::NoPatchWindow);
    assert_eq!(failure.attempts.len(), 1);
    no_images(&failure);
}

#[test]
fn composition_retains_locks_and_complete_page_allocation_exclusions() {
    let f = Fixture::split();
    let (mut c, first, second) = two_members(&f);
    let before = c.clone();
    // A structural negative, never injected into PlannedBundle or published:
    // change one byte already locked by the earlier real typed plan.
    let mut parts = second.plan().parts().clone();
    parts.writes.push(ByteEdit {
        address: PC + 2,
        bytes: vec![first.plan().parts().writes[0].bytes[2] ^ 1],
    });
    let conflicting = PatchPlan::checked(parts).unwrap();
    assert_eq!(c.append(&conflicting), Err(Refusal::OwnershipConflict));
    assert_eq!(c, before);
    let mut r = f.request(1);
    r.allocation = &f.allocations[0];
    let same_mapping = after(&r, &f.actions[1..], &c).unwrap();
    assert!(
        same_mapping.plan().parts().allocations[0]
            .range
            .overlaps(first.plan().parts().allocations[0].range)
    );
    assert_eq!(
        c.append(same_mapping.plan()),
        Err(Refusal::OwnershipConflict)
    );
    assert_eq!(c, before);
    let allocation = AllocationPolicy {
        ranges: vec![range(PAGE, 8192)],
        preferred_address: Some(PAGE + 2048),
        ..f.allocations[0].clone()
    };
    let mut r = f.request(0);
    r.allocation = &allocation;
    let source_page = plan(&r, &f.actions[..1]).unwrap();
    let mut empty = f.predecessor();
    assert!(
        source_page.plan().parts().allocations[0]
            .range
            .overlaps(range(PAGE, 4096))
    );
    assert_eq!(
        empty.append(source_page.plan()),
        Err(Refusal::OwnershipConflict)
    );
    assert_eq!(empty, f.predecessor());
}

#[test]
fn grouped_bundles_clone_whole_optional_images_and_charge_all_extents() {
    let f = Fixture::split();
    let (_, first, second) = two_members(&f);
    let members = vec![first.clone(), second.clone()];
    let b = PlannedBundle::compose_grouped(
        f.originals.clone(),
        members.clone(),
        BundleBudget::default(),
        GroupingBudget::default(),
    )
    .unwrap();
    let grouping = b.grouping().unwrap();
    assert_eq!(b.images().len(), 2);
    for ((actual, grouped), member) in b.images().iter().zip(grouping.images()).zip(&members) {
        for image in [actual, grouped] {
            assert_eq!(image.address(), member.image().address());
            assert_eq!(image.bytes(), member.image().bytes());
            assert_eq!(image.controls(), member.image().controls());
            assert_eq!(image.precontext_selector(), Some(&f.selector));
            assert_eq!(image.precontext_gates(), member.image().precontext_gates());
            assert_eq!(image.entry_routes(), member.image().entry_routes());
            assert_eq!(
                image.instruction_boundaries(),
                member.image().instruction_boundaries()
            );
            assert_eq!(
                image.program_counter_mappings(),
                member.image().program_counter_mappings()
            );
        }
    }
    let a = first.plan().parts().allocations[0].range;
    let z = second.plan().parts().allocations[0].range;
    assert!(!a.overlaps(z) && !a.overlaps(range(PAGE, 4096)) && !z.overlaps(range(PAGE, 4096)));
    let virtual_bytes = a.len() + z.len();
    // Same page offsets overlap, so these images cannot share backing pages.
    assert_eq!(
        first.image().address() % 4096,
        second.image().address() % 4096
    );
    let memory = b.plan().memory();
    assert_eq!(memory.mappings, 2);
    assert_eq!(memory.virtual_bytes, virtual_bytes);
    assert_eq!(memory.backing_bytes, virtual_bytes);
    assert_eq!(memory.virtual_pages as u64, virtual_bytes / 4096);
    assert_eq!(memory.backing_pages, memory.virtual_pages);
    assert_eq!(memory.virtual_span, z.end() - a.start());
    assert_eq!(grouping.memory().backing_bytes, memory.backing_bytes);
    assert_eq!(
        GroupingPlan::new(
            vec![first.image().clone(), first.image().clone()],
            GroupingBudget::default()
        )
        .unwrap_err(),
        Refusal::OwnershipConflict
    );
    for budget in [
        BundleBudget {
            max_mappings: 1,
            ..BundleBudget::default()
        },
        BundleBudget {
            max_virtual_bytes: virtual_bytes - 1,
            ..BundleBudget::default()
        },
        BundleBudget {
            max_backing_bytes: virtual_bytes - 1,
            ..BundleBudget::default()
        },
    ] {
        assert_eq!(
            PlannedBundle::compose_grouped(
                f.originals.clone(),
                members.clone(),
                budget,
                GroupingBudget::default()
            )
            .unwrap_err(),
            Refusal::AllocationUnavailable
        );
    }
    assert_eq!(
        PlannedBundle::compose_grouped(
            f.originals.clone(),
            members,
            BundleBudget::default(),
            GroupingBudget {
                max_mappings: 1,
                ..GroupingBudget::default()
            }
        )
        .unwrap_err(),
        Refusal::AllocationUnavailable
    );
}
