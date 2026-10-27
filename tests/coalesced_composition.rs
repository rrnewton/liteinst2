#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
//! Live-profile planning only: no executable mappings, publication or native calls.
use liteinst2::bundle::{BundleBudget, PlannedBundle};
use liteinst2::composition::Composition;
use liteinst2::contracts::*;
use liteinst2::controls::{ControlledAction, ProbeControl};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, PlanningFailure, SearchPolicy, TacticPolicy,
    plan_coalesced_detailed, plan_coalesced_detailed_after,
};
use liteinst2::scanner::{InstructionScanner, ScanError};
use liteinst2::search::{SearchDomain, SearchStop};

const PAGE: u64 = 0x2000_0000;
const PC: u64 = PAGE + 128;
// XOR2 + XOR2 + NOP4; direct edge to a separate MOV5 + RET1 block.
const BODY: [u8; 16] = [
    0x31, 0xc0, 0x31, 0xd2, 0x0f, 0x1f, 0x40, 0x00, 0xeb, 0x00, 0xb8, 42, 0, 0, 0, 0xc3,
];
unsafe extern "C" fn callback(_: *mut liteinst2::trampoline::HookContext) {}
fn range(start: u64, len: usize) -> AddressRange {
    AddressRange::new(start, len).unwrap()
}
struct Fixture {
    entries: LegalEntrySet,
    allocations: [AllocationPolicy; 2],
    controls: [ProbeControl; 2],
    originals: Vec<ExpectedBytes>,
}
impl Fixture {
    fn new() -> Self {
        let mut page = vec![0xa5; 4096];
        page[128..144].copy_from_slice(&BODY);
        Self {
            entries: LegalEntrySet {
                identity: CodeIdentity {
                    source: SourceIdentity([92; 32]),
                    mapping: 92,
                    generation: 1,
                },
                scope: range(PC, BODY.len()),
                provenance: EntryProvenance::Declared(
                    "two complete fixture blocks; sole external entry and direct edge".into(),
                ),
                completeness: EntryCompleteness::Complete,
                entries: [PC, PC + 10]
                    .into_iter()
                    .map(|address| LegalEntry {
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
            controls: [
                ProbeControl::new(callback, true),
                ProbeControl::new(callback, true),
            ],
            originals: vec![ExpectedBytes {
                address: PAGE,
                bytes: page,
            }],
        }
    }
    fn predecessor(&self) -> Composition {
        Composition::new(self.entries.identity, self.originals.clone()).unwrap()
    }
    fn actions(&self, index: usize) -> [ControlledAction; 1] {
        [ControlledAction {
            logical_pc: PC + if index == 0 { 0 } else { 15 },
            control: self.controls[index].clone(),
        }]
    }
    fn request(&self, index: usize) -> InstallRequest<'_> {
        InstallRequest {
            identity: self.entries.identity,
            code: &BODY,
            base_address: PC,
            function: self.entries.scope,
            block: if index == 0 {
                range(PC, 10)
            } else {
                range(PC + 10, 6)
            },
            logical_pc: self.actions(index)[0].logical_pc,
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
fn authentication_failure(failure: PlanningFailure, reason: Refusal) {
    assert_eq!(failure.reason, reason);
    assert!(failure.attempts.is_empty());
    assert!(failure.search.runs.is_empty());
    assert!(!failure.search.accepted);
    assert!(!failure.search.classification_complete);
    assert_eq!(failure.search.refusals.len(), 1);
    assert_eq!(failure.search.refusals[0].reason, reason);
}

#[test]
fn ret_block_uses_original_decode_and_exact_preceding_full_body_reads() {
    let f = Fixture::new();
    let mut predecessor = f.predecessor();
    let first = plan_coalesced_detailed_after(&f.request(0), &f.actions(0), &predecessor).unwrap();
    assert_eq!(predecessor.final_bytes(), f.originals); // Planning never appends.
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
    let failure = plan_coalesced_detailed(&wrong, &f.actions(1)).unwrap_err();
    assert!(matches!(failure.reason, Refusal::Backend(_)));
    assert!(failure.attempts.is_empty());
    predecessor.append(first.plan()).unwrap();
    let before = predecessor.final_bytes().to_vec();
    let second = plan_coalesced_detailed_after(&f.request(1), &f.actions(1), &predecessor).unwrap();
    assert_eq!(predecessor.final_bytes(), before);
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
    assert!(second.metrics().search.accepted);
    let a = first.plan().parts().allocations[0].range;
    let b = second.plan().parts().allocations[0].range;
    assert!(!a.overlaps(b) && !a.overlaps(range(PAGE, 4096)) && !b.overlaps(range(PAGE, 4096)));
    predecessor.append(second.plan()).unwrap();
    let mut expected = f.originals.clone();
    for member in [&first, &second] {
        for edit in &member.plan().parts().writes {
            let at = (edit.address - PAGE) as usize;
            expected[0].bytes[at..at + edit.bytes.len()].copy_from_slice(&edit.bytes);
        }
    }
    assert_eq!(predecessor.final_bytes(), expected);
    assert_eq!(
        PlannedBundle::compose(
            f.originals.clone(),
            vec![second.clone(), first.clone()],
            BundleBudget::default()
        )
        .unwrap_err(),
        Refusal::ExpectedBytesChanged
    );
    let bundle = PlannedBundle::compose(
        f.originals.clone(),
        vec![first, second],
        BundleBudget::default(),
    )
    .unwrap();
    assert_eq!(bundle.plan().originals(), f.originals);
    assert_eq!(bundle.plan().final_bytes(), predecessor.final_bytes());
    assert_eq!(bundle.images().len(), 2);
    assert_eq!(bundle.plan().memory().mappings, 2);
}

#[test]
fn stale_generation_and_changed_original_refuse_before_search() {
    let f = Fixture::new();
    let stale = Composition::new(
        CodeIdentity {
            generation: 2,
            ..f.entries.identity
        },
        f.originals.clone(),
    )
    .unwrap();
    authentication_failure(
        plan_coalesced_detailed_after(&f.request(0), &f.actions(0), &stale).unwrap_err(),
        Refusal::StaleGeneration,
    );
    let mut changed = BODY;
    changed[11] ^= 1; // Unchanged instruction boundaries, different original immediate.
    let mut request = f.request(0);
    request.code = &changed;
    authentication_failure(
        plan_coalesced_detailed_after(&request, &f.actions(0), &f.predecessor()).unwrap_err(),
        Refusal::ExpectedBytesChanged,
    );
}

#[test]
fn already_changed_displacement_retains_exact_refusal_and_search_evidence() {
    let f = Fixture::new();
    let mut predecessor = f.predecessor();
    let first = plan_coalesced_detailed_after(&f.request(0), &f.actions(0), &predecessor).unwrap();
    predecessor.append(first.plan()).unwrap();
    let before = predecessor.final_bytes().to_vec();
    let failure =
        plan_coalesced_detailed_after(&f.request(0), &f.actions(0), &predecessor).unwrap_err();
    assert_eq!(failure.reason, Refusal::ExpectedBytesChanged);
    assert_eq!(failure.attempts.len(), 1);
    assert_eq!(
        failure.attempts[0].refusal,
        Some(Refusal::ExpectedBytesChanged)
    );
    assert_eq!(failure.search.runs.len(), 1); // No image search before require_original.
    assert_eq!(failure.search.runs[0].domain, SearchDomain::PhysicalSites);
    assert_eq!(failure.search.runs[0].examined, 1);
    assert_eq!(failure.search.runs[0].stop, SearchStop::DomainComplete);
    assert_eq!(
        failure.search.refusals[0].reason,
        Refusal::ExpectedBytesChanged
    );
    assert!(!failure.search.accepted);
    assert_eq!(predecessor.final_bytes(), before);
}
