use std::collections::BTreeSet;
use std::sync::{Arc, Barrier};

use liteinst_admission::entries::{Completeness, EntryProvenance, LegalEntrySet, ResumeKind};
use liteinst_admission::model::*;
use liteinst_admission::scan::*;
use liteinst_admission::{AddressRange, Generation, MappingId};

const A: u64 = 0x10_0000;
const B: u64 = A + 0x4000;
const C: u64 = B + 0x4000;

fn range(base: u64) -> AddressRange {
    AddressRange::new(base, base + 4096).unwrap()
}
fn snapshot(base: u64, generation: u64) -> Snapshot {
    // Closed-world fixture: the only permitted instruction is cpuid followed
    // by INT3. Other bytes are padding, not an attested application CFG.
    let mut bytes = vec![0xcc; 4096];
    bytes[64..66].copy_from_slice(&[0x0f, 0xa2]);
    Snapshot::new(
        MappingId(base),
        Generation(generation),
        base,
        bytes,
        Boundary::NonExecutable,
        Boundary::NonExecutable,
        WriteControl::Owned,
    )
    .unwrap()
}
fn entries(s: &Snapshot) -> LegalEntrySet {
    LegalEntrySet::new(
        s.mapping,
        s.generation,
        s.generation.0,
        s.range(),
        Completeness::AllInstructionHeads,
        [
            (s.range().start() + 64, EntryProvenance::VerifiedInstruction),
            (s.range().start() + 66, EntryProvenance::VerifiedInstruction),
        ],
        [],
    )
    .unwrap()
}
fn dependency(base: u64) -> MockDependency {
    let s = snapshot(base, 1);
    MockDependency::new(range(base), s.clone(), entries(&s), Policy::default()).unwrap()
}
fn register(g: &ModelGate, base: u64) {
    let s = snapshot(base, 1);
    g.register(range(base), s.clone(), entries(&s), Policy::default())
        .unwrap();
}

#[derive(Default)]
struct Publisher {
    extra: Vec<MockDependency>,
    omit: bool,
    failure: Option<PublicationFailure>,
    saved_receipt: Option<MockReceipt>,
    replay: bool,
    saved_plan: Option<MockPlan>,
    reuse_plan: bool,
    calls: usize,
}
impl MockPublisher for Publisher {
    fn plan(&mut self, facts: &ScanReport) -> Result<MockPlan, ModelError> {
        if self.reuse_plan {
            return Ok(self.saved_plan.clone().unwrap());
        }
        let sites = facts
            .candidates()
            .iter()
            .filter(|_| !self.omit)
            .map(|c| c.address);
        let plan = MockPlan::new(facts, self.extra.clone(), sites);
        self.saved_plan = Some(plan.clone());
        Ok(plan)
    }
    fn publish(
        &mut self,
        _plan: &MockPlan,
        lease: &ModelLease<'_>,
    ) -> Result<MockReceipt, PublicationFailure> {
        self.calls += 1;
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        if self.replay {
            return Ok(self.saved_receipt.clone().unwrap());
        }
        let receipt = lease.receipt();
        self.saved_receipt = Some(receipt.clone());
        Ok(receipt)
    }
}

#[test]
fn concurrent_first_requests_publish_exactly_once() {
    let gate = Arc::new(ModelGate::new());
    register(&gate, A);
    let barrier = Arc::new(Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let gate = gate.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut publisher = Publisher::default();
                barrier.wait();
                (gate.admit(A, &mut publisher).unwrap(), publisher.calls)
            })
        })
        .collect();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(
        results
            .iter()
            .filter(|r| r.0 == Admission::Published)
            .count(),
        1
    );
    assert_eq!(results.iter().map(|r| r.1).sum::<usize>(), 1);
    assert_eq!(gate.publications().unwrap(), 1);
    assert_eq!(gate.state(A).unwrap(), PageState::Admitted);
}

#[test]
fn missing_site_coverage_never_calls_publish() {
    let gate = ModelGate::new();
    register(&gate, A);
    let mut publisher = Publisher {
        omit: true,
        ..Publisher::default()
    };
    assert_eq!(
        gate.admit(A, &mut publisher),
        Err(ModelError::WrongCoverage)
    );
    assert_eq!(publisher.calls, 0);
    assert_eq!(gate.state(A).unwrap(), PageState::Refused);
}

#[test]
fn absent_adjacent_dependency_refuses_without_publication() {
    let gate = ModelGate::new();
    register(&gate, A);
    let mut publisher = Publisher {
        extra: vec![dependency(A + 4096)],
        ..Publisher::default()
    };
    assert_eq!(
        gate.admit(A, &mut publisher),
        Err(ModelError::MissingPage(A + 4096))
    );
    assert_eq!(publisher.calls, 0);
}

#[test]
fn failures_before_and_after_write_keep_the_right_bundle_gated() {
    for failure in [
        PublicationFailure::BeforeWrite,
        PublicationFailure::PossiblyWritten,
    ] {
        let gate = ModelGate::new();
        register(&gate, A);
        register(&gate, B);
        let mut publisher = Publisher {
            extra: vec![dependency(B)],
            failure: Some(failure),
            ..Publisher::default()
        };
        assert_eq!(
            gate.admit(A, &mut publisher),
            Err(ModelError::PublicationFailed)
        );
        assert_eq!(gate.publications().unwrap(), 0);
        if failure == PublicationFailure::BeforeWrite {
            assert_eq!(gate.state(A).unwrap(), PageState::Refused);
            assert_eq!(gate.state(B).unwrap(), PageState::Unknown);
        } else {
            assert_eq!(gate.state(A).unwrap(), PageState::Poisoned);
            assert_eq!(gate.state(B).unwrap(), PageState::Poisoned);
            let next = snapshot(B, 2);
            assert_eq!(
                gate.invalidate(B, next.clone(), entries(&next)),
                Err(ModelError::Poisoned)
            );
        }
    }
}

#[test]
fn receipts_cannot_be_replayed_across_transactions_or_gates() {
    let gate = ModelGate::new();
    register(&gate, A);
    register(&gate, B);
    let mut publisher = Publisher::default();
    gate.admit(A, &mut publisher).unwrap();
    publisher.replay = true;
    assert_eq!(gate.admit(B, &mut publisher), Err(ModelError::StaleReceipt));
    assert_eq!(gate.state(B).unwrap(), PageState::Poisoned);
    let second = ModelGate::new();
    register(&second, A);
    assert_eq!(
        second.admit(A, &mut publisher),
        Err(ModelError::StaleReceipt)
    );
}

#[test]
fn stale_plan_cannot_cross_a_generation_change() {
    let gate = ModelGate::new();
    register(&gate, A);
    let old = snapshot(A, 1);
    let facts = RuntimeScan.inspect(&old, range(A), &entries(&old), &Policy::default());
    let mut publisher = Publisher::default();
    publisher.plan(&facts).unwrap();
    publisher.reuse_plan = true;
    let next = snapshot(A, 2);
    gate.invalidate(A, next.clone(), entries(&next)).unwrap();
    assert_eq!(gate.admit(A, &mut publisher), Err(ModelError::StalePlan));
    assert_eq!(publisher.calls, 0);
}

#[test]
fn admitted_bundle_locks_its_unadmitted_dependencies_and_invalidation_revokes_it() {
    let gate = ModelGate::new();
    for base in [A, B, C] {
        register(&gate, base);
    }
    gate.admit(
        A,
        &mut Publisher {
            extra: vec![dependency(B), dependency(C)],
            ..Publisher::default()
        },
    )
    .unwrap();
    let mut publisher = Publisher::default();
    assert_eq!(
        gate.admit(B, &mut publisher),
        Err(ModelError::UnsafeDependency(B))
    );
    assert_eq!(publisher.calls, 0);
    assert_eq!(gate.state(A).unwrap(), PageState::Admitted);
    let next = snapshot(C, 2);
    assert_eq!(
        gate.invalidate(C, next.clone(), entries(&next)).unwrap(),
        BTreeSet::from([A, C])
    );
    for base in [A, C] {
        assert_eq!(gate.state(base).unwrap(), PageState::Invalidated);
    }
    assert_eq!(
        gate.admit(A, &mut Publisher::default()),
        Err(ModelError::UnsafeDependency(A))
    );
    assert_eq!(
        gate.admit(C, &mut Publisher::default()),
        Ok(Admission::Published)
    );
}

#[test]
fn changed_extra_dependency_invalidates_a_cached_plan_even_if_primary_is_unchanged() {
    let gate = ModelGate::new();
    register(&gate, A);
    register(&gate, B);
    let original = snapshot(A, 1);
    let facts = RuntimeScan.inspect(&original, range(A), &entries(&original), &Policy::default());
    let mut publisher = Publisher {
        extra: vec![dependency(B)],
        ..Publisher::default()
    };
    publisher.plan(&facts).unwrap();
    publisher.reuse_plan = true;
    let next = snapshot(B, 2);
    gate.invalidate(B, next.clone(), entries(&next)).unwrap();
    assert_eq!(gate.admit(A, &mut publisher), Err(ModelError::StalePlan));
    assert_eq!(publisher.calls, 0);
}

#[test]
fn saved_resumes_and_aliases_in_a_victim_page_are_refused() {
    for alias in [false, true] {
        let gate = ModelGate::new();
        register(&gate, A);
        let mut s = snapshot(B, 1);
        if alias {
            s.writes = WriteControl::UnownedAlias;
        }
        let e = LegalEntrySet::new(
            s.mapping,
            s.generation,
            1,
            s.range(),
            Completeness::AllInstructionHeads,
            [(B + 64, EntryProvenance::VerifiedInstruction)],
            if alias {
                vec![]
            } else {
                vec![(B + 65, ResumeKind::SyscallReturn)]
            },
        )
        .unwrap();
        gate.register(range(B), s, e, Policy::default()).unwrap();
        let mut publisher = Publisher {
            extra: vec![dependency(B)],
            ..Publisher::default()
        };
        assert_eq!(
            gate.admit(A, &mut publisher),
            Err(ModelError::UnsafeDependency(B))
        );
        assert_eq!(publisher.calls, 0);
    }
}

#[test]
fn cross_page_snapshot_bytes_must_match_registered_neighbor() {
    let gate = ModelGate::new();
    let mut bytes = vec![0x90; 8192];
    bytes[4095..4097].copy_from_slice(&[0x0f, 0xa2]);
    let s = Snapshot::new(
        MappingId(A),
        Generation(1),
        A,
        bytes.clone(),
        Boundary::NonExecutable,
        Boundary::NonExecutable,
        WriteControl::Owned,
    )
    .unwrap();
    let e = LegalEntrySet::new(
        s.mapping,
        s.generation,
        1,
        s.range(),
        Completeness::AllInstructionHeads,
        [(A + 4095, EntryProvenance::VerifiedInstruction)],
        [],
    )
    .unwrap();
    gate.register(range(A), s.clone(), e.clone(), Policy::default())
        .unwrap();
    bytes[4096] = 0x90;
    let changed = Snapshot::new(
        MappingId(A),
        Generation(1),
        A,
        bytes,
        Boundary::NonExecutable,
        Boundary::NonExecutable,
        WriteControl::Owned,
    )
    .unwrap();
    gate.register(range(A + 4096), changed, e, Policy::default())
        .unwrap();
    let mut publisher = Publisher::default();
    assert_eq!(gate.admit(A, &mut publisher), Err(ModelError::BytesChanged));
    assert_eq!(publisher.calls, 0);
}

#[test]
fn poisoned_lock_from_panicking_publisher_fails_closed() {
    struct PanicPublisher;
    impl MockPublisher for PanicPublisher {
        fn plan(&mut self, _: &ScanReport) -> Result<MockPlan, ModelError> {
            panic!("injected planner failure");
        }
        fn publish(
            &mut self,
            _: &MockPlan,
            _: &ModelLease<'_>,
        ) -> Result<MockReceipt, PublicationFailure> {
            unreachable!()
        }
    }
    let gate = ModelGate::new();
    register(&gate, A);
    assert!(std::panic::catch_unwind(|| gate.admit(A, &mut PanicPublisher)).is_err());
    assert_eq!(gate.state(A), Err(ModelError::Poisoned));
    assert_eq!(
        gate.admit(A, &mut Publisher::default()),
        Err(ModelError::Poisoned)
    );
}

#[test]
fn refused_shared_dependency_cannot_reach_a_partially_writing_publisher() {
    let gate = ModelGate::new();
    register(&gate, A);
    register(&gate, B);
    gate.admit(
        A,
        &mut Publisher {
            extra: vec![dependency(B)],
            ..Publisher::default()
        },
    )
    .unwrap();
    let mut publisher = Publisher {
        failure: Some(PublicationFailure::PossiblyWritten),
        ..Publisher::default()
    };
    assert_eq!(
        gate.admit(B, &mut publisher),
        Err(ModelError::UnsafeDependency(B))
    );
    assert_eq!(publisher.calls, 0);
    assert_eq!(gate.state(A).unwrap(), PageState::Admitted);
}

#[test]
fn adding_an_executable_neighbor_cannot_invalidate_a_closed_boundary_claim_silently() {
    let gate = ModelGate::new();
    let mut bytes = vec![0x90; 4096];
    bytes[4095] = 0x0f;
    let s = Snapshot::new(
        MappingId(A),
        Generation(1),
        A,
        bytes,
        Boundary::NonExecutable,
        Boundary::NonExecutable,
        WriteControl::Owned,
    )
    .unwrap();
    let e = LegalEntrySet::new(
        s.mapping,
        s.generation,
        1,
        s.range(),
        Completeness::Partial,
        [],
        [],
    )
    .unwrap();
    gate.register(range(A), s, e, Policy::default()).unwrap();
    gate.admit(A, &mut Publisher::default()).unwrap();
    let mut bytes = vec![0x90; 4096];
    bytes[0] = 0xa2;
    let neighbor = Snapshot::new(
        MappingId(A + 4096),
        Generation(1),
        A + 4096,
        bytes,
        Boundary::Unknown,
        Boundary::NonExecutable,
        WriteControl::Owned,
    )
    .unwrap();
    let e = LegalEntrySet::new(
        neighbor.mapping,
        neighbor.generation,
        1,
        neighbor.range(),
        Completeness::Partial,
        [],
        [],
    )
    .unwrap();
    assert_eq!(
        gate.register(range(A + 4096), neighbor, e, Policy::default()),
        Err(ModelError::BoundaryConflict)
    );
    assert_eq!(gate.state(A).unwrap(), PageState::Admitted);
    assert_eq!(gate.state(A + 4096), Err(ModelError::MissingPage(A + 4096)));
}

#[test]
fn new_boundary_claims_cannot_exclude_already_registered_code() {
    let gate = ModelGate::new();
    let mut first = snapshot(A, 1);
    first.after = Boundary::Unknown;
    gate.register(range(A), first.clone(), entries(&first), Policy::default())
        .unwrap();
    let neighbor = snapshot(A + 4096, 1);
    assert_eq!(
        gate.register(
            range(A + 4096),
            neighbor.clone(),
            entries(&neighbor),
            Policy::default()
        ),
        Err(ModelError::BoundaryConflict)
    );
    assert_eq!(gate.state(A).unwrap(), PageState::Unknown);
}

#[test]
fn replacement_boundary_conflict_does_not_mutate_or_invalidate_current_facts() {
    let gate = ModelGate::new();
    let original = Snapshot::new(
        MappingId(A),
        Generation(1),
        A,
        vec![0x90; 8192],
        Boundary::NonExecutable,
        Boundary::NonExecutable,
        WriteControl::Owned,
    )
    .unwrap();
    let e = LegalEntrySet::new(
        original.mapping,
        original.generation,
        1,
        original.range(),
        Completeness::Partial,
        [],
        [],
    )
    .unwrap();
    for base in [A, A + 4096] {
        gate.register(range(base), original.clone(), e.clone(), Policy::default())
            .unwrap();
    }
    let conflicting = snapshot(A, 2);
    assert_eq!(
        gate.invalidate(A, conflicting.clone(), entries(&conflicting)),
        Err(ModelError::BoundaryConflict)
    );
    assert_eq!(gate.state(A).unwrap(), PageState::Unknown);
    assert_eq!(gate.state(A + 4096).unwrap(), PageState::Unknown);
    let mut publisher = Publisher::default();
    gate.admit(A, &mut publisher).unwrap();
    assert_eq!(
        publisher.saved_plan.unwrap().facts().snapshot().generation,
        Generation(1)
    );
}
