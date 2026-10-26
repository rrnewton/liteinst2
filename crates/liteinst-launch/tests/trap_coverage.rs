#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::collections::BTreeSet;

use liteinst_admission::entries::{Completeness, EntryProvenance, LegalEntrySet, ResumeKind};
use liteinst_admission::scan::{
    Boundary, CandidateKind, Obligation, Policy, SiteClass, Snapshot, Verdict, WriteControl,
};
use liteinst_admission::{AddressRange, Generation, MappingId};
use liteinst_launch::trap_coverage::{
    TrapBudgetResource, TrapCoverageBudget, TrapCoveragePlan, TrapCoverageRefusal, TrapGuardRole,
};

// Small, explicitly declared planning pages keep pure byte puzzles compact.
// These tests neither allocate process pages nor claim live publication proof.
const PAGE: u64 = 64;
const BASE: u64 = 0x1_0000;
const SITE: u64 = BASE + 16;

fn budget() -> TrapCoverageBudget {
    TrapCoverageBudget {
        page_size: PAGE,
        ..TrapCoverageBudget::default()
    }
}

fn range(start: u64, len: u64) -> AddressRange {
    AddressRange::new(start, start + len).unwrap()
}

fn snapshot(pages: usize, blocks: &[(u64, &[u8])]) -> Snapshot {
    let mut bytes = vec![0xcc; pages * PAGE as usize];
    for &(address, block) in blocks {
        let offset = (address - BASE) as usize;
        bytes[offset..offset + block.len()].copy_from_slice(block);
    }
    Snapshot::new(
        MappingId(7),
        Generation(11),
        BASE,
        bytes,
        Boundary::NonExecutable,
        Boundary::NonExecutable,
        WriteControl::Owned,
    )
    .unwrap()
}

fn entries(snapshot: &Snapshot, heads: &[u64]) -> LegalEntrySet {
    LegalEntrySet::new(
        snapshot.mapping,
        snapshot.generation,
        23,
        snapshot.range(),
        Completeness::AllInstructionHeads,
        heads
            .iter()
            .map(|&pc| (pc, EntryProvenance::VerifiedInstruction)),
        [],
    )
    .unwrap()
}

fn plan(snapshot: &Snapshot, heads: &[u64]) -> TrapCoveragePlan {
    TrapCoveragePlan::build(
        snapshot,
        range(BASE, PAGE),
        &entries(snapshot, heads),
        &Policy::default(),
        budget(),
    )
    .unwrap()
}

fn assert_obligation(error: TrapCoverageRefusal, expected: Obligation) {
    match error {
        TrapCoverageRefusal::UnresolvedObligations { obligations, .. } => {
            assert!(obligations.contains(&expected), "{obligations:?}");
        }
        other => panic!("expected {expected:?}, got {other:?}"),
    }
}

fn assert_selected(plan: &TrapCoveragePlan, pc: u64, class: SiteClass, bytes: &[u8]) {
    let guard = &plan.guards()[&pc];
    assert_eq!(guard.address(), pc);
    assert_eq!(guard.original_bytes(), bytes);
    assert_eq!(guard.range(), range(pc, bytes.len() as u64));
    match guard.role() {
        TrapGuardRole::Selected(candidate) => {
            assert_eq!(candidate.address, pc);
            assert_eq!(candidate.class, class);
            assert_eq!(usize::from(candidate.len), bytes.len());
        }
        TrapGuardRole::Collateral => panic!("selected site became collateral"),
    }
}

#[test]
fn prefixed_random_guards_preserve_every_selected_suffix_and_original_refusal() {
    let cases: &[(&[u8], SiteClass, &[usize])] = &[
        (&[0x66, 0x0f, 0xc7, 0xf0], SiteClass::Rdrand, &[0, 1]),
        (&[0x48, 0x0f, 0xc7, 0xf0], SiteClass::Rdrand, &[0, 1]),
        (&[0x49, 0x0f, 0xc7, 0xf0], SiteClass::Rdrand, &[0, 1]),
        (
            &[0x66, 0x41, 0x0f, 0xc7, 0xf8],
            SiteClass::Rdseed,
            &[0, 1, 2],
        ),
    ];
    for &(bytes, class, offsets) in cases {
        let source = snapshot(1, &[(SITE, bytes)]);
        let original = source.clone();
        let facts = entries(&source, &[SITE]);
        let policy = Policy::default();
        let coverage =
            TrapCoveragePlan::build(&source, source.range(), &facts, &policy, budget()).unwrap();
        assert_eq!(coverage.guards().len(), offsets.len());
        for &offset in offsets {
            let pc = SITE + offset as u64;
            assert_selected(&coverage, pc, class, &bytes[offset..]);
            if offset != 0 {
                let obligation = Obligation::EmbeddedCandidate(pc);
                assert!(coverage.reports()[0].obligations().contains(&obligation));
                assert!(coverage.resolutions().iter().any(|resolution| {
                    resolution.obligation == obligation && resolution.guards == [SITE, pc]
                }));
            }
        }
        assert_eq!(coverage.reports()[0].verdict(), Verdict::Refused);
        assert_eq!(coverage.policy(), &policy);
        assert_eq!(coverage.entries(), &facts);
        assert_eq!(coverage.snapshot(), &original);
        assert_eq!(source, original);
    }
}

#[test]
fn default_rdpid_preserves_rdseed_suffix_with_declared_alternate_head() {
    let source = snapshot(1, &[(SITE, &[0xf3, 0x0f, 0xc7, 0xf8])]);
    let coverage = plan(&source, &[SITE, SITE + 1]);
    assert_selected(&coverage, SITE, SiteClass::Rdpid, &[0xf3, 0x0f, 0xc7, 0xf8]);
    assert_selected(&coverage, SITE + 1, SiteClass::Rdseed, &[0x0f, 0xc7, 0xf8]);
    assert_eq!(coverage.guards().len(), 2);
    assert_eq!(coverage.policy(), &Policy::default());
    assert_eq!(coverage.reports()[0].verdict(), Verdict::Refused);
    assert_eq!(
        coverage.reports()[0].obligations(),
        &[Obligation::OverlappingInstructions(SITE + 1)]
    );
    assert_eq!(coverage.resolutions().len(), 1);
    assert_eq!(coverage.resolutions()[0].guards, [SITE, SITE + 1]);
}

#[test]
fn default_rdpid_embedded_suffix_retains_its_original_classification() {
    let source = snapshot(1, &[(SITE, &[0xf3, 0x0f, 0xc7, 0xf8])]);
    let coverage = plan(&source, &[SITE]);
    assert_selected(&coverage, SITE, SiteClass::Rdpid, &[0xf3, 0x0f, 0xc7, 0xf8]);
    assert_selected(&coverage, SITE + 1, SiteClass::Rdseed, &[0x0f, 0xc7, 0xf8]);
    assert_eq!(coverage.guards().len(), 2);
    let TrapGuardRole::Selected(candidate) = coverage.guards()[&(SITE + 1)].role() else {
        panic!("missing selected suffix");
    };
    assert_eq!(candidate.kind, CandidateKind::Embedded);
    assert_eq!(coverage.policy(), &Policy::default());
    assert_eq!(coverage.reports()[0].verdict(), Verdict::Refused);
    assert_eq!(
        coverage.reports()[0].obligations(),
        &[Obligation::EmbeddedCandidate(SITE + 1)]
    );
    assert_eq!(coverage.resolutions().len(), 1);
    assert_eq!(coverage.resolutions()[0].guards, [SITE, SITE + 1]);
}

#[test]
fn immediate_candidate_adds_collateral_guard_without_relabelling_candidate() {
    let bytes = [0x48, 0xb8, 0x0f, 0xc7, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55];
    let source = snapshot(1, &[(SITE, &bytes)]);
    let coverage = plan(&source, &[SITE]);
    assert_eq!(coverage.guards().len(), 2);
    assert_eq!(coverage.guards()[&SITE].role(), TrapGuardRole::Collateral);
    assert_eq!(coverage.guards()[&SITE].original_bytes(), bytes);
    assert_selected(&coverage, SITE + 2, SiteClass::Rdrand, &[0x0f, 0xc7, 0xf0]);
    let TrapGuardRole::Selected(candidate) = coverage.guards()[&(SITE + 2)].role() else {
        panic!("missing selected role");
    };
    assert_eq!(candidate.kind, CandidateKind::Embedded);
    assert_eq!(coverage.reports()[0].candidates(), &[candidate]);
    assert_eq!(
        coverage.reports()[0].obligations(),
        &[Obligation::EmbeddedCandidate(SITE + 2)]
    );
    assert_eq!(coverage.resolutions()[0].guards, [SITE, SITE + 2]);
}

#[test]
fn collateral_guard_closure_is_transitive_across_independent_overlapping_decodes() {
    // The outer MOV does not contain the selected byte. It contains the inner
    // MOV head, whose guard becomes necessary only after the first closure step.
    let bytes = [
        0x48, 0xb8, 0x48, 0xb8, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0f, 0xc7, 0xf0,
    ];
    let source = snapshot(1, &[(SITE, &bytes)]);
    let coverage = plan(&source, &[SITE, SITE + 2]);
    assert_eq!(
        coverage.guards().keys().copied().collect::<Vec<_>>(),
        [SITE, SITE + 2, SITE + 10]
    );
    for head in [SITE, SITE + 2] {
        assert_eq!(coverage.guards()[&head].role(), TrapGuardRole::Collateral);
        assert_eq!(coverage.guards()[&head].original_bytes().len(), 10);
    }
    assert_eq!(coverage.guards()[&SITE].original_bytes(), &bytes[..10]);
    assert_eq!(
        coverage.guards()[&(SITE + 2)].original_bytes(),
        &bytes[2..12]
    );
    assert_selected(&coverage, SITE + 10, SiteClass::Rdrand, &bytes[10..]);
    assert!(!coverage.guards()[&SITE].range().contains(SITE + 10));
    assert!(coverage.resolutions().iter().any(|resolution| {
        resolution.obligation == Obligation::OverlappingInstructions(SITE + 2)
            && resolution.guards == [SITE, SITE + 2]
    }));
    assert!(coverage.resolutions().iter().any(|resolution| {
        resolution.obligation == Obligation::EmbeddedCandidate(SITE + 10)
            && resolution.guards == [SITE + 2, SITE + 10]
    }));
}

#[test]
fn crossed_instruction_adds_complete_page_and_scans_its_other_candidates() {
    let crossed = BASE + PAGE - 2;
    let later = BASE + PAGE + 20;
    let source = snapshot(
        2,
        &[(crossed, &[0x48, 0x0f, 0xc7, 0xf0]), (later, &[0x0f, 0xa2])],
    );
    let facts = entries(&source, &[crossed, later]);
    for target in [range(BASE, PAGE), range(BASE + PAGE, PAGE)] {
        let coverage =
            TrapCoveragePlan::build(&source, target, &facts, &Policy::default(), budget()).unwrap();
        assert_eq!(coverage.pages(), &BTreeSet::from([BASE, BASE + PAGE]));
        assert_eq!(coverage.reports().len(), 2);
        assert_eq!(coverage.dependencies(), &[source.range()]);
        assert_selected(
            &coverage,
            crossed,
            SiteClass::Rdrand,
            &[0x48, 0x0f, 0xc7, 0xf0],
        );
        assert_selected(
            &coverage,
            crossed + 1,
            SiteClass::Rdrand,
            &[0x0f, 0xc7, 0xf0],
        );
        assert_selected(&coverage, later, SiteClass::Cpuid, &[0x0f, 0xa2]);
        assert_eq!(coverage.guards().len(), 3);
        assert_eq!(coverage.target(), target);
        assert_eq!(coverage.page_size(), PAGE);
    }
}

#[test]
fn unresolved_candidate_is_guarded_without_inventing_entry_evidence() {
    let source = snapshot(1, &[(SITE, &[0x0f, 0xa2])]);
    let coverage = plan(&source, &[]);
    assert_eq!(coverage.guards().len(), 1);
    assert!(coverage.entries().heads().is_empty());
    let TrapGuardRole::Selected(candidate) = coverage.guards()[&SITE].role() else {
        panic!("missing selected role");
    };
    assert_eq!(candidate.kind, CandidateKind::Unresolved);
    assert_eq!(
        coverage.reports()[0].obligations(),
        &[Obligation::UnresolvedCandidate(SITE)]
    );
    assert_eq!(coverage.resolutions()[0].guards, [SITE]);
}

#[test]
fn overlap_unconnected_to_guard_closure_remains_a_refusal() {
    let source = snapshot(
        1,
        &[(
            SITE,
            &[0x48, 0xb8, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11],
        )],
    );
    let error = TrapCoveragePlan::build(
        &source,
        source.range(),
        &entries(&source, &[SITE, SITE + 2]),
        &Policy::default(),
        budget(),
    )
    .unwrap_err();
    assert_obligation(error, Obligation::OverlappingInstructions(SITE + 2));
}

#[test]
fn declared_tail_read_beyond_scan_halo_is_a_dependency_without_extra_admission() {
    let tail = BASE + PAGE + 13;
    let source = snapshot(
        2,
        &[(
            tail,
            &[0x48, 0xb8, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11],
        )],
    );
    let coverage = plan(&source, &[tail]);
    assert_eq!(coverage.pages(), &BTreeSet::from([BASE]));
    assert!(coverage.guards().is_empty());
    assert_eq!(coverage.reports()[0].dependency(), range(BASE, PAGE + 14));
    assert_eq!(coverage.dependencies(), &[range(BASE, PAGE + 23)]);
    let too_small = LegalEntrySet::new(
        source.mapping,
        source.generation,
        23,
        range(BASE, PAGE + 14),
        Completeness::AllInstructionHeads,
        [(tail, EntryProvenance::VerifiedInstruction)],
        [],
    )
    .unwrap();
    assert_obligation(
        TrapCoveragePlan::build(
            &source,
            range(BASE, PAGE),
            &too_small,
            &Policy::default(),
            budget(),
        )
        .unwrap_err(),
        Obligation::EntryScopeTooSmall,
    );
}

#[test]
fn malformed_known_head_and_stale_identity_or_generation_are_not_discharged() {
    let invalid = BASE + PAGE - 1;
    let source = snapshot(1, &[(invalid, &[0x0f])]);
    assert_obligation(
        TrapCoveragePlan::build(
            &source,
            source.range(),
            &entries(&source, &[invalid]),
            &Policy::default(),
            budget(),
        )
        .unwrap_err(),
        Obligation::InvalidKnownInstruction(invalid),
    );
    let source = snapshot(1, &[(SITE, &[0x0f, 0xa2])]);
    for (mapping, generation) in [
        (MappingId(8), source.generation),
        (source.mapping, Generation(12)),
    ] {
        let stale = LegalEntrySet::new(
            mapping,
            generation,
            23,
            source.range(),
            Completeness::AllInstructionHeads,
            [(SITE, EntryProvenance::VerifiedInstruction)],
            [],
        )
        .unwrap();
        assert_obligation(
            TrapCoveragePlan::build(
                &source,
                source.range(),
                &stale,
                &Policy::default(),
                budget(),
            )
            .unwrap_err(),
            Obligation::EntryIdentityMismatch,
        );
    }
}

#[test]
fn unknown_boundary_and_uncontrolled_writers_remain_refusals() {
    let original = snapshot(1, &[(SITE, &[0x0f, 0xa2])]);
    for before in [true, false] {
        let mut source = original.clone();
        if before {
            source.before = Boundary::Unknown;
        } else {
            source.after = Boundary::Unknown;
        }
        assert_obligation(
            TrapCoveragePlan::build(
                &source,
                source.range(),
                &entries(&source, &[SITE]),
                &Policy::default(),
                budget(),
            )
            .unwrap_err(),
            Obligation::MissingBoundaryBytes,
        );
    }
    for writes in [WriteControl::UnownedAlias, WriteControl::ExternalWriter] {
        let mut source = original.clone();
        source.writes = writes;
        assert_obligation(
            TrapCoveragePlan::build(
                &source,
                source.range(),
                &entries(&source, &[SITE]),
                &Policy::default(),
                budget(),
            )
            .unwrap_err(),
            Obligation::UncontrolledWrites,
        );
    }
    assert_eq!(original.writes, WriteControl::Owned);
}

#[test]
fn incomplete_heads_and_all_saved_resume_kinds_remain_refusals_even_on_clean_pages() {
    let source = snapshot(1, &[]);
    let partial = LegalEntrySet::new(
        source.mapping,
        source.generation,
        23,
        source.range(),
        Completeness::Partial,
        [],
        [],
    )
    .unwrap();
    assert_obligation(
        TrapCoveragePlan::build(
            &source,
            source.range(),
            &partial,
            &Policy::default(),
            budget(),
        )
        .unwrap_err(),
        Obligation::IncompleteEntries,
    );
    for kind in [
        ResumeKind::ParkedThread,
        ResumeKind::SyscallReturn,
        ResumeKind::SignalFrame,
        ResumeKind::NonlocalJump,
    ] {
        let facts = LegalEntrySet::new(
            source.mapping,
            source.generation,
            23,
            source.range(),
            Completeness::AllInstructionHeads,
            [],
            [(SITE, kind)],
        )
        .unwrap();
        assert_obligation(
            TrapCoveragePlan::build(
                &source,
                source.range(),
                &facts,
                &Policy::default(),
                budget(),
            )
            .unwrap_err(),
            Obligation::SavedResume(SITE),
        );
    }
}

#[test]
fn every_declared_budget_is_enforced_without_returning_a_partial_plan() {
    let source = snapshot(
        2,
        &[
            (SITE, &[0x66, 0x0f, 0xc7, 0xf0]),
            (BASE + PAGE - 2, &[0x48, 0x0f, 0xc7, 0xf8]),
        ],
    );
    let facts = entries(&source, &[SITE, BASE + PAGE - 2]);
    let cases = [
        (
            TrapCoverageBudget {
                max_pages: 1,
                ..budget()
            },
            TrapBudgetResource::Pages,
        ),
        (
            TrapCoverageBudget {
                max_guards: 1,
                ..budget()
            },
            TrapBudgetResource::Guards,
        ),
        (
            TrapCoverageBudget {
                max_heads: 1,
                ..budget()
            },
            TrapBudgetResource::Heads,
        ),
        (
            TrapCoverageBudget {
                max_original_bytes: 3,
                ..budget()
            },
            TrapBudgetResource::OriginalBytes,
        ),
        (
            TrapCoverageBudget {
                max_snapshot_bytes: 63,
                ..budget()
            },
            TrapBudgetResource::SnapshotBytes,
        ),
        (
            TrapCoverageBudget {
                max_rounds: 1,
                ..budget()
            },
            TrapBudgetResource::Rounds,
        ),
    ];
    for (limit, resource) in cases {
        assert_eq!(
            TrapCoveragePlan::build(
                &source,
                range(BASE, PAGE),
                &facts,
                &Policy::default(),
                limit
            )
            .unwrap_err(),
            TrapCoverageRefusal::BudgetExceeded(resource)
        );
    }
}

#[test]
fn invalid_geometry_and_outside_targets_refuse_before_planning() {
    let source = snapshot(1, &[]);
    let facts = entries(&source, &[]);
    for bad_budget in [
        TrapCoverageBudget {
            page_size: 15,
            ..budget()
        },
        TrapCoverageBudget {
            max_guards: 0,
            ..budget()
        },
    ] {
        assert_eq!(
            TrapCoveragePlan::build(
                &source,
                source.range(),
                &facts,
                &Policy::default(),
                bad_budget
            )
            .unwrap_err(),
            TrapCoverageRefusal::InvalidBudget
        );
    }
    assert_eq!(
        TrapCoveragePlan::build(
            &source,
            range(BASE + 1, PAGE - 1),
            &facts,
            &Policy::default(),
            budget()
        )
        .unwrap_err(),
        TrapCoverageRefusal::UnalignedRange
    );
    assert_eq!(
        TrapCoveragePlan::build(
            &source,
            range(BASE + PAGE, PAGE),
            &facts,
            &Policy::default(),
            budget()
        )
        .unwrap_err(),
        TrapCoverageRefusal::OutsideSnapshot
    );
}

#[test]
fn collateral_predecessor_adds_unrequested_page_and_scans_its_selected_sites() {
    // Only the second page is requested. Its embedded RDRAND lies inside a
    // MOV immediate whose head is on the first page. Guarding that head must
    // bring the entire first page into the plan, including its separate CPUID.
    let enclosing = BASE + PAGE - 4;
    let candidate = BASE + PAGE;
    let bytes = [0x48, 0xb8, 0x11, 0x11, 0x0f, 0xc7, 0xf0, 0x11, 0x11, 0x11];
    let source = snapshot(2, &[(SITE, &[0x0f, 0xa2]), (enclosing, &bytes)]);
    let original = source.clone();
    let facts = entries(&source, &[SITE, enclosing]);
    let requested = range(BASE + PAGE, PAGE);
    let coverage =
        TrapCoveragePlan::build(&source, requested, &facts, &Policy::default(), budget()).unwrap();

    assert_eq!(coverage.target(), requested);
    assert_eq!(coverage.pages(), &BTreeSet::from([BASE, BASE + PAGE]));
    assert_eq!(coverage.reports().len(), 2);
    assert_eq!(
        coverage
            .reports()
            .iter()
            .map(|report| report.target())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([range(BASE, PAGE), requested])
    );
    assert_eq!(coverage.dependencies(), &[source.range()]);
    assert_eq!(
        coverage.guards().keys().copied().collect::<Vec<_>>(),
        [SITE, enclosing, candidate]
    );
    assert_eq!(
        coverage.guards()[&enclosing].role(),
        TrapGuardRole::Collateral
    );
    assert_eq!(coverage.guards()[&enclosing].original_bytes(), bytes);
    assert_selected(&coverage, candidate, SiteClass::Rdrand, &[0x0f, 0xc7, 0xf0]);
    assert_selected(&coverage, SITE, SiteClass::Cpuid, &[0x0f, 0xa2]);
    let requested_report = coverage
        .reports()
        .iter()
        .find(|report| report.target() == requested)
        .unwrap();
    assert_eq!(requested_report.verdict(), Verdict::Refused);
    assert_eq!(
        requested_report.obligations(),
        &[Obligation::EmbeddedCandidate(candidate)]
    );
    assert_eq!(coverage.resolutions().len(), 1);
    assert_eq!(coverage.resolutions()[0].target, requested);
    assert_eq!(
        coverage.resolutions()[0].obligation,
        Obligation::EmbeddedCandidate(candidate)
    );
    assert_eq!(coverage.resolutions()[0].guards, [enclosing, candidate]);
    assert_eq!(coverage.snapshot(), &original);
    assert_eq!(source, original);
}

#[test]
fn saved_resume_in_decoded_tail_beyond_original_scan_halo_remains_a_refusal() {
    use liteinst_admission::scan::{AdmissionOracle, RuntimeScan};

    let tail = BASE + PAGE + 13;
    let saved_pc = tail + 9;
    let source = snapshot(
        2,
        &[(
            tail,
            &[0x48, 0xb8, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11],
        )],
    );
    let original = source.clone();
    let requested = range(BASE, PAGE);
    for kind in [
        ResumeKind::ParkedThread,
        ResumeKind::SyscallReturn,
        ResumeKind::SignalFrame,
        ResumeKind::NonlocalJump,
    ] {
        let facts = LegalEntrySet::new(
            source.mapping,
            source.generation,
            23,
            source.range(),
            Completeness::AllInstructionHeads,
            [(tail, EntryProvenance::VerifiedInstruction)],
            [(saved_pc, kind)],
        )
        .unwrap();
        let report = RuntimeScan.inspect(&source, requested, &facts, &Policy::default());
        assert_eq!(report.verdict(), Verdict::Clean);
        assert!(report.candidates().is_empty());
        assert!(report.obligations().is_empty());
        assert_eq!(report.dependency(), range(BASE, PAGE + 14));
        assert!(!report.dependency().contains(saved_pc));
        assert_eq!(
            TrapCoveragePlan::build(&source, requested, &facts, &Policy::default(), budget())
                .unwrap_err(),
            TrapCoverageRefusal::UnresolvedObligations {
                target: requested,
                obligations: vec![Obligation::SavedResume(saved_pc)],
            }
        );
    }
    assert_eq!(source, original);
}
