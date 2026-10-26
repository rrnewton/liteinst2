use super::*;
use crate::trap_coverage::{TrapBudgetResource, TrapCoveragePlan};
use liteinst_admission::entries::{Completeness, EntryProvenance};
use liteinst_admission::scan::{Boundary, RuntimeScan, Verdict, WriteControl};
use liteinst_admission::{Generation, MappingId};

const BASE: u64 = 0x1_0000;
const PAGE: u64 = 64;
const SITE: u64 = BASE + 16;

fn range(start: u64, size: u64) -> AddressRange {
    AddressRange::new(start, start + size).unwrap()
}
fn budget() -> TrapCoverageBudget {
    TrapCoverageBudget {
        page_size: PAGE,
        ..TrapCoverageBudget::default()
    }
}
fn source(pages: usize, blocks: &[(u64, &[u8])]) -> Snapshot {
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
fn facts(snapshot: &Snapshot, heads: &[u64], resumes: &[(u64, ResumeKind)]) -> LegalEntrySet {
    LegalEntrySet::new(
        snapshot.mapping,
        snapshot.generation,
        23,
        snapshot.range(),
        Completeness::AllInstructionHeads,
        heads
            .iter()
            .map(|&pc| (pc, EntryProvenance::VerifiedInstruction)),
        resumes.iter().copied(),
    )
    .unwrap()
}
fn pending(snapshot: &Snapshot, entries: &LegalEntrySet) -> PendingCoverage {
    PendingCoverage::build_with_oracle(
        snapshot,
        range(BASE, PAGE),
        entries,
        &Policy::default(),
        budget(),
        &RuntimeScan,
    )
    .unwrap()
}
fn assert_report_equal(actual: &ScanReport, expected: &ScanReport) {
    assert_eq!(actual.snapshot(), expected.snapshot());
    assert_eq!(actual.entries(), expected.entries());
    assert_eq!(actual.policy(), expected.policy());
    assert_eq!(actual.target(), expected.target());
    assert_eq!(actual.dependency(), expected.dependency());
    assert_eq!(actual.candidates(), expected.candidates());
    assert_eq!(actual.obligations(), expected.obligations());
    assert_eq!(actual.verdict(), expected.verdict());
    assert_eq!(actual.metrics().elapsed, expected.metrics().elapsed);
    assert_eq!(
        actual.metrics().decoded_starts,
        expected.metrics().decoded_starts
    );
    assert_eq!(actual.metrics().known_sites, expected.metrics().known_sites);
    assert_eq!(
        actual.metrics().embedded_candidates,
        expected.metrics().embedded_candidates
    );
    assert_eq!(
        actual.metrics().unresolved_candidates,
        expected.metrics().unresolved_candidates
    );
    assert_eq!(actual.metrics().by_class, expected.metrics().by_class);
}
struct ExactReport(ScanReport);
impl AdmissionOracle for ExactReport {
    fn inspect(&self, _: &Snapshot, _: AddressRange, _: &LegalEntrySet, _: &Policy) -> ScanReport {
        self.0.clone()
    }
}

#[test]
fn pending_retains_exact_refused_report_and_each_kind_without_resolving_resume() {
    let snapshot = source(1, &[(SITE, &[0x0f, 0xa2])]);
    let entries = facts(
        &snapshot,
        &[SITE],
        &[
            (SITE, ResumeKind::ParkedThread),
            (SITE, ResumeKind::SyscallReturn),
            (SITE, ResumeKind::SignalFrame),
            (SITE, ResumeKind::NonlocalJump),
        ],
    );
    let policy = Policy::default();
    let report = RuntimeScan.inspect(&snapshot, snapshot.range(), &entries, &policy);
    let oracle = ExactReport(report.clone());
    let result = PendingCoverage::build_with_oracle(
        &snapshot,
        snapshot.range(),
        &entries,
        &policy,
        budget(),
        &oracle,
    )
    .unwrap();
    assert_report_equal(&result.reports()[0], &report);
    assert_eq!(report.verdict(), Verdict::Refused);
    assert_eq!(report.obligations(), &[Obligation::SavedResume(SITE)]);
    assert!(result.resolutions().is_empty());
    assert_eq!(result.resume_requirements().len(), 2);
    for requirement in result.resume_requirements() {
        assert_eq!(requirement.address(), SITE);
        assert_eq!(requirement.kinds(), &entries.resumes()[&SITE]);
    }
    assert_eq!(
        result.resume_requirements()[0].source(),
        ResumeRequirementSource::Report {
            report_index: 0,
            obligation_index: 0
        }
    );
    assert_eq!(
        result.resume_requirements()[1].source(),
        ResumeRequirementSource::Dependency {
            index: 0,
            range: snapshot.range()
        }
    );
    assert_eq!(result.snapshot(), &snapshot);
    assert_eq!(result.entries(), &entries);
    assert_eq!(result.policy(), &policy);
    assert_eq!(
        TrapCoveragePlan::build_with_oracle(
            &snapshot,
            snapshot.range(),
            &entries,
            &policy,
            budget(),
            &oracle,
        )
        .err()
        .unwrap(),
        TrapCoverageRefusal::UnresolvedObligations {
            target: snapshot.range(),
            obligations: report.obligations().to_vec(),
        }
    );
}

#[test]
fn pending_clean_report_retains_interior_and_headless_resume_requirements() {
    let snapshot = source(1, &[(SITE, &[0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8])]);
    let entries = facts(
        &snapshot,
        &[SITE],
        &[
            (SITE + 4, ResumeKind::SignalFrame),
            (SITE + 24, ResumeKind::NonlocalJump),
        ],
    );
    let result = pending(&snapshot, &entries);
    assert_eq!(result.reports()[0].verdict(), Verdict::Clean);
    assert!(result.reports()[0].obligations().is_empty());
    assert!(result.guards().is_empty());
    assert_eq!(
        result
            .resume_requirements()
            .iter()
            .map(ResumeRequirement::address)
            .collect::<Vec<_>>(),
        [SITE + 4, SITE + 24]
    );
    for requirement in result.resume_requirements() {
        assert!(!entries.heads().contains_key(&requirement.address()));
        assert!(matches!(
            requirement.source(),
            ResumeRequirementSource::Dependency { .. }
        ));
    }
    assert_eq!(
        TrapCoveragePlan::build(
            &snapshot,
            snapshot.range(),
            &entries,
            &Policy::default(),
            budget()
        )
        .err()
        .unwrap(),
        TrapCoverageRefusal::UnresolvedObligations {
            target: snapshot.range(),
            obligations: vec![
                Obligation::SavedResume(SITE + 4),
                Obligation::SavedResume(SITE + 24)
            ],
        }
    );
}

#[test]
fn pending_decoded_tail_retains_resume_beyond_original_scan_halo_without_granting_page() {
    let head = BASE + PAGE + 13;
    let resume = head + 8;
    let snapshot = source(2, &[(head, &[0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8])]);
    let entries = facts(&snapshot, &[head], &[(resume, ResumeKind::SyscallReturn)]);
    let result = pending(&snapshot, &entries);
    assert_eq!(result.reports()[0].verdict(), Verdict::Clean);
    assert_eq!(result.reports()[0].dependency(), range(BASE, PAGE + 14));
    assert!(!result.reports()[0].dependency().contains(resume));
    assert_eq!(result.dependencies(), &[range(BASE, PAGE + 23)]);
    assert_eq!(result.pages(), &BTreeSet::from([BASE]));
    assert_eq!(
        result.decoded_heads()[&head],
        [0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8]
    );
    assert_eq!(result.resume_requirements().len(), 1);
    assert_eq!(result.resume_requirements()[0].address(), resume);
    assert_eq!(
        result.resume_requirements()[0].source(),
        ResumeRequirementSource::Dependency {
            index: 0,
            range: range(BASE, PAGE + 23)
        }
    );
    assert_eq!(
        TrapCoveragePlan::build(
            &snapshot,
            range(BASE, PAGE),
            &entries,
            &Policy::default(),
            budget()
        )
        .err()
        .unwrap(),
        TrapCoverageRefusal::UnresolvedObligations {
            target: range(BASE, PAGE),
            obligations: vec![Obligation::SavedResume(resume)],
        }
    );
}

#[test]
fn pending_preserves_default_rdpid_and_embedded_collateral_closure_with_resumes() {
    let snapshot = source(
        1,
        &[
            (SITE, &[0xf3, 0x0f, 0xc7, 0xf8]),
            (SITE + 16, &[0x48, 0xb8, 0x0f, 0xc7, 0xf0, 1, 2, 3, 4, 5]),
        ],
    );
    let entries = facts(
        &snapshot,
        &[SITE, SITE + 16],
        &[
            (SITE, ResumeKind::ParkedThread),
            (SITE + 16, ResumeKind::SyscallReturn),
        ],
    );
    let result = pending(&snapshot, &entries);
    assert_eq!(
        result.guards().keys().copied().collect::<Vec<_>>(),
        [SITE, SITE + 1, SITE + 16, SITE + 18]
    );
    assert_eq!(
        result.guards()[&(SITE + 16)].role(),
        TrapGuardRole::Collateral
    );
    assert_eq!(
        result.guards()[&(SITE + 16)].original_bytes(),
        &[0x48, 0xb8, 0x0f, 0xc7, 0xf0, 1, 2, 3, 4, 5]
    );
    assert_eq!(result.reports()[0].verdict(), Verdict::Refused);
    assert!(
        result.reports()[0]
            .obligations()
            .contains(&Obligation::EmbeddedCandidate(SITE + 1))
    );
    assert!(
        result.reports()[0]
            .obligations()
            .contains(&Obligation::EmbeddedCandidate(SITE + 18))
    );
    assert_eq!(result.resolutions().len(), 2);
    assert!(
        result
            .resolutions()
            .iter()
            .all(|item| !matches!(item.obligation, Obligation::SavedResume(_)))
    );
    assert_eq!(result.resolutions()[0].guards, [SITE, SITE + 1]);
    assert_eq!(result.resolutions()[1].guards, [SITE + 16, SITE + 18]);
    assert_eq!(result.resume_requirements().len(), 4);
}

#[test]
fn pending_keeps_each_original_resume_report_in_a_cross_page_closure() {
    let site = BASE + PAGE - 1;
    let snapshot = source(2, &[(site, &[0x0f, 0xa2])]);
    let entries = facts(&snapshot, &[site], &[(site, ResumeKind::ParkedThread)]);
    let result = pending(&snapshot, &entries);
    assert_eq!(result.pages(), &BTreeSet::from([BASE, BASE + PAGE]));
    assert_eq!(result.reports().len(), 2);
    assert_eq!(result.resume_requirements().len(), 3);
    for (index, report) in result.reports().iter().enumerate() {
        assert_eq!(report.verdict(), Verdict::Refused);
        assert_eq!(report.obligations(), &[Obligation::SavedResume(site)]);
        assert!(result.resume_requirements().iter().any(|item| item.source()
            == ResumeRequirementSource::Report {
                report_index: index,
                obligation_index: 0,
            }));
    }
    assert_eq!(result.guards()[&site].original_bytes(), &[0x0f, 0xa2]);
    assert_eq!(result.dependencies(), &[snapshot.range()]);
}

#[test]
fn pending_does_not_defer_other_scan_errors_or_foreign_oracle_facts() {
    let original = source(1, &[(SITE, &[0x0f, 0xa2])]);
    for mutation in 0..5 {
        let mut snapshot = original.clone();
        let mut entries = facts(&snapshot, &[SITE], &[(SITE, ResumeKind::ParkedThread)]);
        match mutation {
            0 => snapshot.before = Boundary::Unknown,
            1 => snapshot.writes = WriteControl::ExternalWriter,
            2 => snapshot.generation = Generation(12),
            3 => {
                entries = LegalEntrySet::new(
                    snapshot.mapping,
                    snapshot.generation,
                    23,
                    snapshot.range(),
                    Completeness::Partial,
                    [(SITE, EntryProvenance::VerifiedInstruction)],
                    [(SITE, ResumeKind::ParkedThread)],
                )
                .unwrap()
            }
            4 => {
                snapshot = source(1, &[(SITE, &[0x0f, 0xa2]), (BASE + PAGE - 1, &[0x0f])]);
                entries = facts(
                    &snapshot,
                    &[SITE, BASE + PAGE - 1],
                    &[(SITE, ResumeKind::ParkedThread)],
                );
            }
            _ => unreachable!(),
        }
        let legacy = TrapCoveragePlan::build(
            &snapshot,
            snapshot.range(),
            &entries,
            &Policy::default(),
            budget(),
        )
        .err()
        .unwrap();
        let deferred = PendingCoverage::build_with_oracle(
            &snapshot,
            snapshot.range(),
            &entries,
            &Policy::default(),
            budget(),
            &RuntimeScan,
        )
        .err()
        .unwrap();
        assert_eq!(deferred, legacy, "mutation {mutation}");
    }
    let entries = facts(&original, &[SITE], &[(SITE, ResumeKind::ParkedThread)]);
    let mut foreign = original.clone();
    foreign.mapping = MappingId(99);
    let foreign_entries = facts(&foreign, &[SITE], &[(SITE, ResumeKind::ParkedThread)]);
    let oracle = ExactReport(RuntimeScan.inspect(
        &foreign,
        foreign.range(),
        &foreign_entries,
        &Policy::default(),
    ));
    assert_eq!(
        PendingCoverage::build_with_oracle(
            &original,
            original.range(),
            &entries,
            &Policy::default(),
            budget(),
            &oracle
        )
        .err()
        .unwrap(),
        TrapCoverageRefusal::OracleFactsMismatch
    );
}

#[test]
fn pending_keeps_geometry_budget_and_entry_scope_refusals() {
    let site = BASE + PAGE - 1;
    let snapshot = source(2, &[(site, &[0x0f, 0xa2])]);
    let entries = facts(&snapshot, &[site], &[]);
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
                max_original_bytes: 1,
                ..budget()
            },
            TrapBudgetResource::OriginalBytes,
        ),
        (
            TrapCoverageBudget {
                max_snapshot_bytes: 64,
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
        let expected = TrapCoverageRefusal::BudgetExceeded(resource);
        assert_eq!(
            TrapCoveragePlan::build(
                &snapshot,
                range(BASE, PAGE),
                &entries,
                &Policy::default(),
                limit
            )
            .err()
            .unwrap(),
            expected
        );
        assert_eq!(
            PendingCoverage::build_with_oracle(
                &snapshot,
                range(BASE, PAGE),
                &entries,
                &Policy::default(),
                limit,
                &RuntimeScan
            )
            .err()
            .unwrap(),
            expected
        );
    }
    let head = BASE + PAGE + 13;
    let snapshot = source(2, &[(head, &[0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8])]);
    let entries = LegalEntrySet::new(
        snapshot.mapping,
        snapshot.generation,
        23,
        range(BASE, PAGE + 14),
        Completeness::AllInstructionHeads,
        [(head, EntryProvenance::VerifiedInstruction)],
        [],
    )
    .unwrap();
    let expected = TrapCoverageRefusal::UnresolvedObligations {
        target: range(BASE, PAGE),
        obligations: vec![Obligation::EntryScopeTooSmall],
    };
    assert_eq!(
        TrapCoveragePlan::build(
            &snapshot,
            range(BASE, PAGE),
            &entries,
            &Policy::default(),
            budget()
        )
        .err()
        .unwrap(),
        expected
    );
    assert_eq!(
        PendingCoverage::build_with_oracle(
            &snapshot,
            range(BASE, PAGE),
            &entries,
            &Policy::default(),
            budget(),
            &RuntimeScan
        )
        .err()
        .unwrap(),
        expected
    );
}
