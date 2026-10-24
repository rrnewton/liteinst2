use liteinst_admission::core_bridge::{self, ExportError, ResumeCoverage};
use liteinst_admission::entries::{Completeness, EntryProvenance, LegalEntrySet};
use liteinst_admission::scan::*;
use liteinst_admission::{Generation, MappingId};
use liteinst2::contracts::{CodeIdentity, EntryCompleteness, ResumeObligation, SourceIdentity};

#[test]
fn core_export_preserves_identity_bytes_policy_and_does_not_invent_resume_proof() {
    let snapshot = Snapshot::new(
        MappingId(17),
        Generation(3),
        0x1000,
        vec![0x0f, 0xa2],
        Boundary::NonExecutable,
        Boundary::NonExecutable,
        WriteControl::Owned,
    )
    .unwrap();
    let entries = LegalEntrySet::new(
        snapshot.mapping,
        snapshot.generation,
        9,
        snapshot.range(),
        Completeness::AllInstructionHeads,
        [(0x1000, EntryProvenance::Loader)],
        [],
    )
    .unwrap();
    let report = RuntimeScan.inspect(&snapshot, snapshot.range(), &entries, &Policy::default());
    let identity = CodeIdentity {
        source: SourceIdentity([0xab; 32]),
        mapping: 17,
        generation: 3,
    };
    let exported = core_bridge::export(&report, identity, ResumeCoverage::Unresolved).unwrap();
    assert_eq!(exported.entries.identity, identity);
    assert_eq!(
        exported.entries.completeness,
        EntryCompleteness::AllInstructionHeads
    );
    assert_eq!(exported.entries.resumes, ResumeObligation::Unresolved);
    assert_eq!(exported.expected.bytes, snapshot.bytes());
    assert_eq!(exported.entry_version, 9);
    assert_eq!(exported.policy, Policy::default());
    assert_eq!(exported.selected[0].class, SiteClass::Cpuid);
    assert_eq!(
        core_bridge::export(&report, identity, ResumeCoverage::Exhaustive)
            .unwrap()
            .entries
            .resumes,
        ResumeObligation::NoneExist
    );
    assert_eq!(
        core_bridge::export(
            &report,
            CodeIdentity {
                generation: 4,
                ..identity
            },
            ResumeCoverage::Exhaustive
        )
        .unwrap_err(),
        ExportError::IdentityMismatch
    );
}

#[test]
fn ambiguous_reports_cannot_be_exported_as_positive_core_facts() {
    let snapshot = Snapshot::new(
        MappingId(1),
        Generation(1),
        0x1000,
        vec![0xb8, 0x0f, 0xa2, 0, 0],
        Boundary::NonExecutable,
        Boundary::NonExecutable,
        WriteControl::Owned,
    )
    .unwrap();
    let entries = LegalEntrySet::new(
        snapshot.mapping,
        snapshot.generation,
        1,
        snapshot.range(),
        Completeness::AllInstructionHeads,
        [(0x1000, EntryProvenance::Function)],
        [],
    )
    .unwrap();
    let report = RuntimeScan.inspect(&snapshot, snapshot.range(), &entries, &Policy::default());
    let identity = CodeIdentity {
        source: SourceIdentity([0; 32]),
        mapping: 1,
        generation: 1,
    };
    assert_eq!(
        core_bridge::export(&report, identity, ResumeCoverage::Exhaustive).unwrap_err(),
        ExportError::Refused
    );
}

#[test]
fn exhaustive_resume_census_does_not_turn_an_interior_pc_into_a_verified_head() {
    use liteinst_admission::entries::ResumeKind;
    let snapshot = Snapshot::new(
        MappingId(1),
        Generation(1),
        0x1000,
        vec![0xb8, 1, 2, 3, 4],
        Boundary::NonExecutable,
        Boundary::NonExecutable,
        WriteControl::Owned,
    )
    .unwrap();
    let entries = LegalEntrySet::new(
        snapshot.mapping,
        snapshot.generation,
        1,
        snapshot.range(),
        Completeness::AllInstructionHeads,
        [(0x1000, EntryProvenance::Function)],
        [(0x1001, ResumeKind::SignalFrame)],
    )
    .unwrap();
    let report = RuntimeScan.inspect(&snapshot, snapshot.range(), &entries, &Policy::default());
    assert_eq!(report.verdict(), Verdict::Clean);
    let identity = CodeIdentity {
        source: SourceIdentity([0; 32]),
        mapping: 1,
        generation: 1,
    };
    assert_eq!(
        core_bridge::export(&report, identity, ResumeCoverage::Exhaustive).unwrap_err(),
        ExportError::UnverifiedResume(0x1001)
    );
    assert_eq!(
        core_bridge::export(&report, identity, ResumeCoverage::Unresolved)
            .unwrap()
            .entries
            .resumes,
        ResumeObligation::Unresolved
    );
}
