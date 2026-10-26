#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

// Pure checks of the planner's new fact seam. No live owner or publication.
use liteinst_admission::entries::{Completeness, EntryProvenance, LegalEntrySet};
use liteinst_admission::oracle_chain::OracleChain;
use liteinst_admission::scan::{
    AdmissionOracle, Boundary, Policy, RuntimeScan, ScanReport, SiteClass, Snapshot, Verdict,
    WriteControl,
};
use liteinst_admission::{AddressRange, Generation, MappingId};
use liteinst_launch::trap_coverage::{TrapCoverageBudget, TrapCoveragePlan, TrapCoverageRefusal};

const BASE: u64 = 0x10000;
const PAGE: u64 = 64;
const SITE: u64 = BASE + 16;

fn facts() -> (Snapshot, LegalEntrySet) {
    let mut bytes = vec![0xcc; 2 * PAGE as usize];
    bytes[16..20].copy_from_slice(&[0xf3, 0x0f, 0xc7, 0xf8]);
    let snapshot = Snapshot::new(
        MappingId(71),
        Generation(5),
        BASE,
        bytes,
        Boundary::NonExecutable,
        Boundary::NonExecutable,
        WriteControl::Owned,
    )
    .unwrap();
    let entries = LegalEntrySet::new(
        snapshot.mapping,
        snapshot.generation,
        7,
        snapshot.range(),
        Completeness::AllInstructionHeads,
        [(SITE, EntryProvenance::VerifiedInstruction)],
        [],
    )
    .unwrap();
    (snapshot, entries)
}
fn target() -> AddressRange {
    AddressRange::new(BASE, BASE + PAGE).unwrap()
}
fn budget() -> TrapCoverageBudget {
    TrapCoverageBudget {
        page_size: PAGE,
        ..Default::default()
    }
}

#[test]
fn cached_coverage_facts_preserve_full_plan_and_original_refused_report() {
    let (snapshot, entries) = facts();
    let policy = Policy::default();
    let chain = OracleChain::default();
    let prepared = chain.inspect_with_evidence(&snapshot, target(), &entries, &policy);
    assert_eq!(prepared.report.verdict(), Verdict::Refused);
    let fresh = TrapCoveragePlan::build(&snapshot, target(), &entries, &policy, budget()).unwrap();
    let cached = TrapCoveragePlan::build_with_oracle(
        &snapshot,
        target(),
        &entries,
        &policy,
        budget(),
        &chain,
    )
    .unwrap();
    assert_eq!(cached.snapshot(), fresh.snapshot());
    assert_eq!(cached.entries(), fresh.entries());
    assert_eq!(cached.policy(), fresh.policy());
    assert_eq!(cached.target(), fresh.target());
    assert_eq!(cached.page_size(), fresh.page_size());
    assert_eq!(cached.pages(), fresh.pages());
    assert_eq!(cached.dependencies(), fresh.dependencies());
    assert_eq!(cached.guards(), fresh.guards());
    assert_eq!(cached.resolutions(), fresh.resolutions());
    assert_eq!(cached.reports().len(), 1);
    let report = &cached.reports()[0];
    assert_eq!(report.verdict(), Verdict::Refused);
    assert_eq!(report.snapshot(), prepared.report.snapshot());
    assert_eq!(report.entries(), prepared.report.entries());
    assert_eq!(report.policy(), prepared.report.policy());
    assert_eq!(report.target(), prepared.report.target());
    assert_eq!(report.dependency(), prepared.report.dependency());
    assert_eq!(report.candidates(), prepared.report.candidates());
    assert_eq!(report.obligations(), prepared.report.obligations());
    assert_eq!(report.metrics().elapsed, prepared.report.metrics().elapsed);
    let metrics = chain.metrics().unwrap();
    assert_eq!(metrics.inspections, 2);
    assert_eq!(metrics.runtime_scans, 1);
    assert_eq!(metrics.hits, 1);
}

struct WrongFacts(ScanReport);
impl AdmissionOracle for WrongFacts {
    fn inspect(&self, _: &Snapshot, _: AddressRange, _: &LegalEntrySet, _: &Policy) -> ScanReport {
        self.0.clone()
    }
}

#[test]
fn planner_rejects_foreign_snapshot_entries_policy_and_target_before_resolution() {
    let (snapshot, entries) = facts();
    let policy = Policy::default();
    let mut changed_snapshot = snapshot.clone();
    changed_snapshot.writes = WriteControl::ExternalWriter;
    let changed_entries = LegalEntrySet::new(
        snapshot.mapping,
        snapshot.generation,
        8,
        snapshot.range(),
        Completeness::AllInstructionHeads,
        [(SITE, EntryProvenance::VerifiedInstruction)],
        [],
    )
    .unwrap();
    let changed_policy = Policy {
        version: policy.version + 1,
        ..policy.clone()
    };
    let reports = [
        RuntimeScan.inspect(&changed_snapshot, target(), &entries, &policy),
        RuntimeScan.inspect(&snapshot, target(), &changed_entries, &policy),
        RuntimeScan.inspect(&snapshot, target(), &entries, &changed_policy),
        RuntimeScan.inspect(
            &snapshot,
            AddressRange::new(BASE + PAGE, BASE + 2 * PAGE).unwrap(),
            &entries,
            &policy,
        ),
    ];
    for report in reports {
        assert_eq!(
            TrapCoveragePlan::build_with_oracle(
                &snapshot,
                target(),
                &entries,
                &policy,
                budget(),
                &WrongFacts(report),
            )
            .unwrap_err(),
            TrapCoverageRefusal::OracleFactsMismatch,
        );
    }
}

#[test]
fn planner_policy_change_is_a_stale_miss_and_recomputes_every_candidate() {
    let (snapshot, entries) = facts();
    let chain = OracleChain::default();
    let old = TrapCoveragePlan::build_with_oracle(
        &snapshot,
        target(),
        &entries,
        &Policy::default(),
        budget(),
        &chain,
    )
    .unwrap();
    assert_eq!(old.guards().len(), 2);
    let policy = Policy {
        version: 29,
        selected: [SiteClass::Rdpid].into_iter().collect(),
    };
    let changed = TrapCoveragePlan::build_with_oracle(
        &snapshot,
        target(),
        &entries,
        &policy,
        budget(),
        &chain,
    )
    .unwrap();
    let fresh = TrapCoveragePlan::build(&snapshot, target(), &entries, &policy, budget()).unwrap();
    assert_eq!(changed.guards().len(), 1);
    assert_eq!(changed.guards(), fresh.guards());
    assert_eq!(changed.dependencies(), fresh.dependencies());
    assert_eq!(changed.resolutions(), fresh.resolutions());
    assert_eq!(changed.reports()[0].policy(), &policy);
    assert_eq!(
        changed.reports()[0].candidates(),
        fresh.reports()[0].candidates()
    );
    assert_eq!(
        changed.reports()[0].obligations(),
        fresh.reports()[0].obligations()
    );
    let metrics = chain.metrics().unwrap();
    assert_eq!(metrics.runtime_scans, 2);
    assert_eq!(metrics.stale, 1);
    assert_eq!(metrics.hits, 0);
}
