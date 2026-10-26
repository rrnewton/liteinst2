//! Pure resource-accounting regressions. These fixtures supply owned bytes and
//! immutable facts, never native exclusion or a physical publication receipt.
use super::*;
use crate::gate::ImageFacts;
use crate::trap_coverage::TrapGuardRole;
use liteinst_admission::Generation;
use liteinst_admission::entries::{Completeness, EntryProvenance, ResumeKind};
use liteinst_admission::scan::{AdmissionOracle, Boundary, Policy, RuntimeScan, Verdict};

const BASE: u64 = 0x40_0000;

fn until() -> Instant {
    Instant::now() + Duration::from_secs(3)
}

fn domain(pages: usize, blocks: &[(u64, &[u8])], heads: &[u64], coverage: bool) -> Domain {
    let mut bytes = vec![0xcc; pages * PAGE as usize];
    for &(pc, value) in blocks {
        let offset = (pc - BASE) as usize;
        bytes[offset..offset + value.len()].copy_from_slice(value);
    }
    let mapping = MemoryMapping {
        start: BASE,
        end: BASE + bytes.len() as u64,
        permissions: "r-xp".into(),
        file_offset: 0,
        pathname: None,
    };
    let facts = ImageFacts {
        start: BASE,
        bytes: bytes.clone(),
        heads: heads.iter().copied().collect(),
    };
    let options = DynamicAdmissionOptions {
        backend: if coverage {
            DynamicAdmissionBackend::CoverageTrap(TrapCoverageBudget::default())
        } else {
            DynamicAdmissionBackend::StrictTrap
        },
        ..DynamicAdmissionOptions::default()
    };
    Domain::new(
        vec![facts],
        vec![mapping],
        &options,
        until(),
        |address, len| {
            assert_eq!(address, BASE);
            assert_eq!(len, bytes.len());
            Ok(bytes.clone())
        },
    )
    .unwrap()
}

fn assert_bound(domain: &Domain, plan: &PendingAdmission, active: usize) {
    let actual = actual_plan_charge(plan, active).unwrap();
    let bound = plan_upper_bound(domain, active, 0).unwrap();
    assert!(
        actual.source_fact_bytes <= bound.source_fact_bytes,
        "actual={actual:?}, bound={bound:?}"
    );
    assert!(actual.reports <= bound.reports);
    assert_eq!(actual.plan_history, bound.plan_history);
    assert_eq!(actual.epochs, bound.epochs);
    assert_eq!(actual.origins, bound.origins);
    assert_eq!(actual.witnesses, bound.witnesses);
}

#[test]
fn cross_page_refused_candidates_and_collateral_tails_fit_complete_plan_charge() {
    let mov = BASE + PAGE - 3;
    // A declared MOV contains a declared prefixed CPUID and an embedded bare
    // CPUID. Both selected decodes cross the page boundary and repeat in the
    // two original reports; the MOV tail is retained as collateral geometry.
    let domain = domain(
        2,
        &[(mov, &[0xb8, 0x66, 0x0f, 0xa2, 0x00])],
        &[mov, mov + 1],
        true,
    );
    let image = &domain.images[0];
    let full = RuntimeScan.inspect(
        &image.snapshot,
        image.snapshot.range(),
        &image.entries,
        &domain.policy,
    );
    assert_eq!(full.verdict(), Verdict::Refused);
    assert_eq!(full.candidates().len(), 2);
    assert_eq!(domain.source_candidate_bound().unwrap(), 2);
    assert_eq!(domain.resource_scan_decoded_starts(), 2 * PAGE as usize);
    let plan = domain.plan(BASE, until()).unwrap();
    assert_eq!(plan.reports().len(), 2);
    assert_eq!(plan.pages(), &BTreeSet::from([BASE, BASE + PAGE]));
    assert_eq!(
        plan.reports()
            .iter()
            .map(|r| r.candidates().len())
            .sum::<usize>(),
        4
    );
    assert!(
        plan.reports()
            .iter()
            .all(|r| r.verdict() == Verdict::Refused)
    );
    assert_eq!(plan.guards()[&mov].role(), TrapGuardRole::Collateral);
    assert_eq!(plan.guards().len(), 3);
    assert_eq!(plan.decoded_heads()[&mov], [0xb8, 0x66, 0x0f, 0xa2, 0x00]);
    assert!(
        plan.coverage()
            .unwrap()
            .resolutions()
            .iter()
            .any(|r| r.guards.len() >= 2)
    );
    assert_bound(&domain, &plan, 0);
}

#[test]
fn strict_and_clean_plans_keep_actual_accounting_without_dense_byte_assumptions() {
    for (bytes, candidates) in [(&[0x0f, 0xa2][..], 1), (&[0x90][..], 0)] {
        for coverage in [false, true] {
            let domain = domain(1, &[(BASE + 32, bytes)], &[BASE + 32], coverage);
            assert_eq!(domain.source_candidate_bound().unwrap(), candidates);
            let plan = domain.plan(BASE, until()).unwrap();
            assert_eq!(plan.reports().len(), 1);
            assert_eq!(plan.guards().len(), candidates);
            assert_bound(&domain, &plan, 0);
            let bound = plan_upper_bound(&domain, 0, 0).unwrap();
            // This follows the fixed sparse source, not the runtime failure's
            // budget: even all retained plan facts fit one MiB for this page.
            assert!(bound.source_fact_bytes < 1024 * 1024);
            assert!(domain.resource_basis_bytes() >= PAGE as usize);
        }
    }
    assert_eq!(
        DynamicAdmissionLimits::default().source_fact_bytes,
        64 * 1024 * 1024
    );
}

#[test]
fn exact_basis_survives_only_generation_and_resume_projection_changes() {
    let mut domain = domain(1, &[(BASE + 32, &[0x0f, 0xa2])], &[BASE + 32], false);
    let original_count = domain.source_candidate_bound().unwrap();
    let original_work = domain.resource_scan_decoded_starts();
    let image = &domain.images[0];
    let projection = census::Projection {
        mapping: image.snapshot.mapping,
        generation: Generation(1),
        scope: image.snapshot.range(),
        origins: Vec::new(),
        resumes: BTreeMap::from([(
            BASE + 32,
            BTreeSet::from([ResumeKind::ParkedThread, ResumeKind::SyscallReturn]),
        )]),
    };
    domain.images = domain.projected_images(1, &[projection]).unwrap();
    domain.generation = 1;
    domain.entry_version = 1;
    assert_eq!(domain.source_candidate_bound().unwrap(), original_count);
    assert_eq!(domain.resource_scan_decoded_starts(), original_work);
    let plan = domain.plan(BASE, until()).unwrap();
    assert!(
        plan.reports()[0]
            .obligations()
            .contains(&Obligation::SavedResume(BASE + 32))
    );
    assert!(
        plan.resume_requirements()
            .iter()
            .all(|r| r.kinds().len() == 2)
    );
    assert_bound(&domain, &plan, 2);
    let old_policy = domain.policy.clone();
    domain.policy.version += 1;
    assert!(matches!(
        domain.source_candidate_bound(),
        Err(GateError::Refused(
            "dynamic resource basis identity differs"
        ))
    ));
    domain.policy = old_policy;
    let image = &mut domain.images[0];
    let old_entries = image.entries.clone();
    image.entries = LegalEntrySet::new(
        image.snapshot.mapping,
        image.snapshot.generation,
        1,
        image.snapshot.range(),
        Completeness::AllInstructionHeads,
        [(BASE + 33, EntryProvenance::VerifiedInstruction)],
        [],
    )
    .unwrap();
    assert!(matches!(
        domain.source_candidate_bound(),
        Err(GateError::Refused(
            "dynamic resource basis original source differs"
        ))
    ));
    domain.images[0].entries = old_entries;
    let image = &mut domain.images[0];
    let old_snapshot = image.snapshot.clone();
    let mut changed = old_snapshot.bytes().to_vec();
    changed[32] = 0x90;
    image.snapshot = Snapshot::new(
        old_snapshot.mapping,
        old_snapshot.generation,
        BASE,
        changed,
        old_snapshot.before,
        old_snapshot.after,
        old_snapshot.writes,
    )
    .unwrap();
    assert!(matches!(
        domain.source_candidate_bound(),
        Err(GateError::Refused(
            "dynamic resource basis original source differs"
        ))
    ));
    domain.images[0].snapshot = old_snapshot;
    assert_eq!(domain.source_candidate_bound().unwrap(), original_count);
}

#[test]
fn resource_scan_deadline_is_the_existing_deadline_and_missing_boundaries_do_not_hide_candidates() {
    let mut domain = domain(1, &[(BASE + 32, &[0x0f, 0xa2])], &[BASE + 32], false);
    domain.images[0].snapshot.before = Boundary::Unknown;
    let full = RuntimeScan.inspect(
        &domain.images[0].snapshot,
        domain.images[0].snapshot.range(),
        &domain.images[0].entries,
        &Policy::default(),
    );
    assert_eq!(full.verdict(), Verdict::Refused);
    assert!(
        full.obligations()
            .contains(&Obligation::MissingBoundaryBytes)
    );
    assert_eq!(full.candidates().len(), 1);
    // The original basis refuses a boundary change instead of silently reusing
    // its count. The cross-page case above separately retains refused candidates.
    assert!(domain.source_candidate_bound().is_err());
    let bytes = domain.images[0].snapshot.bytes().to_vec();
    let facts = ImageFacts {
        start: BASE,
        bytes: bytes.clone(),
        heads: BTreeSet::from([BASE + 32]),
    };
    let expired = Domain::new(
        vec![facts],
        domain.original_executables.clone(),
        &DynamicAdmissionOptions::default(),
        Instant::now() - Duration::from_secs(1),
        |_, _| Ok(bytes.clone()),
    );
    assert!(matches!(
        expired,
        Err(GateError::Refused("whole-event deadline exhausted"))
    ));
}
