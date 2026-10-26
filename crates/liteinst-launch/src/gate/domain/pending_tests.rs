use super::*;
use liteinst_admission::entries::ResumeKind;
use liteinst_admission::returns::ReturnError;
use liteinst_admission::scan::{RuntimeScan, SiteClass};

const BASE: u64 = 0x4_0000;
const SITE: u64 = BASE + 32;

fn image(blocks: &[(u64, &[u8])], heads: &[u64], resumes: &[(u64, ResumeKind)]) -> Image {
    let identity = new_core_identity().unwrap();
    let mut bytes = vec![0xcc; PAGE as usize];
    for &(pc, block) in blocks {
        let offset = (pc - BASE) as usize;
        bytes[offset..offset + block.len()].copy_from_slice(block);
    }
    let snapshot = Snapshot::new(
        MappingId(identity.mapping),
        Generation(identity.generation),
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
        17,
        snapshot.range(),
        Completeness::AllInstructionHeads,
        heads
            .iter()
            .map(|&pc| (pc, EntryProvenance::VerifiedInstruction)),
        resumes.iter().copied(),
    )
    .unwrap();
    Image {
        mapping: MemoryMapping {
            start: BASE,
            end: BASE + PAGE,
            permissions: "r-xp".into(),
            file_offset: 0,
            pathname: None,
        },
        snapshot,
        entries,
        core_identity: identity,
    }
}
fn oracle() -> GateOracle {
    GateOracle::new(CacheLimits::default()).unwrap()
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(3)
}
fn strict(
    image: &Image,
    oracle: &GateOracle,
    ledger: &CallReturnLedger,
) -> Result<PendingAdmission, GateError> {
    prepare_admission_pending_resumes(
        (image, oracle),
        BASE,
        &Policy::default(),
        ledger,
        (&BTreeMap::new(), TrapCoverageBudget::default()),
        deadline(),
    )
}
fn coverage(
    image: &Image,
    oracle: &GateOracle,
    ledger: &CallReturnLedger,
) -> Result<PendingAdmission, GateError> {
    prepare_covered_admission_pending_resumes(
        (image, oracle),
        BASE,
        &Policy::default(),
        ledger,
        (&BTreeMap::new(), TrapCoverageBudget::default()),
        deadline(),
    )
}
fn add_external_call(ledger: &mut CallReturnLedger, return_pc: u64) {
    let snapshot = Snapshot::new(
        MappingId(0x8_0000 + return_pc),
        Generation(8),
        return_pc - 5,
        vec![0xe8, 0, 0, 0, 0],
        Boundary::NonExecutable,
        Boundary::NonExecutable,
        WriteControl::Owned,
    )
    .unwrap();
    let entries = LegalEntrySet::new(
        snapshot.mapping,
        snapshot.generation,
        29,
        snapshot.range(),
        Completeness::AllInstructionHeads,
        [(return_pc - 5, EntryProvenance::VerifiedInstruction)],
        [],
    )
    .unwrap();
    assert_eq!(
        ledger.record_before_admission(&snapshot, snapshot.range(), &entries),
        Ok(1)
    );
}
fn assert_refused<T>(result: Result<T, GateError>, expected: &'static str) {
    match result {
        Err(GateError::Refused(actual)) => assert_eq!(actual, expected),
        Err(error) => panic!("expected {expected}, got {error:?}"),
        Ok(_) => panic!("expected refusal: {expected}"),
    }
}

#[test]
fn strict_pending_retains_saved_resume_while_legacy_keeps_exact_scan_refusal() {
    let image = image(
        &[(SITE, &[0x0f, 0xa2])],
        &[SITE],
        &[(SITE, ResumeKind::ParkedThread)],
    );
    let oracle = oracle();
    let ledger = CallReturnLedger::new();
    let expected = RuntimeScan.inspect(
        &image.snapshot,
        image.snapshot.range(),
        &image.entries,
        &Policy::default(),
    );
    let aliases = crate::selected::SyscallAliases::default();
    match prepare_admission(
        (&image, &oracle),
        BASE,
        &Policy::default(),
        &ledger,
        None,
        Some(&aliases),
        deadline(),
    ) {
        Err(GateError::Scan(obligations)) => assert_eq!(obligations, expected.obligations()),
        _ => panic!("legacy strict SavedResume refusal changed"),
    }
    let pending = strict(&image, &oracle, &ledger).unwrap();
    assert_eq!(pending.backend(), PendingTrapBackend::Strict);
    assert!(pending.coverage().is_none());
    assert_eq!(pending.snapshot(), &image.snapshot);
    assert_eq!(pending.entries(), &image.entries);
    assert_eq!(pending.policy(), &Policy::default());
    assert_eq!(pending.target(), image.snapshot.range());
    assert_eq!(pending.page_size(), PAGE);
    assert_eq!(pending.pages(), &BTreeSet::from([BASE]));
    assert_eq!(pending.dependencies(), &[image.snapshot.range()]);
    assert_eq!(pending.guards()[&SITE].original_bytes(), &[0x0f, 0xa2]);
    assert_eq!(pending.decoded_heads()[&SITE], [0x0f, 0xa2]);
    assert_eq!(pending.reports()[0].verdict(), Verdict::Refused);
    assert_eq!(pending.reports()[0].obligations(), expected.obligations());
    assert_eq!(pending.resume_requirements().len(), 2);
    assert!(pending.call_requirements().is_empty());
    assert!(pending.planned_calls().is_empty());
    assert_eq!(pending.planned_callers(), &[image.snapshot.range()]);
    assert_eq!(
        pending.planned_source_footprint(),
        PlannedSourceFootprint {
            records: 1,
            snapshot_bytes: PAGE as usize,
            head_facts: 1,
            resume_facts: 1,
        }
    );
    assert_eq!(ledger.obligations().count(), 0);
    let mut installed = pending.guards().clone();
    let bound = prepare_admission_pending_resumes(
        (&image, &oracle),
        BASE,
        &Policy::default(),
        &ledger,
        (&installed, TrapCoverageBudget::default()),
        deadline(),
    )
    .unwrap();
    assert_eq!(bound.installed_guards(), &installed);
    installed.clear();
    assert_eq!(bound.installed_guards(), pending.guards());
    assert!(installed.is_empty());
}

#[test]
fn pending_coverage_supports_all_seven_defaults_and_preserves_rdpid_suffix_obligation() {
    let blocks: &[(u64, &[u8])] = &[
        (SITE, &[0x0f, 0xa2]),
        (SITE + 16, &[0x0f, 0xc7, 0xf0]),
        (SITE + 32, &[0x0f, 0xc7, 0xf8]),
        (SITE + 48, &[0xf3, 0x0f, 0xc7, 0xf8]),
        (SITE + 64, &[0x0f, 0x31]),
        (SITE + 80, &[0x0f, 0x01, 0xf9]),
        (SITE + 96, &[0x0f, 0x05]),
    ];
    let heads: Vec<_> = blocks.iter().map(|(pc, _)| *pc).collect();
    let image = image(blocks, &heads, &[(SITE, ResumeKind::ParkedThread)]);
    let oracle = oracle();
    let ledger = CallReturnLedger::new();
    let pending = coverage(&image, &oracle, &ledger).unwrap();
    assert_eq!(pending.backend(), PendingTrapBackend::Coverage);
    let classes: BTreeSet<_> = pending
        .guards()
        .values()
        .map(|guard| match guard.role() {
            TrapGuardRole::Selected(candidate) => candidate.class,
            TrapGuardRole::Collateral => panic!("unexpected collateral"),
        })
        .collect();
    assert_eq!(classes, Policy::default().selected);
    assert_eq!(pending.guards().len(), 8);
    assert_eq!(
        pending.guards()[&(SITE + 49)].original_bytes(),
        &[0x0f, 0xc7, 0xf8]
    );
    assert!(
        pending.reports()[0]
            .obligations()
            .contains(&Obligation::EmbeddedCandidate(SITE + 49))
    );
    assert!(
        pending.reports()[0]
            .obligations()
            .contains(&Obligation::SavedResume(SITE))
    );
    let resolution = &pending.coverage().unwrap().resolutions()[0];
    assert_eq!(
        resolution.obligation,
        Obligation::EmbeddedCandidate(SITE + 49)
    );
    assert_eq!(resolution.guards, [SITE + 48, SITE + 49]);
    match strict(&image, &oracle, &ledger) {
        Err(GateError::Scan(obligations)) => {
            assert_eq!(obligations, pending.reports()[0].obligations())
        }
        _ => panic!("strict candidate refusal was relaxed"),
    }
}

#[test]
fn pending_strict_retains_existing_call_refusal_and_refuses_affected_future_calls() {
    let image = image(&[(SITE, &[0x0f, 0xa2])], &[SITE], &[]);
    let oracle = oracle();
    let mut ledger = CallReturnLedger::new();
    add_external_call(&mut ledger, SITE);
    let before: Vec<_> = ledger.obligations().cloned().collect();
    let message = "potential saved CALL return intersects selected publication";
    assert_refused(
        prepare_admission(
            (&image, &oracle),
            BASE,
            &Policy::default(),
            &ledger,
            None,
            None,
            deadline(),
        ),
        message,
    );
    assert_refused(strict(&image, &oracle, &ledger), message);
    assert_eq!(ledger.obligations().cloned().collect::<Vec<_>>(), before);

    let future = image_with_future_call(true);
    let empty = CallReturnLedger::new();
    assert_refused(strict(&future, &oracle, &empty), message);
    assert_eq!(empty.obligations().count(), 0);
}

fn image_with_future_call(return_is_head: bool) -> Image {
    let mut heads = vec![SITE, SITE + 16];
    if return_is_head {
        heads.push(SITE + 21);
    }
    image(
        &[
            (SITE, &[0x0f, 0xa2]),
            (SITE + 16, &[0xe8, 0, 0, 0, 0]),
            (SITE + 21, &[0x90]),
        ],
        &heads,
        &[(SITE, ResumeKind::ParkedThread)],
    )
}

#[test]
fn pending_coverage_inventories_retained_and_planned_call_origins_before_real_append() {
    let image = image_with_future_call(true);
    let oracle = oracle();
    let mut ledger = CallReturnLedger::new();
    add_external_call(&mut ledger, SITE);
    assert_eq!(
        ledger.record_independent_streams_before_admission(
            &image.snapshot,
            image.snapshot.range(),
            &image.entries
        ),
        Ok(1)
    );
    let before: Vec<_> = ledger.obligations().cloned().collect();
    let pending = coverage(&image, &oracle, &ledger).unwrap();
    assert_eq!(pending.call_requirements().len(), 3);
    assert_eq!(pending.planned_calls().len(), 1);
    let future = &pending.planned_calls()[0];
    assert_eq!(future.source_mapping, image.snapshot.mapping);
    assert_eq!(future.source_generation, image.snapshot.generation);
    assert_eq!(future.source_entry_version, image.entries.version());
    assert_eq!(future.call_address, SITE + 16);
    assert_eq!(future.call_bytes, [0xe8, 0, 0, 0, 0]);
    assert_eq!(future.return_pc, SITE + 21);
    for origin in [
        CallRequirementOrigin::Retained,
        CallRequirementOrigin::Planned,
    ] {
        assert!(
            pending
                .call_requirements()
                .iter()
                .any(|item| item.origin() == origin
                    && item.obligation() == future
                    && item.dependency() == image.snapshot.range())
        );
    }
    assert!(
        pending
            .call_requirements()
            .iter()
            .any(|item| item.origin() == CallRequirementOrigin::Retained
                && item.obligation().return_pc == SITE)
    );
    assert_eq!(
        pending.planned_source_footprint(),
        PlannedSourceFootprint {
            records: 1,
            snapshot_bytes: PAGE as usize,
            head_facts: 3,
            resume_facts: 1,
        }
    );
    assert_eq!(ledger.obligations().cloned().collect::<Vec<_>>(), before);
    // Real history checks are still mandatory, even when a temporary caller
    // census was possible. A same-generation entry change is never authorized.
    let changed = LegalEntrySet::new(
        image.snapshot.mapping,
        image.snapshot.generation,
        image.entries.version() + 1,
        image.entries.scope(),
        Completeness::AllInstructionHeads,
        image
            .entries
            .heads()
            .keys()
            .map(|&pc| (pc, EntryProvenance::VerifiedInstruction)),
        [(SITE + 21, ResumeKind::SyscallReturn)],
    )
    .unwrap();
    assert_eq!(
        ledger.record_independent_streams_before_admission(
            &image.snapshot,
            image.snapshot.range(),
            &changed
        ),
        Err(ReturnError::ConflictingEntries)
    );
    assert_eq!(ledger.obligations().cloned().collect::<Vec<_>>(), before);
}

#[test]
fn pending_coverage_keeps_missing_call_heads_and_collateral_qualification_refusals() {
    let image = image(&[(SITE, &[0x0f, 0xa2])], &[SITE], &[]);
    let oracle = oracle();
    let aliases = crate::selected::SyscallAliases::default();
    let mut ledger = CallReturnLedger::new();
    add_external_call(&mut ledger, SITE + 1);
    let message = "saved CALL return lacks a covered head";
    assert_refused(
        prepare_covered_admission(
            (&image, &oracle),
            BASE,
            &Policy::default(),
            &ledger,
            (&aliases, &BTreeMap::new(), TrapCoverageBudget::default()),
            deadline(),
        ),
        message,
    );
    assert_refused(coverage(&image, &oracle, &ledger), message);
    let empty = CallReturnLedger::new();
    assert_refused(
        coverage(&image_with_future_call(false), &oracle, &empty),
        message,
    );
    assert_eq!(empty.obligations().count(), 0);

    let unsupported = image_add_immediate();
    let message = "collateral instruction lacks native-step qualification";
    assert_refused(
        prepare_covered_admission(
            (&unsupported, &oracle),
            BASE,
            &Policy::default(),
            &empty,
            (&aliases, &BTreeMap::new(), TrapCoverageBudget::default()),
            deadline(),
        ),
        message,
    );
    assert_refused(coverage(&unsupported, &oracle, &empty), message);
}
fn image_add_immediate() -> Image {
    image(&[(SITE, &[0x48, 0x05, 0x0f, 0xa2, 0, 0])], &[SITE], &[])
}

#[test]
fn pending_cache_hit_still_inventories_fresh_call_history_and_all_resumes() {
    let image = image(
        &[(SITE, &[0x0f, 0xa2])],
        &[SITE],
        &[(SITE, ResumeKind::SyscallReturn)],
    );
    let oracle = oracle();
    let prepared = oracle.inspect_preparation(&image, image.snapshot.range(), &Policy::default());
    assert_eq!(prepared.report.verdict(), Verdict::Refused);
    let mut ledger = CallReturnLedger::new();
    let first = coverage(&image, &oracle, &ledger).unwrap();
    assert!(first.call_requirements().is_empty());
    let before = oracle.metrics().demand;
    add_external_call(&mut ledger, SITE);
    let second = coverage(&image, &oracle, &ledger).unwrap();
    let after = oracle.metrics().demand;
    assert_eq!(after.hits, before.hits + 1);
    assert_eq!(after.runtime_scans, before.runtime_scans);
    assert_eq!(second.resume_requirements(), first.resume_requirements());
    assert_eq!(
        second.reports()[0].obligations(),
        prepared.report.obligations()
    );
    assert_eq!(
        second.reports()[0].metrics().elapsed,
        prepared.report.metrics().elapsed
    );
    assert_eq!(second.call_requirements().len(), 1);
    assert_eq!(
        second.call_requirements()[0].origin(),
        CallRequirementOrigin::Retained
    );
    assert_eq!(second.call_requirements()[0].obligation().return_pc, SITE);
    assert_eq!(ledger.obligations().count(), 1);
}

#[test]
fn pending_policy_and_deadline_refusals_leave_old_api_contracts_intact() {
    let image = image(&[(SITE, &[0x0f, 0xa2])], &[SITE], &[]);
    let oracle = oracle();
    let ledger = CallReturnLedger::new();
    let mut policy = Policy::default();
    policy.selected.insert(SiteClass::Int80);
    assert_refused(
        prepare_admission_pending_resumes(
            (&image, &oracle),
            BASE,
            &policy,
            &ledger,
            (&BTreeMap::new(), TrapCoverageBudget::default()),
            deadline(),
        ),
        "pending trap path supports only default selected classes",
    );
    assert_refused(
        prepare_covered_admission_pending_resumes(
            (&image, &oracle),
            BASE,
            &policy,
            &ledger,
            (&BTreeMap::new(), TrapCoverageBudget::default()),
            deadline(),
        ),
        "pending trap path supports only default selected classes",
    );
    assert_eq!(oracle.metrics().demand.inspections, 0);
    let expired = Instant::now() - Duration::from_secs(1);
    let message = "whole-event deadline exhausted";
    assert_refused(
        prepare_admission(
            (&image, &oracle),
            BASE,
            &Policy::default(),
            &ledger,
            None,
            None,
            expired,
        ),
        message,
    );
    assert_refused(
        prepare_admission_pending_resumes(
            (&image, &oracle),
            BASE,
            &Policy::default(),
            &ledger,
            (&BTreeMap::new(), TrapCoverageBudget::default()),
            expired,
        ),
        message,
    );
    let aliases = crate::selected::SyscallAliases::default();
    assert_refused(
        prepare_covered_admission(
            (&image, &oracle),
            BASE,
            &Policy::default(),
            &ledger,
            (&aliases, &BTreeMap::new(), TrapCoverageBudget::default()),
            expired,
        ),
        message,
    );
    assert_refused(
        prepare_covered_admission_pending_resumes(
            (&image, &oracle),
            BASE,
            &Policy::default(),
            &ledger,
            (&BTreeMap::new(), TrapCoverageBudget::default()),
            expired,
        ),
        message,
    );
    assert_eq!(ledger.obligations().count(), 0);
}
