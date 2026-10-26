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

// The identities below come from a pure shared-mm creation ledger. They are
// sizing facts only: no test below claims a native hold or a publication lease.
fn sizing_pair() -> [DynamicTask; 2] {
    use crate::lifecycle::{
        CreationEvent, CreationEventKind, CreationRequest, HoldReason, LifecycleRegistry,
    };
    let mut registry = LifecycleRegistry::new_after_exec_syscall_exit(
        crate::lifecycle::Limits {
            tasks: 2,
            processes: 1,
            address_spaces: 1,
            obligations: 16,
        },
        100,
        BASE,
    )
    .unwrap();
    let parent = registry.root_task();
    let sequence = registry.task(parent).unwrap().sequence;
    registry.resume(parent, sequence).unwrap();
    registry
        .observe_stop(parent, sequence + 1, BASE + 2, HoldReason::SyscallEntry)
        .unwrap();
    let ticket = registry
        .prepare_creation(parent, CreationRequest::Clone { flags: 0x10f00 })
        .unwrap();
    let sequence = registry.task(parent).unwrap().sequence;
    registry.resume(parent, sequence).unwrap();
    let child = registry
        .observe_creation(
            ticket,
            sequence + 1,
            CreationEvent {
                kind: CreationEventKind::Clone,
                child_tid: 101,
                child_tgid: 100,
                parent_visible_tid: 101,
                parent_pc: BASE + 2,
            },
        )
        .unwrap();
    registry
        .observe_newborn_return_ready(child, 1, BASE + 2)
        .unwrap();
    let sequence = registry.task(parent).unwrap().sequence;
    registry.resume(parent, sequence).unwrap();
    registry
        .observe_creation_exit(ticket, sequence + 1, BASE + 2, 101)
        .unwrap();
    [parent, child].map(|task| {
        let record = registry.task(task).unwrap();
        DynamicTask {
            task,
            process: record.process,
            address_space: record.address_space,
            generation: 0,
        }
    })
}

fn sizing_census(space: crate::lifecycle::AddressSpaceId, bytes: usize) -> ResumeCensus {
    ResumeCensus::new(
        17,
        space,
        0,
        census::Limits {
            epochs: 32,
            source_fact_bytes: bytes,
            reports: 128,
            origins: 128,
            witnesses: 1024,
            plan_history: 128,
        },
    )
    .unwrap()
}

fn envelope(
    domain: &Domain,
    tasks: usize,
    successors: usize,
    rebind: bool,
    plans: usize,
) -> BudgetCharge {
    combine(
        effect_charge(domain, tasks, tasks, successors, rebind, plans).unwrap(),
        refresh_charge(tasks).unwrap(),
    )
    .unwrap()
}

#[test]
fn task_bound_requires_exact_complete_identity_membership() {
    let pair = sizing_pair();
    assert_eq!(checked_task_bound(&pair[..1], &pair[..1], 0).unwrap(), 1);
    assert_eq!(
        checked_task_bound(&pair, &[pair[1], pair[0]], 0).unwrap(),
        2
    );
    let foreign = sizing_pair()[0];
    let mut other_generation = pair[1];
    other_generation.generation += 1;
    let mut other_process = pair[1];
    other_process.process = foreign.process;
    let mut other_space = pair[1];
    other_space.address_space = foreign.address_space;
    let cases = [
        (
            vec![],
            vec![],
            "dynamic task bound exceeds finite membership",
        ),
        (
            vec![pair[0]; 3],
            vec![pair[0]; 3],
            "dynamic task bound exceeds finite membership",
        ),
        (
            vec![pair[0]],
            vec![pair[0]; 3],
            "dynamic task bound exceeds finite membership",
        ),
        (
            vec![pair[0]; 2],
            vec![pair[0]; 2],
            "dynamic task bound differs from retained membership",
        ),
        (
            pair.to_vec(),
            vec![pair[0]],
            "dynamic task bound differs from retained membership",
        ),
        (
            vec![pair[0]],
            pair.to_vec(),
            "dynamic task bound differs from retained membership",
        ),
        (
            pair.to_vec(),
            vec![pair[0], foreign],
            "dynamic task bound differs from retained membership",
        ),
        (
            vec![pair[0], other_generation],
            vec![pair[0], other_generation],
            "dynamic task bound differs from retained membership",
        ),
        (
            vec![pair[0], other_process],
            vec![pair[0], other_process],
            "dynamic task bound differs from retained membership",
        ),
        (
            vec![pair[0], other_space],
            vec![pair[0], other_space],
            "dynamic task bound differs from retained membership",
        ),
    ];
    for (actual, retained, error) in cases {
        let before = (actual.clone(), retained.clone());
        assert!(
            matches!(checked_task_bound(&actual, &retained, 0), Err(GateError::Refused(message)) if message == error)
        );
        assert_eq!((actual, retained), before);
    }
}

#[test]
fn clone_growth_reserves_two_before_join_and_invalid_shapes_refuse() {
    let pair = sizing_pair();
    let domain = domain(1, &[(BASE + 32, &[0x0f, 0xa2])], &[BASE + 32], false);
    // The same successor count is retained through restoration and the second
    // pre-entry budget check, while only the parent exists in the native set.
    for current in [&pair[..1], &pair[..]] {
        let tasks = checked_task_bound(current, current, 2).unwrap();
        assert_eq!(tasks, 2);
        assert_eq!(
            effect_charge(&domain, current.len(), tasks, 2, true, 1).unwrap(),
            effect_charge(&domain, current.len(), 2, 2, true, 1).unwrap(),
        );
    }
    assert!(matches!(
        checked_task_bound(&pair[..1], &pair[..1], 3),
        Err(GateError::Refused(
            "dynamic task bound exceeds finite membership"
        ))
    ));
    for (tasks, successors, plans) in [(0, 0, 0), (3, 1, 0), (1, 2, 0), (2, 3, 0), (1, 1, 2)] {
        assert!(matches!(
            effect_charge(&domain, 1, tasks, successors, true, plans),
            Err(GateError::Refused(
                "dynamic transition exceeds finite task or plan shape"
            ))
        ));
    }
}

#[test]
fn two_task_envelope_preserves_every_original_accounting_dimension() {
    let domain = domain(1, &[(BASE + 32, &[0x0f, 0xa2])], &[BASE + 32], false);
    // Closed-form legacy envelope. Its fixed refresh counts are intentionally
    // independent of effect_charge's task arithmetic: prefix=2, completion=2,
    // rebind=4, plan=4, progress/probes=8, two settlement passes=8.
    let refresh = refresh_charge(1).unwrap();
    for successors in 0..=2 {
        for rebind in [false, true] {
            for plans in 0..=1 {
                let charge = envelope(&domain, 2, successors, rebind, plans);
                let refreshes = 2
                    + if successors == 0 { 0 } else { 18 }
                    + if rebind { 4 } else { 0 }
                    + 4 * plans;
                let mut bytes = refreshes * refresh.source_fact_bytes;
                if successors == 0 {
                    bytes += state_bound().unwrap() + size_of::<PendingInvocation>() + 1024;
                } else {
                    bytes += successors * (origin_bound().unwrap() + consume_bound().unwrap())
                        + 8 * state_bound().unwrap()
                        + 4 * size_of::<DynamicEvent>()
                        + 8192
                        + 8 * (state_bound().unwrap() + size_of::<RunPermit>() + INSTRUCTION_BYTES);
                }
                if rebind {
                    // Original one-image rebind payload, with all source facts,
                    // mapping strings and retained metadata still charged.
                    let image = &domain.images[0];
                    bytes += facts_bytes(PAGE as usize, 1, 2 + successors).unwrap()
                        + size_of::<crate::gate::domain::Image>()
                        + image.mapping.permissions.len()
                        + image.mapping.pathname.as_ref().map_or(0, String::len)
                        + size_of::<super::super::domain::RetiredGeneration>()
                        + size_of::<census::HistoryRecord>()
                        + size_of::<u64>();
                    assert!(domain.guards.is_empty());
                    assert!(domain.sites.is_empty());
                }
                let plan = plan_upper_bound(&domain, 2, successors).unwrap();
                bytes += plans * plan.source_fact_bytes;
                assert_eq!(
                    charge,
                    BudgetCharge {
                        epochs: usize::from(rebind),
                        source_fact_bytes: bytes,
                        reports: plans * plan.reports,
                        origins: successors,
                        witnesses: successors + refreshes,
                        plan_history: plans,
                    }
                );
            }
        }
    }
}

#[test]
fn singleton_scaling_keeps_probe_and_quadratic_settlement_charges_separate() {
    let domain = domain(1, &[(BASE + 32, &[0x0f, 0xa2])], &[BASE + 32], false);
    let refresh = refresh_charge(1).unwrap();
    // The retained source facts use the SAME active-origin count in this
    // comparison. Only the independently authenticated task multiplicity varies.
    for successors in 0..=1 {
        for rebind in [false, true] {
            for plans in 0..=1 {
                let one = combine(
                    effect_charge(&domain, 1, 1, successors, rebind, plans).unwrap(),
                    refresh_charge(1).unwrap(),
                )
                .unwrap();
                let two = combine(
                    effect_charge(&domain, 1, 2, successors, rebind, plans).unwrap(),
                    refresh_charge(2).unwrap(),
                )
                .unwrap();
                let completion_delta = if successors == 0 { 0 } else { 1 };
                let probe_delta = if successors == 0 { 0 } else { 4 };
                let settlement_delta = if successors == 0 { 0 } else { 6 }; // 2*2*2 - 2*1*1
                let rebind_delta = if rebind { 2 } else { 0 };
                let refresh_delta = 1
                    + completion_delta
                    + probe_delta
                    + settlement_delta
                    + rebind_delta
                    + 2 * plans;
                assert_eq!(
                    two.source_fact_bytes - one.source_fact_bytes,
                    refresh_delta * refresh.source_fact_bytes
                        + probe_delta
                            * (state_bound().unwrap() + size_of::<RunPermit>() + INSTRUCTION_BYTES)
                );
                assert_eq!(two.witnesses - one.witnesses, refresh_delta);
                assert_eq!(two.epochs, one.epochs);
                assert_eq!(two.reports, one.reports);
                assert_eq!(two.origins, one.origins);
                assert_eq!(two.plan_history, one.plan_history);
            }
        }
    }
    // Exactly 64 KiB remains charged for every full-state upper bound. No
    // compression, observed-size shortcut or smaller XSTATE limit is used.
    assert_eq!(
        state_bound().unwrap(),
        size_of::<ObservedStop>() + 64 * 1024
    );
    let one = rebind_charge(&domain, 1, 0, 1).unwrap();
    let two = rebind_charge(&domain, 1, 0, 2).unwrap();
    assert_eq!(
        one.source_fact_bytes - refresh_charge(2).unwrap().source_fact_bytes,
        two.source_fact_bytes - refresh_charge(4).unwrap().source_fact_bytes,
    );
}

#[test]
fn insufficient_effect_reservation_refuses_without_debit_or_larger_task_fallback() {
    let pair = sizing_pair();
    let domain = domain(1, &[(BASE + 32, &[0x0f, 0xa2])], &[BASE + 32], false);
    let one = envelope(&domain, 1, 1, true, 1);
    let two = envelope(&domain, 2, 2, true, 1);
    let mut census = sizing_census(pair[0].address_space, 64 * 1024 * 1024);
    let reservation = census.reserve(one).unwrap();
    let before = (
        census.charged(),
        census.used(),
        census.rows().cloned().collect::<Vec<_>>(),
        census.history().to_vec(),
    );
    assert_eq!(
        census.check_reserved(reservation, two),
        Err(census::CensusError::ReservationExhausted)
    );
    let short = BudgetCharge {
        source_fact_bytes: one.source_fact_bytes + 1,
        ..BudgetCharge::default()
    };
    assert_eq!(
        census.account_external(reservation, short),
        Err(census::CensusError::ReservationExhausted)
    );
    assert_eq!(
        (
            census.charged(),
            census.used(),
            census.rows().cloned().collect::<Vec<_>>(),
            census.history().to_vec()
        ),
        before,
    );
    assert_eq!(census.check_reserved(reservation, one), Ok(()));
    census.finish_reservation(reservation).unwrap();
}

#[test]
fn task_bound_reservations_remain_lifetime_charges_without_refunds() {
    let pair = sizing_pair();
    let domain = domain(1, &[(BASE + 32, &[0x0f, 0xa2])], &[BASE + 32], false);
    let charge = envelope(&domain, 1, 1, true, 1);
    let mut census = sizing_census(pair[0].address_space, charge.source_fact_bytes);
    let initial_used = census.used();
    let reservation = census.reserve(charge).unwrap();
    let charged = census.charged();
    assert_eq!(census.used(), initial_used);
    census.finish_reservation(reservation).unwrap();
    assert_eq!(census.charged(), charged);
    let extra = BudgetCharge {
        source_fact_bytes: 1,
        ..BudgetCharge::default()
    };
    assert_eq!(census.reserve(extra), Err(census::CensusError::Capacity));
    assert_eq!(census.charged(), charged);
    assert_eq!(census.used(), initial_used);
    assert!(census.rows().next().is_none());
    assert!(census.history().is_empty());
    assert_eq!(
        DynamicAdmissionLimits::default().source_fact_bytes,
        64 * 1024 * 1024
    );
}
