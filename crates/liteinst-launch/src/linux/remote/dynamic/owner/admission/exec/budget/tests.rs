//! Pure storage/envelope controls. Prepared buffers and immutable Domains are
//! real allocations; all lifecycle/state inputs are synthetic. These cases do
//! not establish native exec, source completeness, exclusion, or publication.
use super::*;
use crate::lifecycle::LifecycleRegistry;
use crate::linux::remote::dynamic::owner::exec_journal::ExecJournalWriter;
use crate::selected::{SyscallAliases, decode};

const SESSION: u64 = 81;
const PC: u64 = 0x401000;
const BASE: u64 = 0x400000;
const SECOND: u64 = 0x500000;
const UNCENSUSED: u64 = 0x600000;

fn profile() -> DynamicExecProfile {
    DynamicExecProfile {
        max_capture_images: 2,
        max_capture_bytes: 4096,
        max_total_capture_bytes: 8192,
        max_argument_pointers: 8,
        max_string_bytes: 1024,
    }
}

fn registry() -> LifecycleRegistry {
    LifecycleRegistry::new(
        crate::lifecycle::Limits {
            tasks: 2,
            processes: 1,
            address_spaces: 2,
            obligations: 8,
        },
        101,
        PC,
    )
    .unwrap()
}

fn limits() -> census::Limits {
    let default = DynamicAdmissionOptions::default().limits;
    assert_eq!(default.source_fact_bytes, 64 * 1024 * 1024);
    census::Limits {
        epochs: default.epochs,
        source_fact_bytes: default.source_fact_bytes,
        reports: default.reports,
        origins: default.origins,
        witnesses: default.witnesses,
        plan_history: default.plan_history,
    }
}

fn census_with(limits: census::Limits) -> ResumeCensus {
    let registry = registry();
    let row = registry.task(registry.root_task()).unwrap();
    ResumeCensus::new(SESSION, row.address_space, 0, limits).unwrap()
}

fn pending() -> (PendingInvocation, ExecCensusBinding) {
    let registry = registry();
    let row = registry.task(registry.root_task()).unwrap();
    let task = DynamicTask {
        task: row.id,
        process: row.process,
        address_space: row.address_space,
        generation: 0,
    };
    let registers = RegisterSnapshot {
        r15: 15,
        r14: 14,
        r13: 13,
        r12: 12,
        rbp: 11,
        rbx: 10,
        r11: 9,
        r10: 8,
        r9: 7,
        r8: 6,
        rax: libc::SYS_execve as u64,
        rcx: 4,
        rdx: 0x1180,
        rsi: 0x1100,
        rdi: 0x1000,
        orig_rax: u64::MAX,
        rip: PC,
        cs: 0x33,
        eflags: 0x202,
        rsp: 0x2f00,
        ss: 0x2b,
        fs_base: 0x3500,
        gs_base: 0x4500,
        ds: 0,
        es: 0,
        fs: 0,
        gs: 0,
    };
    let stop = DynamicStop {
        session: SESSION,
        sequence: 23,
        tid: 101,
        task: Some(task.task),
    };
    let before = ObservedStop {
        token: stop.clone(),
        task,
        logical_pc: PC,
        registers,
        xstate: vec![0x5a; 832],
        signal_mask: 0x600,
        phase: StopPhase::UserCheckpoint,
        signal: None,
    };
    let mut census = ResumeCensus::new(SESSION, task.address_space, 0, limits()).unwrap();
    let reservation = census
        .reserve(BudgetCharge {
            epochs: 2,
            source_fact_bytes: 1024 * 1024,
            reports: 2,
            origins: 2,
            witnesses: 2,
            plan_history: 2,
        })
        .unwrap();
    let origin = census
        .insert(reservation, OriginKind::CurrentHeldPc, PC, before.clone())
        .unwrap();
    let binding = census
        .prepare_exec_mm(
            reservation,
            origin,
            ExecutionId::from_owner(SESSION, 9).unwrap(),
        )
        .unwrap()
        .binding();
    (
        PendingInvocation {
            token: PendingToken {
                stop: stop.clone(),
                task,
                epoch: 0,
                plan: 7,
                invocation: 9,
            },
            stop: AdmissionStop {
                token: stop,
                identity: task,
                phase: AdmissionPhase::Restored,
                signal: None,
            },
            input: SelectedInput::new(
                decode(PC, &[0x0f, 0x05], &SyscallAliases::new()).unwrap(),
                registers,
            )
            .unwrap(),
            before,
            until: Instant::now() + Duration::from_secs(60),
        },
        binding,
    )
}

fn mapping(start: u64) -> MemoryMapping {
    MemoryMapping {
        start,
        end: start + 4096,
        permissions: "r-xp".into(),
        file_offset: 0,
        pathname: Some("/fixture".into()),
    }
}

#[derive(Debug, Eq, PartialEq)]
struct CensusView {
    charged: BudgetCharge,
    used: BudgetCharge,
    generation: u64,
    rows: Vec<census::OriginRow>,
    history: Vec<census::HistoryRecord>,
}
fn view(census: &ResumeCensus) -> CensusView {
    CensusView {
        charged: census.charged(),
        used: census.used(),
        generation: census.generation(),
        rows: census.rows().cloned().collect(),
        history: census.history().to_vec(),
    }
}
fn refused<T>(result: Result<T, GateError>, expected: &'static str) {
    assert!(matches!(result, Err(GateError::Refused(actual)) if actual == expected));
}

#[test]
fn prepared_allocations_fit_the_bound_and_each_added_payload_is_charged_once() {
    let profile = profile();
    profile
        .validate(&DynamicAdmissionOptions::default())
        .unwrap();
    let (pending, binding) = pending();
    let inputs = ExecInputs::prepare(&profile).unwrap();
    let seal = PreparedExecSeal::prepare(binding, &pending).unwrap();
    let scratch = PreparedExecSources::new(&profile).unwrap();
    let mut journal = ExecJournalWriter::new(SESSION);
    let journal_base = journal.allocated_bytes();
    let prepared = journal
        .prepare(
            &pending.token,
            &pending.input,
            &TaskStateSnapshot {
                registers: pending.before.registers,
                xstate: pending.before.xstate.clone(),
                mask: pending.before.signal_mask,
            },
            pending.until,
        )
        .unwrap();
    let increment = prepared
        .allocated_bytes()
        .checked_sub(journal_base)
        .unwrap();
    // The actual journal has fourteen fixed MAX payloads, independently of the
    // shorter successful synthetic state. No reduced diagnostic buffer claim.
    assert!(increment >= 14 * MAX_XSTATE);
    let mut forbidden = Vec::with_capacity(3);
    forbidden.push(BASE..BASE + 4096);
    let maps = vec![mapping(BASE)];
    let actual =
        initial_attempt_bytes(&inputs, &seal, &scratch, &forbidden, &maps, increment).unwrap();
    let bound = initial_bound(&profile, forbidden.capacity(), &maps, increment).unwrap();
    assert!(actual <= bound, "actual={actual}, bound={bound}");
    assert!(actual > increment + 2 * MAX_XSTATE);

    // Capacity, not current length, owns this retained allocation. The same
    // one forbidden range occupies two deliberately different capacities.
    let mut roomy = Vec::with_capacity(11);
    roomy.extend_from_slice(&forbidden);
    assert_eq!(roomy, forbidden);
    assert_eq!(
        initial_attempt_bytes(&inputs, &seal, &scratch, &roomy, &maps, increment).unwrap() - actual,
        (roomy.capacity() - forbidden.capacity()) * size_of::<Range<u64>>(),
    );
    assert_eq!(
        initial_attempt_bytes(&inputs, &seal, &scratch, &forbidden, &maps, increment + 37).unwrap()
            - actual,
        37,
    );
    let mut larger = profile.clone();
    larger.max_string_bytes += 17;
    let more_inputs = ExecInputs::prepare(&larger).unwrap();
    assert_eq!(
        more_inputs.allocated_bytes().unwrap() - inputs.allocated_bytes().unwrap(),
        34
    );
    assert_eq!(
        initial_attempt_bytes(&more_inputs, &seal, &scratch, &forbidden, &maps, increment).unwrap()
            - actual,
        34,
    );
    let mut retained_maps = maps.clone();
    let mut path = String::with_capacity(257);
    path.push_str("/fixture");
    retained_maps[0].pathname = Some(path);
    let before_strings =
        maps[0].permissions.capacity() + maps[0].pathname.as_ref().unwrap().capacity();
    let after_strings = retained_maps[0].permissions.capacity()
        + retained_maps[0].pathname.as_ref().unwrap().capacity();
    assert_eq!(retained_maps, maps);
    assert_eq!(
        mapping_bytes(&retained_maps).unwrap() - mapping_bytes(&maps).unwrap(),
        (retained_maps.capacity() - maps.capacity()) * size_of::<MemoryMapping>() + after_strings
            - before_strings,
    );
    assert_eq!(
        initial_attempt_bytes(
            &inputs,
            &seal,
            &scratch,
            &forbidden,
            &retained_maps,
            increment
        )
        .unwrap()
            - actual,
        mapping_bytes(&retained_maps).unwrap() - mapping_bytes(&maps).unwrap(),
    );
}

#[test]
fn full_head_sets_and_uncensused_original_pages_fit_the_retained_domain_envelope() {
    let profile = profile();
    let facts: Vec<_> = [BASE, SECOND]
        .into_iter()
        .map(|start| ImageFacts {
            start,
            bytes: vec![0x90; 4096],
            heads: (start..start + 4096).collect(),
        })
        .collect();
    let originals = facts.clone();
    let maps = vec![mapping(BASE), mapping(SECOND), mapping(UNCENSUSED)];
    let domain = Domain::new(
        facts,
        maps.clone(),
        &DynamicAdmissionOptions::default(),
        Instant::now() + Duration::from_secs(60),
        |start, len| {
            let original = originals.iter().find(|fact| fact.start == start).unwrap();
            assert_eq!(len, original.bytes.len());
            Ok(original.bytes.clone())
        },
    )
    .unwrap();
    assert_eq!(domain.images.len(), 2);
    assert_eq!(domain.original_executables, maps);
    assert_eq!(domain.pages.len(), 3);
    assert!(domain.pages.values().all(|executable| !executable));
    assert!(domain.pages.contains_key(&UNCENSUSED));
    for (image, original) in domain.images.iter().zip(&originals) {
        assert_eq!(image.snapshot.bytes(), original.bytes);
        assert_eq!(image.entries.heads().len(), 4096);
        assert!(
            original
                .heads
                .iter()
                .all(|head| image.entries.heads().contains_key(head))
        );
    }
    assert!(domain.plans.is_empty());
    assert!(domain.generations.is_empty());
    assert!(domain.guards.is_empty());
    assert!(domain.sites.is_empty());
    assert!(domain.resource_payload_bytes().unwrap() > 2 * profile.max_total_capture_bytes);
    assert!(domain.resource_payload_bytes().unwrap() < domain.resource_basis_bytes());
    let actual = domain_bytes(&domain).unwrap();
    let upper = domain_bound(&profile).unwrap();
    assert!(actual <= upper, "actual={actual}, upper={upper}");
    assert!(actual > domain.resource_payload_bytes().unwrap() + profile.max_total_capture_bytes);
    domain.audit_history().unwrap();
    assert!(matches!(
        domain.original_decode(UNCENSUSED),
        Err(GateError::Refused(
            "dynamic continuation has no original image census"
        ))
    ));
}

#[test]
fn whole_future_envelope_is_atomic_at_one_byte_short_and_never_refunded() {
    let charge = future(&profile()).unwrap();
    assert_eq!((charge.epochs, charge.origins, charge.witnesses), (1, 1, 1));
    assert_eq!((charge.reports, charge.plan_history), (0, 0));
    assert!(charge.source_fact_bytes > 6 * MAX_XSTATE);
    assert!(charge.source_fact_bytes < limits().source_fact_bytes);
    let tight = census::Limits {
        epochs: 2,
        source_fact_bytes: charge.source_fact_bytes,
        reports: 1,
        origins: 1,
        witnesses: 1,
        plan_history: 1,
    };
    let mut short = census_with(census::Limits {
        source_fact_bytes: tight.source_fact_bytes - 1,
        ..tight
    });
    let before_short = view(&short);
    assert_eq!(short.reserve(charge), Err(CensusError::Capacity));
    assert_eq!(view(&short), before_short);
    // A refusal did not install an outstanding reservation or debit anything.
    let smaller = BudgetCharge {
        source_fact_bytes: charge.source_fact_bytes - 1,
        ..charge
    };
    let short_token = short.reserve(smaller).unwrap();
    short.finish_reservation(short_token).unwrap();

    let mut exact = census_with(tight);
    let before = view(&exact);
    let token = exact.reserve(charge).unwrap();
    assert_eq!(exact.check_reserved(token, charge), Ok(()));
    assert_eq!(exact.charged(), combine(before.charged, charge).unwrap());
    assert_eq!(exact.used(), before.used);
    assert_eq!(exact.generation(), before.generation);
    assert_eq!(exact.rows().count(), 0);
    assert!(exact.history().is_empty());
    exact.account_external(token, bytes(37)).unwrap();
    let retained = view(&exact);
    assert_eq!(retained.used, combine(before.used, bytes(37)).unwrap());
    exact.finish_reservation(token).unwrap();
    assert_eq!(view(&exact), retained);
    assert_eq!(
        exact.check_reserved(token, bytes(0)),
        Err(CensusError::StaleReservation)
    );
    assert_eq!(exact.reserve(bytes(1)), Err(CensusError::Capacity));
    assert_eq!(view(&exact), retained);
}

#[test]
fn every_budget_axis_overflows_closed_and_valid_maxima_do_not_raise_the_lifetime_cap() {
    let mut left = BudgetCharge {
        epochs: 2,
        source_fact_bytes: 3,
        reports: 5,
        origins: 7,
        witnesses: 11,
        plan_history: 13,
    };
    let right = BudgetCharge {
        epochs: 17,
        source_fact_bytes: 19,
        reports: 23,
        origins: 29,
        witnesses: 31,
        plan_history: 37,
    };
    assert_eq!(
        combine(left, right).unwrap(),
        BudgetCharge {
            epochs: 19,
            source_fact_bytes: 22,
            reports: 28,
            origins: 36,
            witnesses: 42,
            plan_history: 50,
        }
    );
    for axis in 0..6 {
        match axis {
            0 => left.epochs = usize::MAX,
            1 => left.source_fact_bytes = usize::MAX,
            2 => left.reports = usize::MAX,
            3 => left.origins = usize::MAX,
            4 => left.witnesses = usize::MAX,
            5 => left.plan_history = usize::MAX,
            _ => unreachable!(),
        }
        let retained_left = left;
        let retained_right = right;
        refused(combine(left, right), "exec evidence size overflows");
        assert_eq!(left, retained_left);
        assert_eq!(right, retained_right);
        left = BudgetCharge {
            epochs: 2,
            source_fact_bytes: 3,
            reports: 5,
            origins: 7,
            witnesses: 11,
            plan_history: 13,
        };
    }
    let mut overflow = profile();
    overflow.max_total_capture_bytes = usize::MAX;
    refused(domain_bound(&overflow), "exec evidence size overflows");
    refused(future(&overflow), "exec evidence size overflows");
    refused(
        initial_bound(&profile(), usize::MAX, &Vec::new(), 0),
        "exec evidence size overflows",
    );
    let mut invalid = profile();
    invalid.max_argument_pointers = 1;
    refused(
        initial_bound(&invalid, 0, &Vec::new(), 0),
        "exec input limits are invalid",
    );
    invalid = profile();
    invalid.max_capture_bytes = 4095;
    refused(future(&invalid), "exec source capture profile differs");

    // A syntactically valid maximum profile is not a promise that its dense
    // retained evidence fits the independently unchanged lifetime account.
    let maximum = DynamicExecProfile {
        max_capture_images: 64,
        max_capture_bytes: 64 * 1024,
        max_total_capture_bytes: 64 * 64 * 1024,
        max_argument_pointers: 4096,
        max_string_bytes: 64 * 1024,
    };
    maximum
        .validate(&DynamicAdmissionOptions::default())
        .unwrap();
    let large = future(&maximum).unwrap();
    let mut census = census_with(limits());
    assert!(large.source_fact_bytes > 64 * 1024 * 1024);
    let before = view(&census);
    assert_eq!(census.reserve(large), Err(CensusError::Capacity));
    assert_eq!(view(&census), before);
    assert_eq!(limits().source_fact_bytes, 64 * 1024 * 1024);
}
