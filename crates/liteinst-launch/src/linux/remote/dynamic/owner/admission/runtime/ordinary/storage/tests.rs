//! Supplied-data allocation and accounting controls only; no native request.
use super::*;
use crate::lifecycle::LifecycleRegistry;
use std::panic::{AssertUnwindSafe, catch_unwind};

const WINDOW: usize = 8192;
const SESSION: u64 = 57;

struct Model {
    census: ResumeCensus,
    origin: OriginId,
    observed: ObservedStop,
    stop: AdmissionStop,
    attempts: Vec<Box<RuntimeOrdinaryAttempt>>,
    pending: Option<PendingOrdinaryPreparation>,
    before_used: BudgetCharge,
    charged: BudgetCharge,
}
fn registers() -> RegisterSnapshot {
    RegisterSnapshot {
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
        rax: 5,
        rcx: 4,
        rdx: 3,
        rsi: 2,
        rdi: 1,
        orig_rax: u64::MAX,
        rip: 0x401000,
        cs: 0x33,
        eflags: 0x202,
        rsp: 0x600000,
        ss: 0x2b,
        fs_base: 0,
        gs_base: 0,
        ds: 0,
        es: 0,
        fs: 0,
        gs: 0,
    }
}
fn model(spare_capacity: usize) -> Model {
    let registry = LifecycleRegistry::new(
        crate::lifecycle::Limits {
            tasks: 4,
            processes: 2,
            address_spaces: 2,
            obligations: 16,
        },
        100,
        0x401000,
    )
    .unwrap();
    let task = registry.root_task();
    let row = registry.task(task).unwrap();
    let observed = ObservedStop {
        token: DynamicStop {
            session: SESSION,
            sequence: 1,
            tid: row.tid,
            task: Some(task),
        },
        task: DynamicTask {
            task,
            process: row.process,
            address_space: row.address_space,
            generation: 0,
        },
        logical_pc: 0x401000,
        registers: registers(),
        xstate: vec![0x5a; 832],
        signal_mask: 0x200,
        phase: StopPhase::UserCheckpoint,
        signal: None,
    };
    let stop = AdmissionStop {
        token: observed.token.clone(),
        identity: observed.task,
        phase: super::super::super::super::super::trusted::AdmissionPhase::Restored,
        signal: None,
    };
    let mut census = ResumeCensus::new(
        SESSION,
        observed.task.address_space,
        0,
        census::Limits {
            epochs: 32,
            source_fact_bytes: 64 * 1024 * 1024,
            reports: 64,
            origins: 64,
            witnesses: 128,
            plan_history: 64,
        },
    )
    .unwrap();
    let token = census
        .reserve(BudgetCharge {
            origins: 1,
            source_fact_bytes: 1024 * 1024,
            ..BudgetCharge::default()
        })
        .unwrap();
    let origin = census
        .insert(
            token,
            census::OriginKind::CurrentHeldPc,
            observed.logical_pc,
            observed.clone(),
        )
        .unwrap();
    let attempts = exact_storage::empty_vec(spare_capacity).unwrap();
    census
        .account_external(
            token,
            BudgetCharge {
                source_fact_bytes: spare_capacity * size_of::<Box<RuntimeOrdinaryAttempt>>(),
                ..BudgetCharge::default()
            },
        )
        .unwrap();
    census.finish_reservation(token).unwrap();
    let mut model = Model {
        before_used: census.used(),
        charged: census.charged(),
        census,
        origin,
        observed,
        stop,
        attempts,
        pending: None,
    };
    begin(&mut model, AllocationFault::default());
    model
}
fn begin(model: &mut Model, fault: AllocationFault) {
    let shape = NativeInstructionStorage::allocation_test_shape();
    let growth = model.attempts.len() == model.attempts.capacity();
    let capacity = model.attempts.capacity() + usize::from(growth);
    let bytes = root_bytes(WINDOW, shape).unwrap()
        + if growth {
            capacity * size_of::<Box<RuntimeOrdinaryAttempt>>()
        } else {
            0
        };
    model.before_used = model.census.used();
    let reservation = model
        .census
        .reserve(BudgetCharge {
            source_fact_bytes: bytes,
            ..BudgetCharge::default()
        })
        .unwrap();
    model.charged = model.census.charged();
    let until = Instant::now() + Duration::from_secs(3);
    let mut pending = PendingOrdinaryPreparation::new(PreparationRequest {
        reservation,
        origin: model.origin,
        serial: 1,
        stop: model.stop.clone(),
        until,
        shape,
        window_bytes: WINDOW,
        temporary: root_temporary_bytes().unwrap(),
        expected_capacity: capacity,
    });
    pending.record.fault = fault;
    model.pending = Some(pending);
}
fn run(model: &mut Model) -> Result<(), GateError> {
    prepare(&mut model.attempts, &mut model.pending, &mut model.census)
}
fn expected_prefix(end: usize) -> usize {
    // Independent stage-size table, not the implementation's measured helper.
    (0..end)
        .map(|i| match i {
            0 => size_of::<Box<RuntimeOrdinaryAttempt>>(),
            1 => size_of::<RuntimeOrdinaryAttempt>(),
            2 | 7 | 8..=16 => MAX_XSTATE,
            3..=5 => WINDOW,
            6 | 17..=22 => MAP_BYTES,
            _ => panic!("unexpected supplied stage"),
        })
        .sum()
}

type ByteOwner = (usize, usize, Vec<u8>);
#[derive(Debug, Eq, PartialEq)]
struct Snapshot {
    record: AllocationRecord,
    pending: bool,
    slot_pointer: usize,
    slot_capacity: usize,
    slot_boxes: Vec<usize>,
    replacement: Option<(usize, usize, usize)>,
    root: Option<RootSnapshot>,
    bytes: Vec<ByteOwner>,
    native: Option<(
        usize,
        Option<runtime_native::InstructionFailure>,
        bool,
        bool,
    )>,
}
#[derive(Debug, Eq, PartialEq)]
struct RootSnapshot {
    pointer: usize,
    reservation: Reservation,
    stop: AdmissionStop,
    before: ObservedStop,
    checkpoint: ObservedStop,
    checkpoint_stop: AdmissionStop,
    progress: [SourceReadProgress; 3],
    stage: AttemptStage,
    failed: bool,
    unwound: bool,
    prior_slots: (usize, usize, usize),
}
fn snapshot(model: &Model) -> Snapshot {
    let view = partial_view(&model.attempts, &model.pending).unwrap();
    let mut bytes = Vec::new();
    if let Some(attempt) = view.attempt {
        for value in [
            &attempt.before.xstate,
            &attempt.source.checkpoint.xstate,
            &attempt.source.identity,
        ] {
            bytes.push((value.as_ptr() as usize, value.capacity(), value.clone()));
        }
        for value in &attempt.source.bytes {
            bytes.push((value.as_ptr() as usize, value.capacity(), value.clone()));
        }
        assert!(attempt.prior_slots.is_empty());
        assert_eq!(
            attempt.census.history_snapshot().unwrap(),
            SharedOrdinaryPreparation::empty()
                .history_snapshot()
                .unwrap()
        );
        for progress in &attempt.source.progress {
            assert_eq!(*progress, SourceReadProgress::default());
        }
        let progress = attempt.native.progress();
        assert_eq!(progress.waits, [None; 7]);
        assert_eq!(progress.queries_started, [false; 7]);
        assert!(progress.effects().is_empty());
        assert!(!progress.nx_closed && !progress.instruction_completed);
        assert!(attempt.native.completed().is_none());
    }
    if let Some(native) = &view.native {
        for value in native.states.iter().flatten() {
            bytes.push((
                value.state.xstate.as_ptr() as usize,
                value.state.xstate.capacity(),
                value.state.xstate.clone(),
            ));
            assert_eq!(
                (
                    value.registers_request,
                    value.xstate_request,
                    value.mask_request
                ),
                (None, None, None)
            );
            assert_eq!(
                (
                    value.requested_pointer,
                    value.returned_pointer,
                    value.returned_length,
                    value.complete
                ),
                (0, 0, 0, false)
            );
        }
        for value in native.maps.iter().flatten() {
            bytes.push((
                value.initialized_storage().as_ptr() as usize,
                MAP_BYTES,
                value.initialized_storage().to_vec(),
            ));
            assert_eq!(
                (
                    value.length,
                    value.request,
                    value.filesystem,
                    value.complete
                ),
                (0, None, None, false)
            );
        }
        if let Some(value) = native.membership {
            bytes.push((value.as_ptr() as usize, MAP_BYTES, value.to_vec()));
        }
    }
    Snapshot {
        record: *view.record,
        pending: view.pending,
        slot_pointer: view.slots.as_ptr() as usize,
        slot_capacity: view.slots.capacity(),
        slot_boxes: view
            .slots
            .iter()
            .map(|v| &**v as *const RuntimeOrdinaryAttempt as usize)
            .collect(),
        replacement: view
            .replacement
            .map(|v| (v.as_ptr() as usize, v.len(), v.capacity())),
        root: view.attempt.map(|v| RootSnapshot {
            pointer: v as *const RuntimeOrdinaryAttempt as usize,
            reservation: v.reservation,
            stop: v.stop.clone(),
            before: v.before.clone(),
            checkpoint: v.source.checkpoint.clone(),
            checkpoint_stop: v.source.checkpoint_stop.clone(),
            progress: v.source.progress,
            stage: v.stage,
            failed: v.failed,
            unwound: v.unwound,
            prior_slots: (
                v.prior_slots.as_ptr() as usize,
                v.prior_slots.len(),
                v.prior_slots.capacity(),
            ),
        }),
        native: view
            .native
            .map(|v| (v.next, v.first_failure, v.pending, v.allocated)),
        bytes,
    }
}
fn failed(model: &mut Model, expected: usize, unwound: bool) {
    let record = record(&model.attempts, &model.pending).unwrap();
    assert_eq!(record.finish, Some(Ok(())));
    assert!(record.first_failure.is_some());
    assert_eq!(record.measurement_failure, None);
    assert_eq!(record.settlement_failure, None);
    assert!(!record.allocated);
    assert_eq!(record.copied, [0; 2]);
    assert_eq!(
        record.settled.iter().sum::<usize>(),
        root_temporary_bytes().unwrap() + expected
    );
    assert_eq!(
        model.census.used().source_fact_bytes - model.before_used.source_fact_bytes,
        root_temporary_bytes().unwrap() + expected
    );
    assert_eq!(model.census.charged(), model.charged);
    assert_eq!(model.census.used().epochs, model.before_used.epochs);
    assert_eq!(model.census.used().origins, model.before_used.origins);
    assert_eq!(model.census.used().witnesses, model.before_used.witnesses);
    assert_eq!(model.census.used().reports, model.before_used.reports);
    assert_eq!(
        model.census.used().plan_history,
        model.before_used.plan_history
    );
    assert_eq!(
        model.census.current_observation(model.origin).unwrap(),
        &model.observed
    );
    assert_eq!(
        model
            .census
            .check_reserved(record.reservation, BudgetCharge::default()),
        Err(CensusError::StaleReservation)
    );
    if let Some(value) = model.attempts.last() {
        assert!(value.failed);
        assert_eq!(value.unwound, unwound);
    }
    let saved = snapshot(model);
    // This is repeated bookkeeping finalization, NOT physical cleanup credit.
    finish_failure(&mut model.attempts, &mut model.pending, &mut model.census);
    assert_eq!(snapshot(model), saved);
}

#[test]
fn ordinary_root_every_allocation_error_keeps_exact_installed_prefix() {
    for ordinal in 0..STAGES {
        let mut model = model(0);
        model.pending.as_mut().unwrap().record.fault.before = Some(ordinal);
        assert!(matches!(
            run(&mut model),
            Err(GateError::Refused("injected ordinary allocation failure"))
        ));
        failed(&mut model, expected_prefix(ordinal), false);
    }
}
#[test]
fn ordinary_root_every_post_install_unwind_keeps_exact_payload_and_debit() {
    for ordinal in 0..STAGES {
        let mut model = model(0);
        model.pending.as_mut().unwrap().record.fault.after = Some(ordinal);
        let panic = catch_unwind(AssertUnwindSafe(|| run(&mut model))).unwrap_err();
        assert_eq!(panic.downcast_ref::<u32>(), Some(&PANIC));
        failed(&mut model, expected_prefix(ordinal + 1), true);
    }
}
#[test]
fn ordinary_root_no_growth_and_two_generations_preserve_all_box_owners() {
    let mut no_growth = model(2);
    run(&mut no_growth).unwrap();
    assert_eq!(no_growth.attempts.capacity(), 2);
    assert_eq!(no_growth.attempts[0].allocation.new_slots, 0);
    assert_eq!(no_growth.attempts[0].prior_slots.capacity(), 0);
    let used = no_growth.census.used();
    let saved = snapshot(&no_growth);
    settle(
        &mut no_growth.attempts,
        &mut no_growth.pending,
        &mut no_growth.census,
    )
    .unwrap();
    assert_eq!(no_growth.census.used(), used);
    assert_eq!(snapshot(&no_growth), saved);
    finish_success(&mut no_growth.attempts[0], &mut no_growth.census).unwrap();
    let mut growth = model(0);
    run(&mut growth).unwrap();
    let old_box = &*growth.attempts[0] as *const RuntimeOrdinaryAttempt as usize;
    let old_payload = growth.attempts[0].before.xstate.as_ptr() as usize;
    let old_slots = growth.attempts.as_ptr() as usize;
    let old_capacity = growth.attempts.capacity();
    finish_success(&mut growth.attempts[0], &mut growth.census).unwrap();
    begin(&mut growth, AllocationFault::default());
    run(&mut growth).unwrap();
    assert_eq!(growth.attempts.len(), 2);
    assert_eq!(
        &*growth.attempts[0] as *const RuntimeOrdinaryAttempt as usize,
        old_box
    );
    assert_eq!(
        growth.attempts[0].before.xstate.as_ptr() as usize,
        old_payload
    );
    assert_eq!(growth.attempts[1].prior_slots.as_ptr() as usize, old_slots);
    assert_eq!(growth.attempts[1].prior_slots.capacity(), old_capacity);
    assert_eq!(growth.attempts[1].prior_slots.len(), 0);
    assert_eq!(
        growth.attempts[1].allocation.settled[1],
        2 * size_of::<Box<RuntimeOrdinaryAttempt>>()
    );
    assert_eq!(growth.census.charged(), growth.charged);
}
#[test]
fn ordinary_root_transfer_copy_and_native_conversion_boundaries_retain_progress() {
    for point in 0..6 {
        for unwind in [false, true] {
            let mut model = model(0);
            model.pending.as_mut().unwrap().record.fault.point = Some((point, unwind));
            let result = catch_unwind(AssertUnwindSafe(|| run(&mut model)));
            if unwind {
                assert_eq!(result.unwrap_err().downcast_ref::<u32>(), Some(&PANIC));
            } else {
                assert!(matches!(
                    result.unwrap(),
                    Err(GateError::Refused(
                        "injected ordinary preparation boundary failure"
                    ))
                ));
            }
            let view = partial_view(&model.attempts, &model.pending).unwrap();
            assert_eq!(view.pending, point == 0);
            let expected_copies = match point {
                0 | 1 => [0, 0],
                2 => [832, 0],
                _ => [832, 832],
            };
            assert_eq!(view.record.copied, expected_copies);
            assert_eq!(view.record.finish, Some(Ok(())));
            assert!(!view.record.allocated);
            if let Some(native) = view.native {
                assert_eq!(native.allocated, point == 5);
            }
            assert_eq!(model.census.charged(), model.charged);
            let saved = snapshot(&model);
            finish_failure(&mut model.attempts, &mut model.pending, &mut model.census);
            assert_eq!(snapshot(&model), saved);
        }
    }
}
#[test]
fn ordinary_root_secondary_settlement_and_finish_keep_original_error_and_unwind() {
    for unwind in [false, true] {
        let mut model = model(0);
        let token = model.pending.as_ref().unwrap().record.reservation;
        // Supplied wrong-lifetime setup, not a mutated actual native census.
        model.census.finish_reservation(token).unwrap();
        if unwind {
            model.pending.as_mut().unwrap().record.fault.after = Some(3);
        } else {
            model.pending.as_mut().unwrap().record.fault.before = Some(4);
        }
        let outcome = catch_unwind(AssertUnwindSafe(|| run(&mut model)));
        if unwind {
            assert_eq!(outcome.unwrap_err().downcast_ref::<u32>(), Some(&PANIC));
        } else {
            assert!(matches!(
                outcome.unwrap(),
                Err(GateError::Refused("injected ordinary allocation failure"))
            ));
        }
        let view = partial_view(&model.attempts, &model.pending).unwrap();
        assert_eq!(
            view.record.settlement_failure,
            Some(CensusError::StaleReservation)
        );
        assert_eq!(view.record.finish, Some(Err(CensusError::StaleReservation)));
        assert_eq!(view.record.settled, [0; 4]);
        assert_eq!(model.census.used(), model.before_used);
        assert_eq!(model.census.charged(), model.charged);
        assert_eq!(view.attempt.unwrap().before.xstate.capacity(), MAX_XSTATE);
    }
    // A rejected first component must not suppress truthful sibling debits.
    // This corrupts only a supplied preparation's temporary-size description.
    let mut model = model(0);
    let reserved = model.charged.source_fact_bytes - model.before_used.source_fact_bytes;
    let pending = model.pending.as_mut().unwrap();
    pending.record.temporary = reserved + 1;
    pending.record.fault.before = Some(4);
    assert!(matches!(
        run(&mut model),
        Err(GateError::Refused("injected ordinary allocation failure"))
    ));
    let view = partial_view(&model.attempts, &model.pending).unwrap();
    assert_eq!(
        view.record.first_failure,
        Some(Failure::Refused("injected ordinary allocation failure"))
    );
    assert_eq!(
        view.record.settlement_failure,
        Some(CensusError::ReservationExhausted)
    );
    assert_eq!(view.record.settled[0], 0);
    assert_eq!(
        view.record.settled[1..].iter().sum::<usize>(),
        expected_prefix(4)
    );
    assert_eq!(
        model.census.used().source_fact_bytes - model.before_used.source_fact_bytes,
        expected_prefix(4)
    );
    assert_eq!(model.census.charged(), model.charged);
    assert_eq!(view.record.finish, Some(Ok(())));
}
#[test]
fn ordinary_root_reuse_and_slot_shape_refusal_do_not_discard_owner() {
    let mut wrong_shape = model(0);
    wrong_shape.pending.as_mut().unwrap().expected_capacity = 0;
    assert!(matches!(
        run(&mut wrong_shape),
        Err(GateError::Refused("ordinary installation shape differs"))
    ));
    let saved = snapshot(&wrong_shape);
    assert!(saved.pending && saved.root.is_some());
    assert_eq!(saved.record.finish, Some(Ok(())));
    let mut supplied = model(0);
    run(&mut supplied).unwrap();
    let old = snapshot(&supplied);
    assert!(
        prepare_inner(
            &mut supplied.attempts,
            &mut supplied.pending,
            &supplied.census
        )
        .is_err()
    );
    assert_eq!(snapshot(&supplied), old);
    assert!(supplied.attempts[0].native.take_completed().is_err());
}
