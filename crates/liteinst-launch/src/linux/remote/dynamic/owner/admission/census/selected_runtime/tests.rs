//! Pure synthetic census controls. No synthetic token proves native execution.
use super::*;
use crate::lifecycle::LifecycleRegistry;
use crate::selected::{SelectedResult, SyscallAliases, decode};
fn registers(pc: u64) -> RegisterSnapshot {
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
        rax: 0xfeed_beef_0000_0005,
        rcx: 4,
        rdx: 3,
        rsi: 2,
        rdi: 1,
        orig_rax: u64::MAX,
        rip: pc,
        cs: 0x33,
        eflags: 0xad7,
        rsp: 0x700000,
        ss: 0x2b,
        fs_base: 0x900000,
        gs_base: 0,
        ds: 0,
        es: 0,
        fs: 0,
        gs: 0,
    }
}

fn before() -> ObservedStop {
    let registry = LifecycleRegistry::new(
        crate::lifecycle::Limits {
            tasks: 1,
            processes: 1,
            address_spaces: 1,
            obligations: 8,
        },
        100,
        0x401000,
    )
    .unwrap();
    let task = registry.root_task();
    let record = registry.task(task).unwrap();
    ObservedStop {
        token: DynamicStop {
            session: 17,
            sequence: 7,
            tid: 100,
            task: Some(task),
        },
        task: DynamicTask {
            task,
            process: record.process,
            address_space: record.address_space,
            generation: 0,
        },
        logical_pc: 0x401000,
        registers: registers(0x401000),
        xstate: vec![0x5a; 832],
        signal_mask: 0x200,
        phase: StopPhase::UserCheckpoint,
        signal: None,
    }
}
fn setup() -> (
    ResumeCensus,
    OriginId,
    ObservedStop,
    SelectedInput,
    CompletedInstruction,
    ExecutionId,
) {
    let before = before();
    let mut census = ResumeCensus::new(
        17,
        before.task.address_space,
        0,
        Limits {
            epochs: 8,
            source_fact_bytes: 8 * 1024 * 1024,
            reports: 8,
            origins: 8,
            witnesses: 8,
            plan_history: 8,
        },
    )
    .unwrap();
    let reservation = census
        .reserve(BudgetCharge {
            origins: 1,
            source_fact_bytes: 16384,
            ..BudgetCharge::default()
        })
        .unwrap();
    let id = census
        .insert(
            reservation,
            OriginKind::CurrentHeldPc,
            before.logical_pc,
            before.clone(),
        )
        .unwrap();
    census.finish_reservation(reservation).unwrap();
    let input = SelectedInput::new(
        decode(before.logical_pc, &[0x0f, 0xa2], &SyscallAliases::new()).unwrap(),
        before.registers,
    )
    .unwrap();
    let completed = input
        .complete(SelectedResult::Cpuid {
            eax: 1,
            ebx: 2,
            ecx: 3,
            edx: 4,
        })
        .unwrap();
    let invocation = ExecutionId::from_owner(17, 3).unwrap();
    (census, id, before, input, completed, invocation)
}
fn actual(
    before: &ObservedStop,
    completed: &CompletedInstruction,
    invocation: ExecutionId,
) -> ObservedStop {
    let mut after = before.clone();
    after.token.sequence += 1;
    after.logical_pc = completed.after.rip;
    after.registers = completed.after;
    after.phase = StopPhase::SelectedComplete { invocation };
    after
}
#[test]
fn prepared_selected_commits_exact_full_history_without_post_effect_allocation() {
    let (mut census, id, before, input, completed, invocation) = setup();
    let charge = PreparedRuntimeSelected::reservation_charge().unwrap();
    let reservation = census.reserve(charge).unwrap();
    let charged = census.charged();
    let mut prepared = census
        .prepare_runtime_selected(reservation, id, invocation, &input, &completed)
        .unwrap();
    let used = census.used();
    assert!(used.source_fact_bytes > 4 * MAX_XSTATE_BYTES);
    let capacities = (
        census.state.origins.capacity(),
        census.state.history.capacity(),
    );
    let pointers = (
        prepared
            .evidence
            .as_ref()
            .unwrap()
            .successor
            .xstate
            .as_ptr(),
        prepared
            .successor
            .as_ref()
            .unwrap()
            .row
            .initial
            .xstate
            .as_ptr(),
        prepared.successor.as_ref().unwrap().current.xstate.as_ptr(),
    );
    let after = actual(&before, &completed, invocation);
    let new_id = census
        .commit_runtime_selected(&mut prepared, &after)
        .unwrap();
    assert_eq!(census.charged(), charged);
    assert_eq!(census.used(), used.add(fixed_charge()).unwrap());
    assert_eq!(
        (
            census.state.origins.capacity(),
            census.state.history.capacity()
        ),
        capacities
    );
    assert_eq!(census.state.origins.len(), 2);
    assert!(!census.state.origins[0].active);
    let current = &census.state.origins[1];
    assert_eq!(current.row.id, new_id);
    let mut checkpoint = after.clone();
    checkpoint.phase = StopPhase::UserCheckpoint;
    assert_eq!(current.row.initial, checkpoint);
    assert_eq!(current.current, checkpoint);
    assert_eq!(current.row.initial.xstate.as_ptr(), pointers.1);
    assert_eq!(current.current.xstate.as_ptr(), pointers.2);
    let HistoryRecord::Consumed { origin, evidence } = census.history().last().unwrap() else {
        panic!("missing consumption")
    };
    assert_eq!(*origin, id);
    assert_eq!(evidence.before, before);
    assert_eq!(evidence.successor, after);
    assert_eq!(evidence.successor.xstate.as_ptr(), pointers.0);
    let Consumption::Selected {
        input: stored,
        completed: result,
        invocation: actual_id,
    } = &evidence.evidence
    else {
        panic!("wrong witness")
    };
    assert_eq!(**stored, input);
    assert_eq!(**result, completed);
    assert_eq!(*actual_id, invocation);
    census.finish_reservation(reservation).unwrap();
    assert_eq!(census.charged(), charged);
}
#[test]
fn selected_successor_corruptions_leave_complete_model_unchanged() {
    for field in 0..15 {
        let (mut census, id, before, input, completed, invocation) = setup();
        let reservation = census
            .reserve(PreparedRuntimeSelected::reservation_charge().unwrap())
            .unwrap();
        let mut prepared = census
            .prepare_runtime_selected(reservation, id, invocation, &input, &completed)
            .unwrap();
        let mut after = actual(&before, &completed, invocation);
        match field {
            0 => after.token.sequence = before.token.sequence,
            1 => after.token.session += 1,
            2 => after.token.tid += 1,
            3 => after.token.task = None,
            4 => after.task.generation += 1,
            5 => after.registers.rax ^= 1,
            6 => after.xstate[17] ^= 1,
            7 => after.signal_mask ^= 1,
            8 => after.logical_pc += 1,
            9 => after.phase = StopPhase::UserCheckpoint,
            10 => after.registers.rsp ^= 8,
            11 => after.signal = Some(DynamicSignalInfo { raw: [0; 128] }),
            12 => {
                let donor = self::before();
                after.task.task = donor.task.task;
                after.token.task = Some(donor.task.task);
            }
            13 => after.task.process = self::before().task.process,
            14 => after.task.address_space = self::before().task.address_space,
            _ => unreachable!(),
        }
        let prior = census.state.clone();
        let pointer = prepared
            .evidence
            .as_ref()
            .unwrap()
            .successor
            .xstate
            .as_ptr();
        assert!(
            census
                .commit_runtime_selected(&mut prepared, &after)
                .is_err()
        );
        assert_eq!(census.state, prior);
        assert!(prepared.committed.is_none());
        assert_eq!(
            prepared
                .evidence
                .as_ref()
                .unwrap()
                .successor
                .xstate
                .as_ptr(),
            pointer
        );
    }
    for field in 0..8 {
        let (mut census, id, before, input, completed, invocation) = setup();
        let reservation = census
            .reserve(PreparedRuntimeSelected::reservation_charge().unwrap())
            .unwrap();
        let mut prepared = census
            .prepare_runtime_selected(reservation, id, invocation, &input, &completed)
            .unwrap();
        let row = prepared.successor.as_mut().unwrap();
        match field {
            0 => row.row.initial.xstate[19] ^= 1,
            1 => row.row.initial.token.sequence += 1,
            2 => row.current.registers.rsp ^= 8,
            3 => row.current.signal_mask ^= 1,
            4 => row.row.pc += 1,
            5 => row.row.created_generation += 1,
            6 => row.active = false,
            7 => row.row.initial.phase = StopPhase::Interrupted,
            _ => unreachable!(),
        }
        let prior = census.state.clone();
        assert!(matches!(
            census.commit_runtime_selected(&mut prepared, &actual(&before, &completed, invocation)),
            Err(CensusError::InvalidConsumption)
        ));
        assert_eq!(census.state, prior);
        assert!(prepared.evidence.is_some());
        assert!(prepared.successor.is_some());
    }
}
#[test]
fn selected_before_and_model_corruption_refuse_before_prepaid_storage() {
    for field in 0..4 {
        let (mut census, id, _, input, mut completed, invocation) = setup();
        match field {
            0 => completed.before.rax ^= 1,
            1 => completed.after.rip += 1,
            2 => completed.after.cs = 0x23,
            3 => {
                completed.instruction =
                    decode(0x401000, &[0x0f, 0x31], &SyscallAliases::new()).unwrap()
            }
            _ => unreachable!(),
        }
        let reservation = census
            .reserve(PreparedRuntimeSelected::reservation_charge().unwrap())
            .unwrap();
        let prior = census.state.clone();
        assert!(matches!(
            census.prepare_runtime_selected(reservation, id, invocation, &input, &completed),
            Err(CensusError::InvalidConsumption)
        ));
        assert_eq!(census.state, prior);
    }
}
#[test]
fn selected_one_byte_short_and_origin_or_witness_short_reservations_are_exact() {
    for axis in 0..3 {
        let (mut census, id, _, input, completed, invocation) = setup();
        let mut charge = PreparedRuntimeSelected::reservation_charge().unwrap();
        match axis {
            0 => charge.source_fact_bytes -= 1,
            1 => charge.origins = 0,
            2 => charge.witnesses = 0,
            _ => unreachable!(),
        }
        let reservation = census.reserve(charge).unwrap();
        let prior = census.state.clone();
        assert!(matches!(
            census.prepare_runtime_selected(reservation, id, invocation, &input, &completed),
            Err(CensusError::ReservationExhausted)
        ));
        assert_eq!(census.state, prior);
    }
    let (mut census, id, before, input, completed, invocation) = setup();
    let reservation = census
        .reserve(PreparedRuntimeSelected::reservation_charge().unwrap())
        .unwrap();
    let mut prepared = census
        .prepare_runtime_selected(reservation, id, invocation, &input, &completed)
        .unwrap();
    let remaining = prepared.remaining_charge().unwrap();
    let extra =
        census.remaining(reservation).unwrap().source_fact_bytes - remaining.source_fact_bytes + 1;
    census
        .account_external(
            reservation,
            BudgetCharge {
                source_fact_bytes: extra,
                ..BudgetCharge::default()
            },
        )
        .unwrap();
    let prior = census.state.clone();
    assert_eq!(
        census.check_reserved(reservation, remaining),
        Err(CensusError::ReservationExhausted)
    );
    assert!(matches!(
        census.commit_runtime_selected(&mut prepared, &actual(&before, &completed, invocation)),
        Err(CensusError::ReservationExhausted)
    ));
    assert_eq!(census.state, prior);
    assert!(prepared.evidence.is_some());
    assert!(prepared.successor.is_some());
}
#[test]
fn selected_preparation_is_not_replay_or_foreign_census_authority() {
    let (mut census, id, before, input, completed, invocation) = setup();
    let reservation = census
        .reserve(PreparedRuntimeSelected::reservation_charge().unwrap())
        .unwrap();
    let mut prepared = census
        .prepare_runtime_selected(reservation, id, invocation, &input, &completed)
        .unwrap();
    let (mut foreign, _, _, _, _, _) = setup();
    let foreign_before = foreign.state.clone();
    assert!(matches!(
        foreign.commit_runtime_selected(&mut prepared, &actual(&before, &completed, invocation)),
        Err(CensusError::IdentityMismatch)
    ));
    assert_eq!(foreign.state, foreign_before);
    census
        .commit_runtime_selected(&mut prepared, &actual(&before, &completed, invocation))
        .unwrap();
    let prior = census.state.clone();
    assert!(matches!(
        census.commit_runtime_selected(&mut prepared, &actual(&before, &completed, invocation)),
        Err(CensusError::IdentityMismatch)
    ));
    assert_eq!(census.state, prior);
}
#[test]
fn selected_serial_overflow_refuses_without_retiring_any_original() {
    let (mut census, id, before, input, completed, invocation) = setup();
    let reservation = census
        .reserve(PreparedRuntimeSelected::reservation_charge().unwrap())
        .unwrap();
    let mut prepared = census
        .prepare_runtime_selected(reservation, id, invocation, &input, &completed)
        .unwrap();
    census.state.next_serial = u64::MAX;
    let prior = census.state.clone();
    assert!(matches!(
        census.commit_runtime_selected(&mut prepared, &actual(&before, &completed, invocation)),
        Err(CensusError::Capacity)
    ));
    assert_eq!(census.state, prior);
    assert!(prepared.evidence.is_some());
    assert!(prepared.successor.is_some());
}
