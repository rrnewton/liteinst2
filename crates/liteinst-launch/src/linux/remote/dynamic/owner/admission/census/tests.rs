//! Synthetic bookkeeping checks only: no case claims a real stop, exclusion,
//! permission change, native instruction completion or saved-context census.

use super::*;
use crate::lifecycle::{
    CreationEvent, CreationEventKind, CreationRequest, HoldReason, LifecycleRegistry,
};
use crate::selected::{SyscallAliases, decode};
use liteinst_admission::entries::{Completeness, EntryProvenance};
use liteinst_admission::returns::{CallReturnLedger, ReturnError};
use liteinst_admission::scan::{Boundary, Snapshot, WriteControl};

const PC: u64 = 0x401000;
const SESSION: u64 = 17;

fn limits() -> Limits {
    Limits {
        epochs: 32,
        source_fact_bytes: 1 << 20,
        reports: 64,
        origins: 64,
        witnesses: 128,
        plan_history: 64,
    }
}

fn charge() -> BudgetCharge {
    BudgetCharge {
        epochs: 16,
        source_fact_bytes: 1 << 19,
        reports: 32,
        origins: 32,
        witnesses: 64,
        plan_history: 32,
    }
}

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
        rax: 5,
        rcx: 4,
        rdx: 3,
        rsi: 2,
        rdi: 1,
        orig_rax: u64::MAX,
        rip: pc,
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

fn registry() -> LifecycleRegistry {
    LifecycleRegistry::new(
        crate::lifecycle::Limits {
            tasks: 4,
            processes: 2,
            address_spaces: 2,
            obligations: 16,
        },
        100,
        PC,
    )
    .unwrap()
}

fn observed(
    registry: &LifecycleRegistry,
    task: TaskId,
    pc: u64,
    sequence: u64,
    phase: StopPhase,
) -> ObservedStop {
    let record = registry.task(task).unwrap();
    ObservedStop {
        token: DynamicStop {
            session: SESSION,
            sequence,
            tid: record.tid,
            task: Some(task),
        },
        task: DynamicTask {
            task,
            process: record.process,
            address_space: record.address_space,
            generation: 0,
        },
        logical_pc: pc,
        registers: registers(pc),
        xstate: vec![0x5a; 832],
        signal_mask: 0x200,
        phase,
        signal: None,
    }
}

fn initial() -> ObservedStop {
    let registry = registry();
    observed(
        &registry,
        registry.root_task(),
        PC,
        1,
        StopPhase::UserCheckpoint,
    )
}

fn census(stop: &ObservedStop) -> ResumeCensus {
    ResumeCensus::new(SESSION, stop.task.address_space, 0, limits()).unwrap()
}

fn signal(number: i32, code: i32) -> DynamicSignalInfo {
    let mut raw = [0_u8; 128];
    raw[..4].copy_from_slice(&number.to_ne_bytes());
    raw[8..12].copy_from_slice(&code.to_ne_bytes());
    raw[16..24].copy_from_slice(&PC.to_ne_bytes());
    DynamicSignalInfo { raw }
}

fn entries(
    mapping: u64,
    generation: u64,
    version: u64,
    range: AddressRange,
    resumes: impl IntoIterator<Item = (u64, ResumeKind)>,
) -> LegalEntrySet {
    LegalEntrySet::new(
        MappingId(mapping),
        Generation(generation),
        version,
        range,
        Completeness::AllInstructionHeads,
        [(range.start(), EntryProvenance::VerifiedInstruction)],
        resumes,
    )
    .unwrap()
}

fn unchanged<T: std::fmt::Debug>(
    census: &mut ResumeCensus,
    error: CensusError,
    action: impl FnOnce(&mut ResumeCensus) -> Result<T, CensusError>,
) {
    let before = census.state.clone();
    assert_eq!(action(census).unwrap_err(), error);
    assert_eq!(census.state, before);
}

fn selected(
    before: &ObservedStop,
    invocation: ExecutionId,
) -> (SelectedInput, CompletedInstruction, ObservedStop) {
    let decoded = decode(before.logical_pc, &[0x0f, 0xa2], &SyscallAliases::default()).unwrap();
    let input = SelectedInput::new(decoded.clone(), before.logical_registers()).unwrap();
    let mut after = before.clone();
    after.token.sequence += 1;
    after.logical_pc = decoded.next_pc();
    after.registers.rip = decoded.next_pc();
    after.registers.rax = 0x16;
    after.registers.rbx = 0x756e6547;
    after.registers.rcx = 0x6c65746e;
    after.registers.rdx = 0x49656e69;
    after.phase = StopPhase::SelectedComplete { invocation };
    after.signal = None;
    let completion = CompletedInstruction {
        instruction: decoded,
        before: *input.registers(),
        after: after.registers,
    };
    (input, completion, after)
}

fn thread_pair() -> (
    ObservedStop,
    ObservedStop,
    ObservedStop,
    ObservedStop,
    SelectedInput,
) {
    let mut registry = registry();
    let parent = registry.root_task();
    registry.resume(parent, 0).unwrap();
    registry
        .observe_stop(parent, 1, PC + 2, HoldReason::SyscallEntry)
        .unwrap();
    let ticket = registry
        .prepare_creation(parent, CreationRequest::Clone { flags: 0x10f00 })
        .unwrap();
    registry.resume(parent, 1).unwrap();
    let child = registry
        .observe_creation(
            ticket,
            2,
            CreationEvent {
                kind: CreationEventKind::Clone,
                child_tid: 101,
                child_tgid: 100,
                parent_visible_tid: 101,
                parent_pc: PC + 2,
            },
        )
        .unwrap();
    registry
        .observe_newborn_return_ready(child, 1, PC + 2)
        .unwrap();
    let mut before = observed(&registry, parent, PC, 2, StopPhase::OwnedGuard);
    before.registers.rax = libc::SYS_clone as u64;
    before.registers.rdi = 0x10f00;
    before.signal = Some(signal(libc::SIGTRAP, libc::SI_KERNEL));
    let input = SelectedInput::new(
        decode(PC, &[0x0f, 0x05], &SyscallAliases::default()).unwrap(),
        before.registers,
    )
    .unwrap();
    let mut entry = observed(
        &registry,
        parent,
        PC + 2,
        3,
        StopPhase::SyscallEntry {
            syscall: libc::SYS_clone as u64,
        },
    );
    entry.registers.orig_rax = libc::SYS_clone as u64;
    entry.registers.rax = (-libc::ENOSYS as i64) as u64;
    let mut parent_exit = observed(
        &registry,
        parent,
        PC + 2,
        5,
        StopPhase::ParentSyscallExit {
            syscall: libc::SYS_clone as u64,
            result: 101,
            is_error: false,
        },
    );
    parent_exit.registers.rax = 101;
    parent_exit.registers.orig_rax = libc::SYS_clone as u64;
    let mut newborn = observed(
        &registry,
        child,
        PC + 2,
        1,
        StopPhase::NewbornReturnReady {
            parent,
            syscall: libc::SYS_clone as u64,
        },
    );
    newborn.registers.rax = 0;
    (before, entry, parent_exit, newborn, input)
}

#[test]
fn limits_reject_every_zero_and_excessive_dimension() {
    for dimension in 0..6 {
        for value in [0, usize::MAX] {
            let mut bad = limits();
            match dimension {
                0 => bad.epochs = value,
                1 => bad.source_fact_bytes = value,
                2 => bad.reports = value,
                3 => bad.origins = value,
                4 => bad.witnesses = value,
                5 => bad.plan_history = value,
                _ => unreachable!(),
            }
            assert_eq!(bad.validate(), Err(CensusError::InvalidLimits));
        }
    }
    assert_eq!(limits().validate(), Ok(limits()));
}

#[test]
fn distinct_origins_survive_equal_address_and_kind_projection() {
    let (before, _, parent_exit, newborn, _) = thread_pair();
    let mut census = census(&before);
    let reservation = census.reserve(charge()).unwrap();
    let pc = PC + 2;
    let mut held = parent_exit.clone();
    held.phase = StopPhase::UserCheckpoint;
    let current = census
        .insert(reservation, OriginKind::CurrentHeldPc, pc, held)
        .unwrap();
    let parent = census
        .insert(
            reservation,
            OriginKind::ParentSyscallReturn {
                syscall: libc::SYS_clone as u64,
            },
            pc,
            parent_exit.clone(),
        )
        .unwrap();
    let child = census
        .insert(
            reservation,
            OriginKind::NewbornStart {
                parent: before.task.task,
                syscall: libc::SYS_clone as u64,
            },
            pc,
            newborn,
        )
        .unwrap();
    let unknown = census
        .insert(
            reservation,
            OriginKind::UnknownPersistent {
                kind: ResumeKind::ParkedThread,
            },
            pc,
            parent_exit.clone(),
        )
        .unwrap();
    let ids: BTreeSet<_> = [current, parent, child, unknown].into_iter().collect();
    assert_eq!(ids.len(), 4);
    let range = AddressRange::new(PC, PC + 4096).unwrap();
    let projected = census
        .project(&[ImageScope {
            mapping: MappingId(9),
            range,
        }])
        .unwrap();
    assert_eq!(projected[0].origins.len(), 4);
    assert_eq!(
        projected[0].resumes,
        BTreeMap::from([(
            pc,
            BTreeSet::from([ResumeKind::ParkedThread, ResumeKind::SyscallReturn])
        )])
    );
    census
        .validate_projection(&[entries(
            9,
            0,
            0,
            range,
            [
                (pc, ResumeKind::ParkedThread),
                (pc, ResumeKind::SyscallReturn),
            ],
        )])
        .unwrap();
    assert_eq!(
        census.check_current_origin(unknown, &parent_exit),
        Err(CensusError::PersistentUnknown)
    );
    assert_eq!(census.active().count(), 4);
}

#[test]
fn complete_projection_refuses_missing_overlapping_stale_and_extra_facts() {
    let stop = initial();
    let mut census = census(&stop);
    let reservation = census.reserve(charge()).unwrap();
    census
        .insert(reservation, OriginKind::CurrentHeldPc, PC, stop)
        .unwrap();
    let range = AddressRange::new(PC, PC + 4096).unwrap();
    let image = ImageScope {
        mapping: MappingId(1),
        range,
    };
    assert_eq!(census.project(&[]), Err(CensusError::MissingImage));
    assert_eq!(
        census.project(&[image, image]),
        Err(CensusError::OverlappingImages)
    );
    assert_eq!(
        census.validate_projection(&[entries(1, 0, 0, range, [])]),
        Err(CensusError::ProjectionMismatch)
    );
    assert_eq!(
        census.validate_projection(&[entries(1, 1, 0, range, [(PC, ResumeKind::ParkedThread)])]),
        Err(CensusError::ProjectionMismatch)
    );
    assert_eq!(
        census.validate_projection(&[entries(
            1,
            0,
            0,
            range,
            [
                (PC, ResumeKind::ParkedThread),
                (PC + 1, ResumeKind::SignalFrame)
            ]
        )]),
        Err(CensusError::ProjectionMismatch)
    );
    assert_eq!(census.active().count(), 1);
}

#[test]
fn same_pc_fetch_interrupt_and_guard_refresh_never_consume() {
    let stop = initial();
    let mut census = census(&stop);
    let reservation = census.reserve(charge()).unwrap();
    let id = census
        .insert(reservation, OriginKind::CurrentHeldPc, PC, stop.clone())
        .unwrap();
    let execution = ExecutionId::from_owner(SESSION, 1).unwrap();
    let mut current = stop.clone();
    for phase in [
        StopPhase::OwnedFetch,
        StopPhase::Interrupted,
        StopPhase::OwnedGuard,
    ] {
        let mut after = current.clone();
        after.token.sequence += 1;
        after.phase = phase;
        after.registers.eflags |= 1 << 16;
        after.signal = Some(signal(
            if phase == StopPhase::OwnedFetch {
                libc::SIGSEGV
            } else {
                libc::SIGTRAP
            },
            2,
        ));
        assert_eq!(
            OwnerConsumption::original_progress(
                execution,
                current.clone(),
                vec![0x90],
                after.clone()
            ),
            Err(CensusError::InvalidConsumption)
        );
        census
            .refresh_same_pc(reservation, id, after.clone())
            .unwrap();
        assert_eq!(census.active().count(), 1);
        assert_eq!(
            census.check_current_origin(id, &after).unwrap().initial,
            stop
        );
        current = after;
    }
    assert_eq!(census.history().len(), 3);
    assert!(
        census
            .history()
            .iter()
            .all(|row| matches!(row, HistoryRecord::Refreshed { .. }))
    );
    assert_eq!(census.active().next().unwrap().current, &current);
}

#[test]
fn selected_completion_retains_exact_input_output_and_rejects_replay() {
    let mut stop = initial();
    stop.phase = StopPhase::OwnedGuard;
    stop.registers.rip += 1;
    stop.signal = Some(signal(libc::SIGTRAP, libc::SI_KERNEL));
    let mut census = census(&stop);
    let reservation = census.reserve(charge()).unwrap();
    let id = census
        .insert(reservation, OriginKind::CurrentHeldPc, PC, stop.clone())
        .unwrap();
    let invocation = ExecutionId::from_owner(SESSION, 2).unwrap();
    let (input, completion, after) = selected(&stop, invocation);
    let proof = OwnerConsumption::completed_selected(
        invocation,
        stop.clone(),
        input,
        completion,
        after.clone(),
    )
    .unwrap();
    census.consume(reservation, id, proof.clone()).unwrap();
    assert_eq!(census.active().count(), 0);
    assert_eq!(census.rows().count(), 1);
    assert_eq!(
        census.history(),
        &[HistoryRecord::Consumed {
            origin: id,
            evidence: proof.clone()
        }]
    );
    unchanged(&mut census, CensusError::InactiveOrigin, |census| {
        census.consume(reservation, id, proof)
    });
    assert_eq!(census.rows().next().unwrap().initial, stop);
    assert_eq!(census.used().witnesses, 1);
    assert_eq!(after.registers.rip, PC + 2);
}

#[test]
fn completion_constructors_reject_wrong_phase_decode_state_and_identity() {
    let stop = initial();
    let invocation = ExecutionId::from_owner(SESSION, 3).unwrap();
    let (input, completion, after) = selected(&stop, invocation);
    for dimension in 0..6 {
        let mut bad_before = stop.clone();
        let mut bad_after = after.clone();
        let mut bad_completed = completion.clone();
        match dimension {
            0 => bad_after.phase = StopPhase::OwnedFetch,
            1 => {
                bad_after.logical_pc = PC;
                bad_after.registers.rip = PC;
                bad_completed.after.rip = PC;
            }
            2 => bad_before.registers.eflags ^= 1,
            3 => bad_after.token.session += 1,
            4 => bad_after.token.sequence = stop.token.sequence,
            5 => bad_completed.after.r11 ^= 1,
            _ => unreachable!(),
        }
        assert!(
            OwnerConsumption::completed_selected(
                invocation,
                bad_before,
                input.clone(),
                bad_completed,
                bad_after
            )
            .is_err()
        );
    }
    let mut next = stop.clone();
    next.logical_pc += 4096;
    next.registers.rip += 4096;
    next.token.sequence += 1;
    assert_eq!(
        OwnerConsumption::original_progress(
            invocation,
            stop.clone(),
            vec![0x90, 0x90],
            next.clone()
        ),
        Err(CensusError::InvalidConsumption)
    );
    next.phase = StopPhase::Interrupted;
    assert_eq!(
        OwnerConsumption::original_progress(invocation, stop, vec![0x90], next),
        Err(CensusError::InvalidConsumption)
    );
}

#[test]
fn different_pc_fetch_consumption_retains_fault_flags_and_full_state() {
    let stop = initial();
    let mut census = census(&stop);
    let reservation = census.reserve(charge()).unwrap();
    let id = census
        .insert(reservation, OriginKind::CurrentHeldPc, PC, stop.clone())
        .unwrap();
    let mut after = stop.clone();
    after.token.sequence += 1;
    after.logical_pc += 4096;
    after.registers.rip = after.logical_pc;
    after.registers.eflags |= 1 << 16;
    after.phase = StopPhase::OwnedFetch;
    after.signal = Some(signal(libc::SIGSEGV, 2));
    let proof = OwnerConsumption::original_progress(
        ExecutionId::from_owner(SESSION, 4).unwrap(),
        stop,
        vec![0xe9, 0xfb, 0x0f, 0, 0],
        after.clone(),
    )
    .unwrap();
    census.consume(reservation, id, proof).unwrap();
    let HistoryRecord::Consumed { evidence, .. } = &census.history()[0] else {
        panic!("missing consumption history")
    };
    assert_eq!(evidence.successor, after);
    assert_ne!(evidence.successor.registers.eflags & (1 << 16), 0);
    assert_eq!(census.active().count(), 0);
}

#[test]
fn generation_rebind_preserves_history_and_requires_fresh_current_evidence() {
    let stop = initial();
    let mut census = census(&stop);
    let reservation = census.reserve(charge()).unwrap();
    let id = census
        .insert(reservation, OriginKind::CurrentHeldPc, PC, stop.clone())
        .unwrap();
    unchanged(&mut census, CensusError::GenerationNotAdvanced, |census| {
        census.rebind_epoch(reservation, 2)
    });
    census.rebind_epoch(reservation, 1).unwrap();
    assert_eq!(
        census.check_current_origin(id, &stop),
        Err(CensusError::StaleObservation)
    );
    let mut rebound = stop.clone();
    rebound.task.generation = 1;
    census
        .refresh_same_pc(reservation, id, rebound.clone())
        .unwrap();
    assert_eq!(
        census.check_current_origin(id, &rebound).unwrap().initial,
        stop
    );
    assert_eq!(census.rows().next().unwrap().created_generation, 0);
    assert_eq!(census.generation(), 1);
    assert_eq!(census.history().len(), 2);
    assert_eq!(census.active().count(), 1);
}

#[test]
fn ledger_keeps_old_call_provenance_and_rejects_version_only_resume_changes() {
    let mut stop = initial();
    stop.logical_pc = PC + 5;
    stop.registers.rip = PC + 5;
    let mut census = census(&stop);
    let reservation = census.reserve(charge()).unwrap();
    let bytes = vec![0xe8, 0, 0, 0, 0, 0x90];
    let snapshot = Snapshot::new(
        MappingId(7),
        Generation(0),
        PC,
        bytes.clone(),
        Boundary::NonExecutable,
        Boundary::NonExecutable,
        WriteControl::Owned,
    )
    .unwrap();
    let heads = [
        (PC, EntryProvenance::VerifiedInstruction),
        (PC + 5, EntryProvenance::VerifiedInstruction),
    ];
    let original = LegalEntrySet::new(
        MappingId(7),
        Generation(0),
        0,
        snapshot.range(),
        Completeness::AllInstructionHeads,
        heads,
        [],
    )
    .unwrap();
    let mut ledger = CallReturnLedger::new();
    assert_eq!(
        ledger.record_before_admission(&snapshot, snapshot.range(), &original),
        Ok(1)
    );
    census
        .insert(reservation, OriginKind::CurrentHeldPc, PC + 5, stop)
        .unwrap();
    let changed = LegalEntrySet::new(
        MappingId(7),
        Generation(0),
        1,
        snapshot.range(),
        Completeness::AllInstructionHeads,
        heads,
        [(PC + 5, ResumeKind::ParkedThread)],
    )
    .unwrap();
    census
        .validate_projection(std::slice::from_ref(&changed))
        .unwrap();
    assert_eq!(
        ledger.record_before_admission(&snapshot, snapshot.range(), &changed),
        Err(ReturnError::ConflictingEntries)
    );
    assert_eq!(ledger.obligations().count(), 1);
    census.rebind_epoch(reservation, 1).unwrap();
    let newer = Snapshot::new(
        MappingId(7),
        Generation(1),
        PC,
        bytes,
        Boundary::NonExecutable,
        Boundary::NonExecutable,
        WriteControl::Owned,
    )
    .unwrap();
    let newer_entries = LegalEntrySet::new(
        MappingId(7),
        Generation(1),
        1,
        newer.range(),
        Completeness::AllInstructionHeads,
        heads,
        [(PC + 5, ResumeKind::ParkedThread)],
    )
    .unwrap();
    census
        .validate_projection(std::slice::from_ref(&newer_entries))
        .unwrap();
    assert_eq!(
        ledger.record_before_admission(&newer, newer.range(), &newer_entries),
        Ok(1)
    );
    assert_eq!(
        ledger
            .obligations()
            .map(|row| row.source_generation)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([Generation(0), Generation(1)])
    );
    assert_eq!(
        ledger.record_before_admission(&snapshot, snapshot.range(), &original),
        Err(ReturnError::StaleGeneration)
    );
    assert_eq!(ledger.obligations().count(), 2);
}

#[test]
fn exact_budget_consumption_and_finished_reservation_never_refund_history() {
    let stop = initial();
    let invocation = ExecutionId::from_owner(SESSION, 5).unwrap();
    let (input, completion, after) = selected(&stop, invocation);
    let proof =
        OwnerConsumption::completed_selected(invocation, stop.clone(), input, completion, after)
            .unwrap();
    let origin_bytes = 2 * stop.retained_bytes() + std::mem::size_of::<StoredOrigin>();
    let bytes = origin_bytes + proof.retained_bytes() + std::mem::size_of::<HistoryRecord>() + 17;
    let exact = Limits {
        epochs: 2,
        source_fact_bytes: bytes,
        reports: 1,
        origins: 1,
        witnesses: 1,
        plan_history: 1,
    };
    let mut census = ResumeCensus::new(SESSION, stop.task.address_space, 0, exact).unwrap();
    let reservation_charge = BudgetCharge {
        epochs: 1,
        source_fact_bytes: bytes,
        reports: 1,
        origins: 1,
        witnesses: 1,
        plan_history: 1,
    };
    let reservation = census.reserve(reservation_charge).unwrap();
    let id = census
        .insert(reservation, OriginKind::CurrentHeldPc, PC, stop)
        .unwrap();
    census.consume(reservation, id, proof).unwrap();
    census.rebind_epoch(reservation, 1).unwrap();
    census
        .account_external(
            reservation,
            BudgetCharge {
                source_fact_bytes: 17,
                reports: 1,
                plan_history: 1,
                ..BudgetCharge::default()
            },
        )
        .unwrap();
    let total = BudgetCharge {
        epochs: 2,
        ..reservation_charge
    };
    assert_eq!(census.used(), total);
    assert_eq!(census.charged(), total);
    unchanged(&mut census, CensusError::ReservationExhausted, |census| {
        census.account_external(
            reservation,
            BudgetCharge {
                reports: 1,
                ..BudgetCharge::default()
            },
        )
    });
    census.finish_reservation(reservation).unwrap();
    unchanged(&mut census, CensusError::Capacity, |census| {
        census.reserve(BudgetCharge {
            origins: 1,
            ..BudgetCharge::default()
        })
    });
    assert_eq!(census.rows().count(), 1);
    assert_eq!(census.history().len(), 2);
}

#[test]
fn stale_foreign_and_underfunded_operations_leave_full_bookkeeping_unchanged() {
    let stop = initial();
    let mut census = census(&stop);
    let reservation = census
        .reserve(BudgetCharge {
            origins: 1,
            source_fact_bytes: 1,
            ..BudgetCharge::default()
        })
        .unwrap();
    unchanged(&mut census, CensusError::ReservationExhausted, |census| {
        census.insert(reservation, OriginKind::CurrentHeldPc, PC, stop.clone())
    });
    unchanged(&mut census, CensusError::OutstandingReservation, |census| {
        census.reserve(charge())
    });
    let mut foreign = ResumeCensus::new(SESSION, stop.task.address_space, 0, limits()).unwrap();
    let foreign_token = foreign.reserve(charge()).unwrap();
    unchanged(&mut census, CensusError::StaleReservation, |census| {
        census.finish_reservation(foreign_token)
    });
    census.finish_reservation(reservation).unwrap();
    unchanged(&mut census, CensusError::StaleReservation, |census| {
        census.finish_reservation(reservation)
    });
    let next = census.reserve(charge()).unwrap();
    assert_ne!(next, reservation);
    let id = census
        .insert(next, OriginKind::CurrentHeldPc, PC, stop.clone())
        .unwrap();
    let mut corrupt = stop.clone();
    corrupt.registers.r11 ^= 1;
    unchanged(&mut census, CensusError::StaleObservation, |census| {
        census.refresh_same_pc(next, id, corrupt)
    });
    assert_eq!(census.rows().next().unwrap().initial, stop);
}

#[test]
fn completed_kernel_keeps_real_parent_exit_and_separate_newborn_across_epoch() {
    let (before, entry, parent_exit, newborn, input) = thread_pair();
    let invocation = ExecutionId::from_owner(SESSION, 6).unwrap();
    let kernel = CompletedKernel::clone_from_owner(
        invocation,
        before.clone(),
        input.clone(),
        entry.clone(),
        parent_exit.clone(),
        newborn.clone(),
    )
    .unwrap();
    assert_eq!(kernel.invocation(), invocation);
    assert_eq!(kernel.parent_exit(), &parent_exit);
    assert_eq!(kernel.newborn(), &newborn);
    let mut fabricated_child_exit = newborn.clone();
    fabricated_child_exit.phase = StopPhase::ParentSyscallExit {
        syscall: libc::SYS_clone as u64,
        result: 0,
        is_error: false,
    };
    assert_eq!(
        CompletedKernel::clone_from_owner(
            invocation,
            before.clone(),
            input.clone(),
            entry.clone(),
            parent_exit.clone(),
            fabricated_child_exit
        ),
        Err(CensusError::InvalidConsumption)
    );
    let mut wrong_parent_result = parent_exit.clone();
    wrong_parent_result.registers.rax += 1;
    assert_eq!(
        CompletedKernel::clone_from_owner(
            invocation,
            before.clone(),
            input,
            entry,
            wrong_parent_result,
            newborn
        ),
        Err(CensusError::InvalidConsumption)
    );
    let mut census = census(&before);
    let reservation = census.reserve(charge()).unwrap();
    let id = census
        .insert(reservation, OriginKind::CurrentHeldPc, PC, before)
        .unwrap();
    let proof = OwnerConsumption::completed_kernel(kernel.clone());
    census.consume(reservation, id, proof.clone()).unwrap();
    census.rebind_epoch(reservation, 1).unwrap();
    assert_eq!(
        census.history()[0],
        HistoryRecord::Consumed {
            origin: id,
            evidence: proof
        }
    );
    assert_eq!(kernel.parent_exit().task.generation, 0);
    assert_eq!(census.generation(), 1);
}

#[test]
fn persistent_unknown_cannot_borrow_matching_current_pc_consumption() {
    let stop = initial();
    let mut census = census(&stop);
    let reservation = census.reserve(charge()).unwrap();
    let unknown = census
        .insert(
            reservation,
            OriginKind::UnknownPersistent {
                kind: ResumeKind::SignalFrame,
            },
            PC,
            stop.clone(),
        )
        .unwrap();
    let invocation = ExecutionId::from_owner(SESSION, 7).unwrap();
    let (input, completed, after) = selected(&stop, invocation);
    let proof =
        OwnerConsumption::completed_selected(invocation, stop.clone(), input, completed, after)
            .unwrap();
    unchanged(&mut census, CensusError::PersistentUnknown, |census| {
        census.consume(reservation, unknown, proof)
    });
    unchanged(&mut census, CensusError::PersistentUnknown, |census| {
        census.refresh_same_pc(reservation, unknown, stop.clone())
    });
    assert_eq!(census.active().count(), 1);
    assert_eq!(
        census.check_current_origin(unknown, &stop),
        Err(CensusError::PersistentUnknown)
    );
    assert!(census.history().is_empty());
}

#[test]
fn terminal_requires_both_actual_wait_and_hup_and_keeps_persistent_origins() {
    let stop = initial();
    let mut census = census(&stop);
    let reservation = census.reserve(charge()).unwrap();
    let current = census
        .insert(reservation, OriginKind::CurrentHeldPc, PC, stop.clone())
        .unwrap();
    let saved = census
        .insert(
            reservation,
            OriginKind::UnknownPersistent {
                kind: ResumeKind::NonlocalJump,
            },
            PC,
            stop.clone(),
        )
        .unwrap();
    let terminal = ObservedTerminal {
        session: SESSION,
        task: stop.task,
        tid: stop.token.tid,
        sequence: stop.token.sequence + 1,
        wait_status: 23 << 8,
        pidfd_events: libc::POLLIN | libc::POLLHUP,
    };
    let mut merely_zombie = terminal.clone();
    merely_zombie.pidfd_events = libc::POLLIN;
    assert_eq!(
        OwnerTerminal::from_owner(stop.clone(), merely_zombie),
        Err(CensusError::InvalidConsumption)
    );
    let mut merely_stopped = terminal.clone();
    merely_stopped.wait_status = (libc::SIGTRAP << 8) | 0x7f;
    assert_eq!(
        OwnerTerminal::from_owner(stop.clone(), merely_stopped),
        Err(CensusError::InvalidConsumption)
    );
    let proof = OwnerTerminal::from_owner(stop.clone(), terminal).unwrap();
    unchanged(&mut census, CensusError::PersistentUnknown, |census| {
        census.retire_terminal(reservation, saved, proof.clone())
    });
    census
        .retire_terminal(reservation, current, proof.clone())
        .unwrap();
    assert_eq!(census.rows().count(), 2);
    assert_eq!(
        census.active().map(|row| row.row.id).collect::<Vec<_>>(),
        [saved]
    );
    assert_eq!(
        census.history(),
        &[HistoryRecord::Terminal {
            origin: current,
            evidence: proof.clone()
        }]
    );
    unchanged(&mut census, CensusError::InactiveOrigin, |census| {
        census.retire_terminal(reservation, current, proof)
    });
    assert_eq!(
        census.check_current_origin(saved, &stop),
        Err(CensusError::PersistentUnknown)
    );
}

#[test]
fn initial_epoch_consumes_the_only_epoch_without_inventing_a_transition() {
    let stop = initial();
    let mut bounded = limits();
    bounded.epochs = 1;
    let mut census = ResumeCensus::new(SESSION, stop.task.address_space, 17, bounded).unwrap();
    let initial_charge = BudgetCharge {
        epochs: 1,
        ..BudgetCharge::default()
    };
    assert_eq!(census.charged(), initial_charge);
    assert_eq!(census.used(), initial_charge);
    assert_eq!(census.generation(), 17);
    assert!(census.history().is_empty());
    unchanged(&mut census, CensusError::Capacity, |census| {
        census.reserve(initial_charge)
    });
    let reservation = census
        .reserve(BudgetCharge {
            source_fact_bytes: std::mem::size_of::<HistoryRecord>(),
            ..BudgetCharge::default()
        })
        .unwrap();
    unchanged(&mut census, CensusError::ReservationExhausted, |census| {
        census.rebind_epoch(reservation, 18)
    });
    census.finish_reservation(reservation).unwrap();
    assert_eq!(census.used(), initial_charge);
    assert_eq!(census.generation(), 17);
    assert!(census.history().is_empty());
}

#[test]
fn growing_current_xstate_is_charged_in_addition_to_history_and_never_refunded() {
    let before = initial();
    let mut after = before.clone();
    after.token.sequence += 1;
    after.phase = StopPhase::Interrupted;
    after.xstate.resize(MAX_XSTATE_BYTES, 0xa5);
    let origin_bytes = 2 * before.retained_bytes() + std::mem::size_of::<StoredOrigin>();
    let history_bytes =
        before.retained_bytes() + after.retained_bytes() + std::mem::size_of::<HistoryRecord>();
    let growth = after.xstate.len() - before.xstate.len();
    assert!(growth > 0);
    let mut shrunk = after.clone();
    shrunk.token.sequence += 1;
    shrunk.xstate = before.xstate.clone();
    let shrink_history_bytes =
        after.retained_bytes() + shrunk.retained_bytes() + std::mem::size_of::<HistoryRecord>();
    let exact_bytes = origin_bytes + history_bytes + growth + shrink_history_bytes;
    let mut bounded = limits();
    bounded.source_fact_bytes = exact_bytes;
    let mut census = ResumeCensus::new(SESSION, before.task.address_space, 0, bounded).unwrap();
    let short = census
        .reserve(BudgetCharge {
            origins: 1,
            witnesses: 1,
            source_fact_bytes: origin_bytes + history_bytes,
            ..BudgetCharge::default()
        })
        .unwrap();
    let id = census
        .insert(short, OriginKind::CurrentHeldPc, PC, before.clone())
        .unwrap();
    unchanged(&mut census, CensusError::ReservationExhausted, |census| {
        census.refresh_same_pc(short, id, after.clone())
    });
    assert_eq!(census.active().next().unwrap().current, &before);
    assert!(census.history().is_empty());

    // The rejected attempt keeps its reservation available. Explicitly reserve
    // the full charge in a fresh census; finishing unused capacity cannot refund it.
    census.finish_reservation(short).unwrap();
    let charged_before = census.charged();
    unchanged(&mut census, CensusError::Capacity, |census| {
        census.reserve(BudgetCharge {
            source_fact_bytes: exact_bytes,
            ..BudgetCharge::default()
        })
    });
    assert_eq!(census.charged(), charged_before);

    let mut exact = ResumeCensus::new(SESSION, before.task.address_space, 0, bounded).unwrap();
    let reservation = exact
        .reserve(BudgetCharge {
            origins: 1,
            witnesses: 2,
            source_fact_bytes: exact_bytes,
            ..BudgetCharge::default()
        })
        .unwrap();
    let id = exact
        .insert(reservation, OriginKind::CurrentHeldPc, PC, before.clone())
        .unwrap();
    exact
        .refresh_same_pc(reservation, id, after.clone())
        .unwrap();
    assert_eq!(
        exact.used().source_fact_bytes,
        origin_bytes + history_bytes + growth
    );
    assert_eq!(exact.active().next().unwrap().current, &after);
    assert_eq!(
        exact.history()[0],
        HistoryRecord::Refreshed {
            origin: id,
            before,
            after: after.clone()
        }
    );
    exact
        .refresh_same_pc(reservation, id, shrunk.clone())
        .unwrap();
    assert_eq!(exact.used().source_fact_bytes, exact_bytes);
    assert_eq!(exact.charged().source_fact_bytes, exact_bytes);
    assert_eq!(exact.active().next().unwrap().current, &shrunk);
    assert_eq!(
        exact.history()[1],
        HistoryRecord::Refreshed {
            origin: id,
            before: after,
            after: shrunk
        }
    );
    exact.finish_reservation(reservation).unwrap();
    unchanged(&mut exact, CensusError::Capacity, |census| {
        census.reserve(BudgetCharge {
            source_fact_bytes: 1,
            ..BudgetCharge::default()
        })
    });
}

#[test]
fn remaining_preflight_is_read_only_and_rejects_consumed_stale_or_foreign_capacity() {
    let stop = initial();
    let mut census = census(&stop);
    let charge = BudgetCharge {
        source_fact_bytes: 23,
        reports: 1,
        ..BudgetCharge::default()
    };
    let reservation = census.reserve(charge).unwrap();
    let before = census.state.clone();
    assert_eq!(census.check_reserved(reservation, charge), Ok(()));
    assert_eq!(census.state, before);
    assert_eq!(
        census.check_reserved(
            reservation,
            BudgetCharge {
                source_fact_bytes: 24,
                ..charge
            }
        ),
        Err(CensusError::ReservationExhausted)
    );
    assert_eq!(census.state, before);
    census.account_external(reservation, charge).unwrap();
    let used = census.state.clone();
    assert_eq!(
        census.check_reserved(reservation, charge),
        Err(CensusError::ReservationExhausted)
    );
    assert_eq!(
        census.check_reserved(reservation, BudgetCharge::default()),
        Ok(())
    );
    assert_eq!(census.state, used);
    let mut foreign = ResumeCensus::new(SESSION, stop.task.address_space, 0, limits()).unwrap();
    let foreign_token = foreign.reserve(charge).unwrap();
    assert_eq!(
        census.check_reserved(foreign_token, BudgetCharge::default()),
        Err(CensusError::StaleReservation)
    );
    assert_eq!(census.state, used);
    census.finish_reservation(reservation).unwrap();
    let finished = census.state.clone();
    assert_eq!(
        census.check_reserved(reservation, BudgetCharge::default()),
        Err(CensusError::StaleReservation)
    );
    assert_eq!(census.state, finished);
}
