//! Pure accounting/identity controls. The cfg(test) seal is explicitly
//! synthetic: none of these cases observes exec, establishes exclusion,
//! authenticates a new bootstrap or permits a native release.

use super::*;
use crate::lifecycle::{HoldReason, LifecycleRegistry};

const SESSION: u64 = 0x51;
const OLD_PC: u64 = 0x401000;
const NEW_PC: u64 = 0x601000;

fn limits() -> Limits {
    Limits {
        epochs: 32,
        source_fact_bytes: 64 * 1024 * 1024,
        reports: 64,
        origins: 64,
        witnesses: 128,
        plan_history: 64,
    }
}

fn envelope() -> BudgetCharge {
    BudgetCharge {
        epochs: 8,
        source_fact_bytes: 1 << 20,
        reports: 12,
        origins: 12,
        witnesses: 24,
        plan_history: 12,
    }
}

fn regs(pc: u64) -> RegisterSnapshot {
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
        rsp: 0x801000,
        ss: 0x2b,
        fs_base: 0x901000,
        gs_base: 0xa01000,
        ds: 0,
        es: 0,
        fs: 0,
        gs: 0,
    }
}

fn observation(registry: &LifecycleRegistry, task: TaskId, pc: u64, sequence: u64) -> ObservedStop {
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
        registers: regs(pc),
        xstate: vec![0x5a; 832],
        signal_mask: 0x200,
        phase: StopPhase::UserCheckpoint,
        signal: None,
    }
}

// Registry-produced identities are genuine model identities. The phase/state
// observations and native seal remain synthetic and supply no kernel proof.
fn model_pair() -> (ObservedStop, ObservedStop) {
    let mut registry = LifecycleRegistry::new(
        crate::lifecycle::Limits {
            tasks: 4,
            processes: 2,
            address_spaces: 3,
            obligations: 16,
        },
        100,
        OLD_PC,
    )
    .unwrap();
    let old = registry.root_task();
    let before = observation(&registry, old, OLD_PC, 10);
    registry.resume(old, 0).unwrap();
    registry
        .observe_stop(old, 1, OLD_PC + 2, HoldReason::SyscallEntry)
        .unwrap();
    let ticket = registry.prepare_exec(old).unwrap();
    registry.resume(old, 1).unwrap();
    let transition = registry
        .observe_exec_event(ticket, 2, 100, 100, NEW_PC)
        .unwrap();
    let mut after = observation(&registry, transition.task, NEW_PC, 30);
    after.registers.rax = 0;
    after.registers.rsp = 0xb01000;
    after.xstate = vec![0xa5; 976];
    after.signal_mask = 0x600;
    assert_ne!(before.task.task, after.task.task);
    assert_ne!(before.task.address_space, after.task.address_space);
    assert_eq!(before.task.process, after.task.process);
    (before, after)
}

struct Fixture {
    census: ResumeCensus,
    reservation: Reservation,
    origin: OriginId,
    consumed: OriginId,
    invocation: ExecutionId,
    before: ObservedStop,
    after: ObservedStop,
}

impl Fixture {
    fn new() -> Self {
        let (initial, after) = model_pair();
        let mut census =
            ResumeCensus::new(SESSION, initial.task.address_space, 0, limits()).unwrap();
        let reservation = census.reserve(envelope()).unwrap();
        let consumed = census
            .insert(
                reservation,
                OriginKind::CurrentHeldPc,
                initial.logical_pc,
                initial.clone(),
            )
            .unwrap();
        let mut before = initial.clone();
        before.logical_pc += 1;
        before.registers.rip += 1;
        before.token.sequence += 1;
        let progress = OwnerConsumption::original_progress(
            ExecutionId::from_owner(SESSION, 7).unwrap(),
            initial,
            vec![0x90],
            before.clone(),
        )
        .unwrap();
        census.consume(reservation, consumed, progress).unwrap();
        let origin = census
            .insert(
                reservation,
                OriginKind::CurrentHeldPc,
                before.logical_pc,
                before.clone(),
            )
            .unwrap();
        before.token.sequence += 1;
        before.registers.r14 ^= 0x80;
        census
            .refresh_same_pc(reservation, origin, before.clone())
            .unwrap();
        census.rebind_epoch(reservation, 1).unwrap();
        before.task.generation = 1;
        census
            .refresh_same_pc(reservation, origin, before.clone())
            .unwrap();
        census
            .account_external(
                reservation,
                BudgetCharge {
                    reports: 3,
                    plan_history: 2,
                    source_fact_bytes: 37,
                    ..BudgetCharge::default()
                },
            )
            .unwrap();
        Self {
            census,
            reservation,
            origin,
            consumed,
            invocation: ExecutionId::from_owner(SESSION, 9).unwrap(),
            before,
            after,
        }
    }

    fn prepare(&mut self) -> PreparedExecCensus {
        self.census
            .prepare_exec_mm(self.reservation, self.origin, self.invocation)
            .unwrap()
    }

    fn seal(&self, prepared: &PreparedExecCensus) -> ExecCensusCommit {
        ExecCensusCommit::synthetic_for_test(
            prepared.binding(),
            self.before.clone(),
            self.after.clone(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WholeCensus {
    identity: u64,
    session: u64,
    space: AddressSpaceId,
    limits: Limits,
    state: State,
}

fn whole(census: &ResumeCensus) -> WholeCensus {
    WholeCensus {
        identity: census.identity,
        session: census.session,
        space: census.space,
        limits: census.limits,
        state: census.state.clone(),
    }
}

fn refuses<T>(
    census: &mut ResumeCensus,
    expected: CensusError,
    action: impl FnOnce(&mut ResumeCensus) -> Result<T, CensusError>,
) {
    let before = whole(census);
    assert_eq!(action(census).err(), Some(expected));
    assert_eq!(whole(census), before);
}

fn axis(charge: &mut BudgetCharge, index: usize) -> &mut usize {
    match index {
        0 => &mut charge.epochs,
        1 => &mut charge.source_fact_bytes,
        2 => &mut charge.reports,
        3 => &mut charge.origins,
        4 => &mut charge.witnesses,
        5 => &mut charge.plan_history,
        _ => panic!("invalid synthetic budget axis"),
    }
}

#[test]
fn exec_handoff_moves_complete_old_vectors_and_keeps_one_lifetime_account() {
    let mut f = Fixture::new();
    let prepared = f.prepare();
    let seal = f.seal(&prepared);
    let saved = whole(&f.census);
    let old_origins = f.census.state.origins.as_ptr();
    let old_history = f.census.state.history.as_ptr();
    let account = &f.census as *const ResumeCensus;
    let (retired, reservation, origin) = f
        .census
        .commit_exec_mm(f.reservation, prepared, seal, &f.after)
        .unwrap();
    assert_eq!(&f.census as *const ResumeCensus, account);
    assert_eq!(retired.origins.as_ptr(), old_origins);
    assert_eq!(retired.history.as_ptr(), old_history);
    assert_eq!(retired.origins, saved.state.origins);
    assert_eq!(retired.history(), saved.state.history.as_slice());
    assert!(!retired.origins[0].active);
    assert!(retired.origins[1].active);
    assert_eq!(retired.origins[0].row.id, f.consumed);
    assert_eq!(retired.origins[1].row.id, f.origin);
    assert_eq!(retired.rows().count(), 2);
    assert_eq!(
        retired.accounting_at_retirement(),
        (saved.state.charged, saved.state.used)
    );
    assert_eq!(retired.binding().invocation, f.invocation);
    assert_eq!(retired.retirement.old_stop, f.before.token);
    assert_eq!(retired.retirement.new_stop, f.after.token);
    assert_eq!(retired.retirement.new_task, f.after.task);

    // Independent layout inventory: two complete retained initial/current
    // observations, one stored origin and the distinct retirement metadata.
    let expected_bytes = 2 * (std::mem::size_of::<ObservedStop>() + f.after.xstate.len())
        + std::mem::size_of::<StoredOrigin>()
        + std::mem::size_of::<RetiredCensus>();
    let debit = BudgetCharge {
        epochs: 1,
        source_fact_bytes: expected_bytes,
        origins: 1,
        witnesses: 1,
        reports: 0,
        plan_history: 0,
    };
    let actual = f.census.used();
    assert_eq!(actual.epochs, saved.state.used.epochs + 1);
    assert_eq!(
        actual.source_fact_bytes,
        saved.state.used.source_fact_bytes + expected_bytes
    );
    assert_eq!(actual.reports, saved.state.used.reports);
    assert_eq!(actual.origins, saved.state.used.origins + 1);
    assert_eq!(actual.witnesses, saved.state.used.witnesses + 1);
    assert_eq!(actual.plan_history, saved.state.used.plan_history);
    assert_eq!(f.census.charged(), saved.state.charged);
    assert_eq!(f.census.limits, saved.limits);
    assert_eq!(
        f.census.remaining(reservation).unwrap(),
        saved.state.reservation.unwrap().1.subtract(debit).unwrap()
    );
    assert_eq!(f.census.generation(), 0);
    assert_eq!(f.census.space, f.after.task.address_space);
    assert_eq!(f.census.session, saved.session);
    assert!(f.census.history().is_empty());
    assert_eq!(f.census.state.origins.len(), 1);
    let active = f.census.active().next().unwrap();
    assert_eq!(active.row.id, origin);
    assert_eq!(active.row.initial, f.after);
    assert_eq!(active.current, &f.after);
    assert_eq!(active.row.created_generation, 0);
    assert_eq!(active.row.kind, OriginKind::CurrentHeldPc);
    f.census.check_current_origin(origin, &f.after).unwrap();
    f.census.finish_reservation(reservation).unwrap();
    assert_eq!(f.census.charged(), saved.state.charged);
    assert_eq!(f.census.used(), actual);
}

#[test]
fn exec_nonce_rotation_rejects_old_tokens_and_unused_old_preparation() {
    let mut f = Fixture::new();
    let prepared = f.prepare();
    let unused = f.prepare();
    assert_ne!(prepared.identity, unused.identity);
    let old_identity = f.census.identity;
    let seal = f.seal(&prepared);
    let unused_seal = f.seal(&unused);
    let (retired, reservation, origin) = f
        .census
        .commit_exec_mm(f.reservation, prepared, seal, &f.after)
        .unwrap();
    assert_ne!(f.census.identity, old_identity);
    assert_eq!(reservation.census, f.census.identity);
    assert_eq!(origin.census, f.census.identity);
    assert_eq!(retired.binding().census, old_identity);
    refuses(&mut f.census, CensusError::StaleReservation, |c| {
        c.finish_reservation(f.reservation)
    });
    refuses(&mut f.census, CensusError::StaleReservation, |c| {
        c.account_external(f.reservation, BudgetCharge::default())
    });
    assert_eq!(
        f.census.check_current_origin(f.origin, &f.after).err(),
        Some(CensusError::UnknownOrigin)
    );
    assert_eq!(
        f.census.check_current_origin(f.consumed, &f.after).err(),
        Some(CensusError::UnknownOrigin)
    );
    refuses(&mut f.census, CensusError::IdentityMismatch, |c| {
        c.commit_exec_mm(reservation, unused, unused_seal, &f.after)
    });
    f.census.check_current_origin(origin, &f.after).unwrap();
}

#[test]
fn exec_prepare_requires_exact_current_singleton_origin_and_invocation() {
    for case in 0..11 {
        let mut f = Fixture::new();
        let mut reservation = f.reservation;
        let mut origin = f.origin;
        let mut invocation = f.invocation;
        let expected = match case {
            0 => {
                reservation.census += 1;
                CensusError::StaleReservation
            }
            1 => {
                origin.census += 1;
                CensusError::UnknownOrigin
            }
            2 => {
                origin = f.consumed;
                CensusError::InactiveOrigin
            }
            3 => {
                invocation.session += 1;
                CensusError::IdentityMismatch
            }
            4 => {
                invocation.serial = 0;
                CensusError::IdentityMismatch
            }
            5 => {
                f.census
                    .insert(
                        reservation,
                        OriginKind::CurrentHeldPc,
                        f.before.logical_pc,
                        f.before.clone(),
                    )
                    .unwrap();
                CensusError::PersistentUnknown
            }
            6 => {
                f.census.state.origins[1].row.kind = OriginKind::UnknownPersistent {
                    kind: ResumeKind::SignalFrame,
                };
                CensusError::PersistentUnknown
            }
            7 => {
                f.census.state.origins[1].current.phase = StopPhase::Interrupted;
                CensusError::WrongOriginPhase
            }
            8 => {
                f.census.state.origins[1].current.registers.orig_rax = libc::SYS_execve as u64;
                CensusError::WrongOriginPhase
            }
            9 => {
                f.census.state.origins[1].current.signal =
                    Some(DynamicSignalInfo { raw: [0; 128] });
                CensusError::WrongOriginPhase
            }
            10 => {
                f.census.state.origins[1].current.registers.cs = 0x23;
                CensusError::InvalidObservation
            }
            _ => unreachable!(),
        };
        refuses(&mut f.census, expected, |c| {
            c.prepare_exec_mm(reservation, origin, invocation)
        });
    }
}

#[test]
fn exec_preparation_requires_max_seed_capacity_and_dropped_nonces_are_not_reused() {
    let required = exec_initial_charge(MAX_XSTATE_BYTES).unwrap();
    for dimension in [0, 1, 3, 4] {
        let mut f = Fixture::new();
        let mut one_short = required;
        *axis(&mut one_short, dimension) -= 1;
        f.census.state.reservation.as_mut().unwrap().1 = one_short;
        refuses(&mut f.census, CensusError::ReservationExhausted, |c| {
            c.prepare_exec_mm(f.reservation, f.origin, f.invocation)
        });
    }
    let mut f = Fixture::new();
    f.census.state.reservation.as_mut().unwrap().1 = required;
    let before = whole(&f.census);
    let first = f.prepare();
    let issued = first.identity;
    assert_eq!(whole(&f.census), before);
    drop(first);
    assert_eq!(whole(&f.census), before);
    let second = f.prepare();
    assert_ne!(second.identity, issued);
    assert!(second.initial_xstate.capacity() >= MAX_XSTATE_BYTES);
    assert!(second.current_xstate.capacity() >= MAX_XSTATE_BYTES);
    assert_eq!(whole(&f.census), before);
    drop(second);
    f.census.finish_reservation(f.reservation).unwrap();
    assert_eq!(f.census.charged(), before.state.charged);
    assert_eq!(f.census.used(), before.state.used);
    for size in [0, MAX_XSTATE_BYTES + 1, usize::MAX] {
        assert_eq!(
            exec_initial_charge(size),
            Err(CensusError::InvalidObservation)
        );
    }
}

#[test]
fn exec_commit_checks_current_remaining_capacity_and_preserves_failure_state() {
    for dimension in [0, 1, 3, 4] {
        let mut f = Fixture::new();
        let prepared = f.prepare();
        let seal = f.seal(&prepared);
        let mut required = exec_initial_charge(f.after.xstate.len()).unwrap();
        *axis(
            &mut f.census.state.reservation.as_mut().unwrap().1,
            dimension,
        ) = *axis(&mut required, dimension) - 1;
        refuses(&mut f.census, CensusError::ReservationExhausted, |c| {
            c.commit_exec_mm(f.reservation, prepared, seal, &f.after)
        });
    }
    // A real model API debit after preparation must not be ignored at commit.
    let mut f = Fixture::new();
    let prepared = f.prepare();
    let seal = f.seal(&prepared);
    let required = exec_initial_charge(f.after.xstate.len()).unwrap();
    let remaining = f.census.remaining(f.reservation).unwrap();
    f.census
        .account_external(
            f.reservation,
            BudgetCharge {
                source_fact_bytes: remaining.source_fact_bytes - required.source_fact_bytes + 1,
                ..BudgetCharge::default()
            },
        )
        .unwrap();
    refuses(&mut f.census, CensusError::ReservationExhausted, |c| {
        c.commit_exec_mm(f.reservation, prepared, seal, &f.after)
    });
}

#[test]
fn exec_commit_refuses_foreign_stale_and_malformed_new_observations_atomically() {
    for case in 0..18 {
        let mut f = Fixture::new();
        let prepared = f.prepare();
        let seal = f.seal(&prepared);
        let mut after = f.after.clone();
        let (foreign, _) = model_pair();
        let expected = match case {
            0 => {
                after.token.session += 1;
                CensusError::IdentityMismatch
            }
            1 => {
                after.token.task = Some(f.before.task.task);
                CensusError::IdentityMismatch
            }
            2 => {
                after.task.task = f.before.task.task;
                after.token.task = Some(after.task.task);
                CensusError::IdentityMismatch
            }
            3 => {
                after.task.address_space = f.before.task.address_space;
                CensusError::IdentityMismatch
            }
            4 => {
                after.task.process = foreign.task.process;
                CensusError::IdentityMismatch
            }
            5 => {
                after.token.tid += 1;
                CensusError::IdentityMismatch
            }
            6 => {
                after.token.tid = 0;
                CensusError::IdentityMismatch
            }
            7 => {
                after.task.generation = 1;
                CensusError::StaleObservation
            }
            8 => {
                after.token.sequence = f.before.token.sequence;
                CensusError::StaleObservation
            }
            9 => {
                after.token.sequence = f.before.token.sequence - 1;
                CensusError::StaleObservation
            }
            10 => {
                after.phase = StopPhase::Interrupted;
                CensusError::WrongOriginPhase
            }
            11 => {
                after.registers.orig_rax = libc::SYS_execve as u64;
                CensusError::WrongOriginPhase
            }
            12 => {
                after.registers.cs = 0x23;
                CensusError::InvalidObservation
            }
            13 => {
                after.registers.rip += 1;
                CensusError::InvalidObservation
            }
            14 => {
                after.xstate.clear();
                CensusError::InvalidObservation
            }
            15 => {
                after.xstate.resize(MAX_XSTATE_BYTES + 1, 0);
                CensusError::InvalidObservation
            }
            16 => {
                after.logical_pc = 0;
                after.registers.rip = 0;
                CensusError::InvalidObservation
            }
            17 => {
                after.signal = Some(DynamicSignalInfo { raw: [0; 128] });
                CensusError::WrongOriginPhase
            }
            _ => unreachable!(),
        };
        refuses(&mut f.census, expected, |c| {
            c.commit_exec_mm(f.reservation, prepared, seal, &after)
        });
    }
}

fn corrupt_register(registers: &mut RegisterSnapshot, index: usize) {
    let field = match index {
        0 => &mut registers.r15,
        1 => &mut registers.r14,
        2 => &mut registers.r13,
        3 => &mut registers.r12,
        4 => &mut registers.rbp,
        5 => &mut registers.rbx,
        6 => &mut registers.r11,
        7 => &mut registers.r10,
        8 => &mut registers.r9,
        9 => &mut registers.r8,
        10 => &mut registers.rax,
        11 => &mut registers.rcx,
        12 => &mut registers.rdx,
        13 => &mut registers.rsi,
        14 => &mut registers.rdi,
        15 => &mut registers.orig_rax,
        16 => &mut registers.rip,
        17 => &mut registers.cs,
        18 => &mut registers.eflags,
        19 => &mut registers.rsp,
        20 => &mut registers.ss,
        21 => &mut registers.fs_base,
        22 => &mut registers.gs_base,
        23 => &mut registers.ds,
        24 => &mut registers.es,
        25 => &mut registers.fs,
        26 => &mut registers.gs,
        _ => panic!("invalid synthetic register index"),
    };
    *field ^= 1;
}

#[test]
fn exec_native_seal_must_bind_full_before_after_and_original_invocation() {
    for side in 0..2 {
        for field in 0..31 {
            let mut f = Fixture::new();
            let prepared = f.prepare();
            let mut expected_before = f.before.clone();
            let mut expected_after = f.after.clone();
            let stop = if side == 0 {
                &mut expected_before
            } else {
                &mut expected_after
            };
            match field {
                0..=26 => corrupt_register(&mut stop.registers, field),
                27 => stop.xstate[0] ^= 1,
                28 => stop.signal_mask ^= 1,
                29 => stop.logical_pc += 1,
                30 => stop.token.sequence += 1,
                _ => unreachable!(),
            }
            let seal = ExecCensusCommit::synthetic_for_test(
                prepared.binding(),
                expected_before,
                expected_after,
            );
            refuses(&mut f.census, CensusError::StaleObservation, |c| {
                c.commit_exec_mm(f.reservation, prepared, seal, &f.after)
            });
        }
    }
    let mut f = Fixture::new();
    let prepared = f.prepare();
    let mut binding = prepared.binding();
    binding.invocation = ExecutionId::from_owner(SESSION, 10).unwrap();
    let seal = ExecCensusCommit::synthetic_for_test(binding, f.before.clone(), f.after.clone());
    refuses(&mut f.census, CensusError::IdentityMismatch, |c| {
        c.commit_exec_mm(f.reservation, prepared, seal, &f.after)
    });
}

#[test]
fn exec_prepared_identity_and_storage_cannot_be_substituted_after_effects() {
    for case in 0..11 {
        let mut f = Fixture::new();
        let mut prepared = f.prepare();
        let seal = f.seal(&prepared);
        let expected = match case {
            0 => {
                prepared.binding.census += 1;
                CensusError::IdentityMismatch
            }
            1 => {
                prepared.binding.session += 1;
                CensusError::IdentityMismatch
            }
            2 => {
                prepared.binding.space = f.after.task.address_space;
                CensusError::IdentityMismatch
            }
            3 => {
                prepared.binding.generation += 1;
                CensusError::IdentityMismatch
            }
            4 => {
                prepared.binding.reservation.serial += 1;
                CensusError::IdentityMismatch
            }
            5 => {
                prepared.identity = 0;
                CensusError::IdentityMismatch
            }
            6 => {
                prepared.identity = f.census.identity;
                CensusError::IdentityMismatch
            }
            7 => {
                prepared.initial_xstate.push(0);
                CensusError::Allocation
            }
            8 => {
                prepared.current_xstate = Vec::new();
                CensusError::Allocation
            }
            9 => {
                prepared.origins = Vec::new();
                CensusError::Allocation
            }
            10 => {
                prepared.history = Vec::new();
                CensusError::Allocation
            }
            _ => unreachable!(),
        };
        refuses(&mut f.census, expected, |c| {
            c.commit_exec_mm(f.reservation, prepared, seal, &f.after)
        });
    }
}

#[test]
fn exec_handoff_preserves_all_six_caps_and_checked_counter_failures() {
    let mut f = Fixture::new();
    let prepared = f.prepare();
    let seal = f.seal(&prepared);
    let (_, reservation, _) = f
        .census
        .commit_exec_mm(f.reservation, prepared, seal, &f.after)
        .unwrap();
    f.census.finish_reservation(reservation).unwrap();
    let charged = f.census.charged();
    f.census.limits = Limits {
        epochs: charged.epochs,
        source_fact_bytes: charged.source_fact_bytes,
        reports: charged.reports,
        origins: charged.origins,
        witnesses: charged.witnesses,
        plan_history: charged.plan_history,
    };
    for dimension in 0..6 {
        let mut extra = BudgetCharge::default();
        *axis(&mut extra, dimension) = 1;
        refuses(&mut f.census, CensusError::Capacity, |c| c.reserve(extra));
    }
    for dimension in [0, 1, 3, 4] {
        let mut f = Fixture::new();
        let prepared = f.prepare();
        let seal = f.seal(&prepared);
        *axis(&mut f.census.state.used, dimension) = usize::MAX;
        refuses(&mut f.census, CensusError::Capacity, |c| {
            c.commit_exec_mm(f.reservation, prepared, seal, &f.after)
        });
    }
    // Corrupted/overflowing bookkeeping inputs are synthetic negatives. They
    // must refuse before allocation or any change to the existing account.
    let mut f = Fixture::new();
    f.census.state.reservation.as_mut().unwrap().1.witnesses = usize::MAX;
    refuses(&mut f.census, CensusError::Capacity, |c| {
        c.prepare_exec_mm(f.reservation, f.origin, f.invocation)
    });
    for initial in [0, u64::MAX] {
        let counter = AtomicU64::new(initial);
        assert_eq!(next_identity(&counter), Err(CensusError::Capacity));
        assert_eq!(counter.load(Ordering::Relaxed), initial);
    }
    let counter = AtomicU64::new(u64::MAX - 1);
    assert_eq!(next_identity(&counter), Ok(u64::MAX - 1));
    assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    assert_eq!(next_identity(&counter), Err(CensusError::Capacity));
    assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
}

#[test]
fn exec_preparation_allows_exact_hidden_refresh_but_not_epoch_substitution() {
    let mut f = Fixture::new();
    let prepared = f.prepare();
    f.before.token.sequence += 1;
    f.before.registers.r13 ^= 4;
    f.census
        .refresh_same_pc(f.reservation, f.origin, f.before.clone())
        .unwrap();
    let seal = f.seal(&prepared);
    let (_, reservation, origin) = f
        .census
        .commit_exec_mm(f.reservation, prepared, seal, &f.after)
        .unwrap();
    f.census.check_current_origin(origin, &f.after).unwrap();
    assert_eq!(f.census.remaining(reservation).unwrap().reports, 9);

    let mut f = Fixture::new();
    let prepared = f.prepare();
    let seal = f.seal(&prepared);
    f.census.rebind_epoch(f.reservation, 2).unwrap();
    f.before.task.generation = 2;
    f.census
        .refresh_same_pc(f.reservation, f.origin, f.before.clone())
        .unwrap();
    refuses(&mut f.census, CensusError::IdentityMismatch, |c| {
        c.commit_exec_mm(f.reservation, prepared, seal, &f.after)
    });
}

#[test]
fn exec_new_task_sequence_is_local_and_still_requires_the_exact_native_seal() {
    // These are synthetic seal controls, not native phase evidence. Linux's
    // registry creates the replacement TaskRecord at zero; a real bootstrap
    // may therefore have a lower sequence than the retired task's last stop.
    for relation in 0..4 {
        let mut f = Fixture::new();
        f.after.token.sequence = match relation {
            0 => 1,
            1 => f.before.token.sequence - 1,
            2 => f.before.token.sequence,
            3 => f.before.token.sequence + 1,
            _ => unreachable!(),
        };
        let original = whole(&f.census);
        let debit = BudgetCharge {
            epochs: 1,
            origins: 1,
            witnesses: 1,
            source_fact_bytes: 2 * (std::mem::size_of::<ObservedStop>() + f.after.xstate.len())
                + std::mem::size_of::<StoredOrigin>()
                + std::mem::size_of::<RetiredCensus>(),
            reports: 0,
            plan_history: 0,
        };
        let expected_used = original.state.used.add(debit).unwrap();
        let prepared = f.prepare();
        let seal = f.seal(&prepared);
        let (retired, reservation, origin) = f
            .census
            .commit_exec_mm(f.reservation, prepared, seal, &f.after)
            .unwrap();
        assert_eq!(retired.origins, original.state.origins);
        assert_eq!(retired.history, original.state.history);
        assert_eq!(f.census.state.charged, original.state.charged);
        assert_eq!(f.census.state.used, expected_used);
        assert_eq!(
            f.census.remaining(reservation).unwrap(),
            original
                .state
                .reservation
                .unwrap()
                .1
                .subtract(debit)
                .unwrap()
        );
        f.census.check_current_origin(origin, &f.after).unwrap();
    }
    for violation in 0..3 {
        let mut f = Fixture::new();
        let prepared = f.prepare();
        let mut after = f.after.clone();
        after.token.sequence = 1;
        let (seal, expected) = match violation {
            0 => (f.seal(&prepared), CensusError::StaleObservation),
            1 => {
                after.task.task = f.before.task.task;
                after.token.task = Some(after.task.task);
                (
                    ExecCensusCommit::synthetic_for_test(
                        prepared.binding(),
                        f.before.clone(),
                        after.clone(),
                    ),
                    CensusError::IdentityMismatch,
                )
            }
            2 => {
                after.token.sequence = 0;
                (
                    ExecCensusCommit::synthetic_for_test(
                        prepared.binding(),
                        f.before.clone(),
                        after.clone(),
                    ),
                    CensusError::StaleObservation,
                )
            }
            _ => unreachable!(),
        };
        refuses(&mut f.census, expected, |c| {
            c.commit_exec_mm(f.reservation, prepared, seal, &after)
        });
    }
}
