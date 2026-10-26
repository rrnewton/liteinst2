//! Synthetic saved-frame bookkeeping controls only. No test observes a native
//! signal, authenticates bytes, grants an exclusion lease or retires a CALL.
//! Lifecycle identities come from the independent pure registry; every stop and
//! syscall-info byte below is explicitly a model input, not kernel evidence.
use super::*;
use crate::lifecycle::{LifecycleRegistry, SignalEvent};

const SESSION: u64 = 73;
const PC: u64 = 0x401080;
const HANDLER: u64 = 0x402000;
const RESTORER: u64 = 0x403005;
const LANDING: u64 = 0x404000;
const FRAME: u64 = 0x700008;

fn limits() -> Limits {
    Limits {
        epochs: 16,
        source_fact_bytes: 8 << 20,
        reports: 32,
        origins: 64,
        witnesses: 128,
        plan_history: 32,
    }
}
fn charge() -> BudgetCharge {
    BudgetCharge {
        epochs: 4,
        source_fact_bytes: 1 << 20,
        reports: 4,
        origins: 16,
        witnesses: 32,
        plan_history: 4,
    }
}
fn registers(pc: u64) -> RegisterSnapshot {
    RegisterSnapshot {
        r15: 15,
        r14: 14,
        r13: 13,
        r12: 12,
        rbp: 5,
        rbx: 3,
        r11: 11,
        r10: 10,
        r9: 9,
        r8: 8,
        rax: (-22_i64) as u64,
        rcx: 1,
        rdx: 2,
        rsi: 6,
        rdi: 7,
        orig_rax: u64::MAX,
        rip: pc,
        cs: 0x33,
        eflags: 0xed7,
        rsp: 0x71ff00,
        ss: 0x2b,
        fs_base: 0x12340000,
        gs_base: 0x56780000,
        ds: 0,
        es: 0,
        fs: 0,
        gs: 0,
    }
}
fn info(signal: i32, code: i32) -> DynamicSignalInfo {
    let mut raw = [0_u8; 128];
    raw[..4].copy_from_slice(&signal.to_ne_bytes());
    raw[8..12].copy_from_slice(&code.to_ne_bytes());
    raw[16..24].copy_from_slice(&HANDLER.to_ne_bytes());
    DynamicSignalInfo { raw }
}
fn put(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

struct Fixture {
    delivery: ObservedStop,
    fetch: ObservedStop,
    frame: Arc<FrameFacts>,
    obligation: ObligationRecord,
    identical_signal: ObligationRecord,
}
impl Fixture {
    fn new(prospective: bool) -> Self {
        let mut registry = LifecycleRegistry::new(
            crate::lifecycle::Limits {
                tasks: 4,
                processes: 2,
                address_spaces: 2,
                obligations: 16,
            },
            100,
            PC,
        )
        .unwrap();
        let task = registry.root_task();
        let event = SignalEvent {
            pc: PC,
            signal: 44,
            code: libc::SI_QUEUE,
            scope: SignalScope::Unknown,
        };
        registry.resume(task, 0).unwrap();
        let first = registry.observe_signal(task, 1, event).unwrap();
        registry.resume(task, 1).unwrap();
        let second = registry.observe_signal(task, 2, event).unwrap();
        let obligation = registry
            .obligations()
            .find(|row| row.id == first)
            .unwrap()
            .clone();
        let identical_signal = registry
            .obligations()
            .find(|row| row.id == second)
            .unwrap()
            .clone();
        assert_ne!(obligation.id, identical_signal.id);
        assert_eq!(obligation.kind, identical_signal.kind);
        let record = registry.task(task).unwrap();
        let delivery = ObservedStop {
            token: DynamicStop {
                session: SESSION,
                sequence: 10,
                tid: 100,
                task: Some(task),
            },
            task: DynamicTask {
                task,
                process: record.process,
                address_space: record.address_space,
                generation: 0,
            },
            logical_pc: PC,
            registers: registers(PC),
            xstate: vec![0x31; 832],
            signal_mask: 0xa00,
            phase: StopPhase::OriginalSignal,
            signal: Some(info(44, libc::SI_QUEUE)),
        };
        let mut fetch = delivery.clone();
        fetch.token.sequence = 11;
        fetch.logical_pc = HANDLER;
        fetch.registers.rip = HANDLER;
        fetch.registers.rsp = FRAME;
        fetch.registers.rax = 0;
        fetch.registers.rdi = 44;
        fetch.registers.rsi = FRAME + 312;
        fetch.registers.rdx = FRAME + 8;
        fetch.registers.eflags = (fetch.registers.eflags & !0x400) | 0x10000;
        fetch.signal_mask |= (1 << 43) | (1 << 14);
        fetch.phase = StopPhase::OwnedFetch;
        fetch.signal = Some(info(libc::SIGSEGV, 2));
        let mut bytes = vec![0x5a; 1272];
        put(&mut bytes, 152, (-22_i64) as u64);
        put(&mut bytes, 176, PC);
        let frame = Arc::new(FrameFacts {
            id: SignalFrameId {
                session: SESSION,
                serial: 1,
            },
            version: 1,
            address: FRAME,
            bytes,
            original_pc: PC,
            prospective_pc: prospective.then_some(LANDING),
            obligation: obligation.clone(),
        });
        Self {
            delivery,
            fetch,
            frame,
            obligation,
            identical_signal,
        }
    }
    fn census(&self) -> ResumeCensus {
        ResumeCensus::new(SESSION, self.fetch.task.address_space, 0, limits()).unwrap()
    }
    fn current(&self, sequence: u64) -> ObservedStop {
        let mut stop = self.fetch.clone();
        stop.token.sequence = sequence;
        stop.logical_pc = RESTORER;
        stop.registers.rip = RESTORER;
        stop.phase = StopPhase::UserCheckpoint;
        stop.signal = None;
        stop
    }
    fn edited(&self) -> Arc<FrameFacts> {
        let mut frame = (*self.frame).clone();
        frame.version += 1;
        put(&mut frame.bytes, 176, LANDING);
        Arc::new(frame)
    }
    fn returned(&self) -> SignalReturnWitness {
        let mut entry = self.current(20);
        entry.logical_pc = RESTORER + 2;
        entry.registers.rip = RESTORER + 2;
        entry.registers.orig_rax = 15;
        entry.registers.rax = (-libc::ENOSYS as i64) as u64;
        entry.phase = StopPhase::SyscallEntry { syscall: 15 };
        let mut returned = self.delivery.clone();
        returned.token.sequence = 21;
        returned.phase = StopPhase::SignalReturn;
        returned.signal = None;
        let mut bytes = [0_u8; 88];
        bytes[0] = 2;
        bytes[4..8].copy_from_slice(&0xc000_003e_u32.to_ne_bytes());
        put(&mut bytes, 8, PC);
        put(&mut bytes, 16, returned.registers.rsp);
        put(&mut bytes, 24, returned.registers.rax);
        bytes[32] = 1;
        SignalReturnWitness {
            frame: self.frame.id,
            entry,
            expected: returned.clone(),
            returned,
            syscall_bytes: bytes,
            syscall_count: 33,
        }
    }
}

fn unchanged<T: std::fmt::Debug>(
    census: &mut ResumeCensus,
    error: CensusError,
    action: impl FnOnce(&mut ResumeCensus) -> Result<T, CensusError>,
) {
    let before = census.state.clone();
    assert_eq!(action(census).unwrap_err(), error);
    assert_eq!(
        census.state, before,
        "refusal changed origins/history/accounting/reservation"
    );
}
fn record(census: &mut ResumeCensus, token: Reservation, f: &Fixture) {
    census
        .record_delivery(
            token,
            f.frame.id,
            f.obligation.clone(),
            f.delivery.clone(),
            f.fetch.clone(),
        )
        .unwrap();
}
fn pair(census: &mut ResumeCensus, token: Reservation, f: &Fixture) -> (OriginId, OriginId) {
    assert!(f.frame.prospective_pc.is_some());
    let original = census
        .insert_frame(token, Arc::clone(&f.frame), false, f.fetch.clone())
        .unwrap();
    let prospective = census
        .insert_frame(token, Arc::clone(&f.frame), true, f.fetch.clone())
        .unwrap();
    (original, prospective)
}
fn scope() -> ImageScope {
    ImageScope {
        mapping: MappingId(19),
        range: AddressRange::new(0x401000, 0x405000).unwrap(),
    }
}

#[test]
fn exact_frame_roles_stay_distinct_from_current_registers_and_projection() {
    for prospective in [false, true] {
        let f = Fixture::new(prospective);
        let mut c = f.census();
        let token = c.reserve(charge()).unwrap();
        record(&mut c, token, &f);
        let current = c
            .insert(token, OriginKind::CurrentHeldPc, HANDLER, f.fetch.clone())
            .unwrap();
        let original = c
            .insert_frame(token, Arc::clone(&f.frame), false, f.fetch.clone())
            .unwrap();
        if prospective {
            assert_eq!(
                c.check_signal_obligations(std::slice::from_ref(&f.obligation)),
                Err(CensusError::PersistentUnknown)
            );
        }
        let edited = prospective.then(|| {
            c.insert_frame(token, Arc::clone(&f.frame), true, f.fetch.clone())
                .unwrap()
        });
        c.check_signal_obligations(std::slice::from_ref(&f.obligation))
            .unwrap();
        assert_eq!(
            c.active_registers()
                .map(|row| row.row.id)
                .collect::<Vec<_>>(),
            [current]
        );
        assert_eq!(c.active_frames().count(), 1 + usize::from(prospective));
        let projected = c.project(&[scope()]).unwrap();
        assert_eq!(projected.len(), 1);
        let mut expected_origins = vec![current, original];
        let mut expected = BTreeMap::from([
            (HANDLER, BTreeSet::from([ResumeKind::ParkedThread])),
            (PC, BTreeSet::from([ResumeKind::SignalFrame])),
        ]);
        if let Some(edited) = edited {
            expected_origins.push(edited);
            expected.insert(LANDING, BTreeSet::from([ResumeKind::SignalFrame]));
        }
        assert_eq!(projected[0].origins, expected_origins);
        assert_eq!(projected[0].resumes, expected);
        assert_eq!(projected[0].generation, Generation(0));
        c.check_frame_origin(original, &f.fetch, FRAME, &f.frame.bytes)
            .unwrap();
        assert_eq!(c.rows().count(), 2 + usize::from(prospective));
    }
}

#[test]
fn divergent_sibling_frame_bytes_version_address_and_holder_refuse_atomically() {
    for mutation in 0..5 {
        let f = Fixture::new(true);
        let mut c = f.census();
        let token = c.reserve(charge()).unwrap();
        c.insert_frame(token, Arc::clone(&f.frame), false, f.fetch.clone())
            .unwrap();
        let mut frame = (*f.frame).clone();
        let mut holder = f.fetch.clone();
        match mutation {
            0 => frame.bytes[64] ^= 1,
            1 => frame.version += 1,
            2 => frame.address += 64,
            3 => holder.token.sequence += 1,
            4 => holder.registers.r15 ^= 1,
            _ => unreachable!(),
        }
        unchanged(&mut c, CensusError::StaleObservation, |c| {
            c.insert_frame(token, Arc::new(frame), true, holder)
        });
        unchanged(&mut c, CensusError::StaleObservation, |c| {
            c.insert_frame(token, Arc::clone(&f.frame), false, f.fetch.clone())
        });
    }
    let f = Fixture::new(true);
    let mut c = f.census();
    let token = c.reserve(charge()).unwrap();
    record(&mut c, token, &f);
    c.insert_frame(token, Arc::clone(&f.frame), false, f.fetch.clone())
        .unwrap();
    let mut other = (*f.frame).clone();
    other.id.serial += 1;
    c.insert_frame(token, Arc::new(other), true, f.fetch.clone())
        .unwrap();
    // Distinct IDs remain distinct rows. They cannot masquerade as one complete
    // original/prospective pair merely because every other field is equal.
    assert_eq!(c.rows().count(), 2);
    assert_eq!(
        c.check_signal_obligations(&[f.obligation]),
        Err(CensusError::PersistentUnknown)
    );
}

#[test]
fn malformed_frame_fact_id_range_saved_pc_and_obligation_never_insert() {
    let foreign = Fixture::new(true);
    for mutation in 0..16 {
        let f = Fixture::new(true);
        let mut c = f.census();
        let token = c.reserve(charge()).unwrap();
        let mut frame = (*f.frame).clone();
        match mutation {
            0 => frame.id.session += 1,
            1 => frame.id.serial = 0,
            2 => frame.version = 0,
            3 => frame.address = 0,
            4 => frame.address = u64::MAX - 1,
            5 => frame.bytes.clear(),
            6 => frame.bytes.resize(183, 0),
            7 => frame.bytes.resize(MAX_XSTATE_BYTES + 4097, 0),
            8 => put(&mut frame.bytes, 176, PC + 1),
            9 => frame.original_pc = 0,
            10 => frame.prospective_pc = Some(0),
            11 => frame.prospective_pc = Some(PC),
            12 => frame.obligation.task = foreign.fetch.task.task,
            13 => frame.obligation.address_space = foreign.fetch.task.address_space,
            14 => frame.obligation.inherited_from = Some(f.identical_signal.id),
            15 => {
                frame.obligation.kind = ObligationKind::PendingSignal {
                    signal: 44,
                    code: libc::SI_QUEUE,
                    scope: SignalScope::Task,
                }
            }
            _ => unreachable!(),
        }
        unchanged(&mut c, CensusError::InvalidObservation, |c| {
            c.insert_frame(token, Arc::new(frame), false, f.fetch.clone())
        });
    }
}

#[test]
fn live_frame_check_requires_exact_holder_and_every_retained_byte() {
    let f = Fixture::new(true);
    let mut c = f.census();
    let token = c.reserve(charge()).unwrap();
    let (original, _) = pair(&mut c, token, &f);
    for mutation in 0..5 {
        let mut holder = f.fetch.clone();
        let mut bytes = f.frame.bytes.clone();
        let mut address = FRAME;
        match mutation {
            0 => holder.token.sequence += 1,
            1 => holder.registers.r11 ^= 1,
            2 => holder.xstate[160] ^= 1,
            3 => bytes[300] ^= 1,
            4 => address += 1,
            _ => unreachable!(),
        }
        let before = c.state.clone();
        assert_eq!(
            c.check_frame_origin(original, &holder, address, &bytes),
            Err(CensusError::StaleObservation)
        );
        assert_eq!(c.state, before);
    }
    c.check_frame_origin(original, &f.fetch, FRAME, &f.frame.bytes)
        .unwrap();
}

#[test]
fn identical_looking_unknown_signal_ids_and_foreign_obligations_are_not_discharged() {
    let f = Fixture::new(true);
    let foreign = Fixture::new(true);
    let mut c = f.census();
    let token = c.reserve(charge()).unwrap();
    record(&mut c, token, &f);
    pair(&mut c, token, &f);
    let before = c.state.clone();
    for obligations in [
        vec![],
        vec![f.identical_signal.clone()],
        vec![foreign.obligation],
        vec![f.obligation.clone(), f.identical_signal.clone()],
    ] {
        assert_eq!(
            c.check_signal_obligations(&obligations),
            Err(CensusError::PersistentUnknown)
        );
        assert_eq!(c.state, before);
    }
    for mutation in 0..4 {
        let mut wrong = f.obligation.clone();
        match mutation {
            0 => {
                wrong.kind = ObligationKind::PendingSignal {
                    signal: 44,
                    code: libc::SI_QUEUE,
                    scope: SignalScope::Process,
                }
            }
            1 => {
                wrong.kind = ObligationKind::PendingSignal {
                    signal: 45,
                    code: libc::SI_QUEUE,
                    scope: SignalScope::Unknown,
                }
            }
            2 => wrong.inherited_from = Some(f.identical_signal.id),
            3 => {
                wrong.kind = ObligationKind::SavedResume {
                    pc: PC,
                    kind: ResumeKind::SignalFrame,
                }
            }
            _ => unreachable!(),
        }
        assert_eq!(
            c.check_signal_obligations(&[wrong]),
            Err(CensusError::PersistentUnknown)
        );
        assert_eq!(c.state, before);
    }
    c.check_signal_obligations(&[f.obligation]).unwrap();
}

#[test]
fn delivery_requires_actual_model_phase_identity_and_nonreused_record() {
    for mutation in 0..7 {
        let f = Fixture::new(true);
        let mut c = f.census();
        let token = c.reserve(charge()).unwrap();
        let mut frame = f.frame.id;
        let mut obligation = f.obligation.clone();
        let mut delivery = f.delivery.clone();
        let mut fetch = f.fetch.clone();
        match mutation {
            0 => frame.session += 1,
            1 => frame.serial = 0,
            2 => {
                obligation.kind = ObligationKind::PendingSignal {
                    signal: 44,
                    code: 0,
                    scope: SignalScope::Unknown,
                }
            }
            3 => obligation.inherited_from = Some(f.identical_signal.id),
            4 => delivery.phase = StopPhase::Interrupted,
            5 => fetch.phase = StopPhase::UserCheckpoint,
            6 => fetch.token.sequence = delivery.token.sequence,
            _ => unreachable!(),
        }
        unchanged(&mut c, CensusError::InvalidConsumption, |c| {
            c.record_delivery(token, frame, obligation, delivery, fetch)
        });
    }
    let f = Fixture::new(true);
    let mut c = f.census();
    let token = c.reserve(charge()).unwrap();
    record(&mut c, token, &f);
    unchanged(&mut c, CensusError::InvalidConsumption, |c| {
        c.record_delivery(
            token,
            f.frame.id,
            f.obligation.clone(),
            f.delivery.clone(),
            f.fetch.clone(),
        )
    });
    let mut different = f.frame.id;
    different.serial += 1;
    unchanged(&mut c, CensusError::InvalidConsumption, |c| {
        c.record_delivery(
            token,
            different,
            f.obligation.clone(),
            f.delivery.clone(),
            f.fetch.clone(),
        )
    });
}

#[test]
fn delivery_history_is_bound_to_this_census_session_space_and_generation() {
    let foreign = Fixture::new(true);
    for mutation in 0..3 {
        let f = Fixture::new(true);
        let mut c = f.census();
        let token = c.reserve(charge()).unwrap();
        let mut delivery = f.delivery.clone();
        let mut fetch = f.fetch.clone();
        let expected = match mutation {
            0 => {
                delivery.token.session += 1;
                fetch.token.session += 1;
                CensusError::IdentityMismatch
            }
            1 => {
                delivery.task.address_space = foreign.fetch.task.address_space;
                fetch.task.address_space = foreign.fetch.task.address_space;
                CensusError::IdentityMismatch
            }
            2 => {
                delivery.task.generation = 1;
                fetch.task.generation = 1;
                CensusError::StaleObservation
            }
            _ => unreachable!(),
        };
        unchanged(&mut c, expected, |c| {
            c.record_delivery(token, f.frame.id, f.obligation.clone(), delivery, fetch)
        });
    }
}

#[test]
fn active_and_retired_frame_rows_cannot_pass_without_their_delivery_inventory() {
    for retired in [false, true] {
        let f = Fixture::new(true);
        let mut c = f.census();
        let token = c.reserve(charge()).unwrap();
        c.check_signal_obligations(&[]).unwrap();
        let (original, prospective) = pair(&mut c, token, &f);
        if retired {
            let witness = f.returned();
            c.consume_frame(token, original, witness.clone()).unwrap();
            c.consume_frame(token, prospective, witness).unwrap();
        }
        let before = c.state.clone();
        assert_eq!(
            c.check_signal_obligations(&[]),
            Err(CensusError::PersistentUnknown)
        );
        assert_eq!(
            c.check_signal_obligations(std::slice::from_ref(&f.obligation)),
            Err(CensusError::PersistentUnknown)
        );
        assert_eq!(c.state, before);
        // Supplying the real model delivery record closes this missing-fact
        // boundary; no frame row or completed-return history is deleted.
        record(&mut c, token, &f);
        c.check_signal_obligations(std::slice::from_ref(&f.obligation))
            .unwrap();
        assert_eq!(c.rows().count(), 2);
        assert_eq!(c.active_frames().count(), if retired { 0 } else { 2 });
        assert_eq!(
            &c.history()[..before.history.len()],
            before.history.as_slice()
        );
        assert_eq!(
            c.check_signal_obligations(&[]),
            Err(CensusError::PersistentUnknown)
        );
    }
}

#[test]
fn generic_origin_paths_cannot_insert_refresh_consume_or_retire_saved_frames() {
    let f = Fixture::new(true);
    let mut c = f.census();
    let token = c.reserve(charge()).unwrap();
    unchanged(&mut c, CensusError::WrongOriginPhase, |c| {
        c.insert(
            token,
            OriginKind::SignalFrame {
                frame: f.frame.id,
                prospective: false,
            },
            PC,
            f.fetch.clone(),
        )
    });
    for observed in [f.delivery.clone(), f.returned().returned] {
        unchanged(&mut c, CensusError::WrongOriginPhase, |c| {
            c.insert(
                token,
                OriginKind::CurrentHeldPc,
                observed.logical_pc,
                observed,
            )
        });
    }
    let (original, _) = pair(&mut c, token, &f);
    unchanged(&mut c, CensusError::PersistentUnknown, |c| {
        c.refresh_same_pc(token, original, f.fetch.clone())
    });
    assert_eq!(
        c.check_current_origin(original, &f.fetch),
        Err(CensusError::PersistentUnknown)
    );
    let successor = f.current(12);
    let execution = ExecutionId::from_owner(SESSION, 1).unwrap();
    let evidence =
        OwnerConsumption::original_progress(execution, f.fetch.clone(), vec![0x90], successor)
            .unwrap();
    unchanged(&mut c, CensusError::PersistentUnknown, |c| {
        c.consume(token, original, evidence)
    });
    let terminal = OwnerTerminal::from_owner(
        f.fetch.clone(),
        ObservedTerminal {
            session: SESSION,
            task: f.fetch.task,
            tid: 100,
            sequence: 30,
            wait_status: 0,
            pidfd_events: libc::POLLIN | libc::POLLHUP,
        },
    )
    .unwrap();
    unchanged(&mut c, CensusError::PersistentUnknown, |c| {
        c.retire_terminal(token, original, terminal)
    });
    assert_eq!(c.active_frames().count(), 2);
}

#[test]
fn explicit_signal_current_origins_require_their_own_phase_and_do_not_merge_frames() {
    let f = Fixture::new(true);
    let mut c = f.census();
    let token = c.reserve(charge()).unwrap();
    unchanged(&mut c, CensusError::WrongOriginPhase, |c| {
        c.insert_signal_current(token, f.fetch.clone())
    });
    let delivery = c.insert_signal_current(token, f.delivery.clone()).unwrap();
    let returned = c
        .insert_signal_current(token, f.returned().returned)
        .unwrap();
    assert_ne!(delivery, returned);
    assert_eq!(c.active_registers().count(), 2);
    assert_eq!(c.active_frames().count(), 0);
    let projection = c.project(&[scope()]).unwrap();
    assert_eq!(projection[0].origins, [delivery, returned]);
    assert_eq!(
        projection[0].resumes,
        BTreeMap::from([(PC, BTreeSet::from([ResumeKind::ParkedThread]))])
    );
}

#[test]
fn frame_versions_and_generation_rebind_keep_full_immutable_history_and_roles() {
    let f = Fixture::new(true);
    let mut c = f.census();
    let token = c.reserve(charge()).unwrap();
    record(&mut c, token, &f);
    let (original, prospective) = pair(&mut c, token, &f);
    let initial = c.rows().cloned().collect::<Vec<_>>();
    let history = c.history().to_vec();
    let charged = c.charged();
    let used = c.used();
    let edited = f.edited();
    let holder = f.current(12);
    c.refresh_frame(token, original, Arc::clone(&edited), holder.clone())
        .unwrap();
    assert_eq!(
        c.check_signal_obligations(std::slice::from_ref(&f.obligation)),
        Err(CensusError::StaleObservation)
    );
    c.refresh_frame(token, prospective, Arc::clone(&edited), holder.clone())
        .unwrap();
    c.check_signal_obligations(std::slice::from_ref(&f.obligation))
        .unwrap();
    assert_eq!(c.rows().cloned().collect::<Vec<_>>(), initial);
    assert_eq!(&c.history()[..history.len()], history.as_slice());
    for row in &c.history()[history.len()..] {
        let HistoryRecord::SignalFrameRefreshed(refresh) = row else {
            panic!("expected retained frame refresh")
        };
        assert_eq!(refresh.before, f.fetch);
        assert_eq!(refresh.after, holder);
        assert_eq!(refresh.before_frame, f.frame);
        assert_eq!(refresh.after_frame, edited);
    }
    assert_eq!(c.charged(), charged);
    assert_eq!(c.used().witnesses, used.witnesses + 2);
    assert!(c.used().source_fact_bytes > used.source_fact_bytes + 2 * f.frame.bytes.len());
    c.rebind_epoch(token, 1).unwrap();
    let mut rebound = holder.clone();
    rebound.task.generation = 1;
    c.refresh_frame(token, original, Arc::clone(&edited), rebound.clone())
        .unwrap();
    assert_eq!(
        c.check_signal_obligations(std::slice::from_ref(&f.obligation)),
        Err(CensusError::StaleObservation)
    );
    c.refresh_frame(token, prospective, Arc::clone(&edited), rebound.clone())
        .unwrap();
    c.check_signal_obligations(&[f.obligation]).unwrap();
    assert_eq!(c.rows().cloned().collect::<Vec<_>>(), initial);
    assert_eq!(
        c.active_frames()
            .map(|(_, facts)| facts.version)
            .collect::<Vec<_>>(),
        [2, 2]
    );
    let projection = c.project(&[scope()]).unwrap();
    assert_eq!(projection[0].generation, Generation(1));
    assert_eq!(
        projection[0].resumes.keys().copied().collect::<Vec<_>>(),
        [PC, LANDING]
    );
}

#[test]
fn frame_refresh_cannot_hide_changed_bytes_under_old_or_skipped_versions() {
    for mutation in 0..7 {
        let f = Fixture::new(true);
        let mut c = f.census();
        let token = c.reserve(charge()).unwrap();
        let (original, _) = pair(&mut c, token, &f);
        let mut frame = (*f.frame).clone();
        let mut holder = f.current(12);
        match mutation {
            0 => frame.bytes[64] ^= 1,
            1 => frame.version += 1,
            2 => {
                frame.bytes[64] ^= 1;
                frame.version += 2;
            }
            3 => frame.address += 64,
            4 => {
                frame.bytes.push(0);
                frame.version += 1;
            }
            5 => holder.token.sequence = f.fetch.token.sequence,
            6 => holder.task.generation = 1,
            _ => unreachable!(),
        }
        unchanged(&mut c, CensusError::StaleObservation, |c| {
            c.refresh_frame(token, original, Arc::new(frame), holder)
        });
    }
    let f = Fixture::new(true);
    let mut c = f.census();
    let token = c.reserve(charge()).unwrap();
    let (original, _) = pair(&mut c, token, &f);
    c.finish_reservation(token).unwrap();
    unchanged(&mut c, CensusError::StaleReservation, |c| {
        c.refresh_frame(token, original, Arc::clone(&f.frame), f.fetch.clone())
    });
}

#[test]
fn frame_holder_xstate_growth_and_shrink_retain_every_copy_without_refund() {
    let f = Fixture::new(true);
    let mut c = f.census();
    let token = c.reserve(charge()).unwrap();
    record(&mut c, token, &f);
    let (original, prospective) = pair(&mut c, token, &f);
    let initial = c.rows().cloned().collect::<Vec<_>>();
    let charged = c.charged();
    let initial_used = c.used();
    let history = c.history().to_vec();
    let mut grown = f.current(12);
    grown.xstate.resize(1664, 0x62);
    for id in [original, prospective] {
        let before = c.used();
        c.refresh_frame(token, id, Arc::clone(&f.frame), grown.clone())
            .unwrap();
        let delta = c.used().source_fact_bytes - before.source_fact_bytes;
        assert!(
            delta > 832 + 1664 + 832 + f.frame.bytes.len(),
            "old/new history, positive current growth and frame payload must all be charged"
        );
    }
    c.check_signal_obligations(std::slice::from_ref(&f.obligation))
        .unwrap();
    let grown_used = c.used();
    let mut shrunk = grown.clone();
    shrunk.token.sequence += 1;
    shrunk.xstate.truncate(832);
    for id in [original, prospective] {
        let before = c.used();
        c.refresh_frame(token, id, Arc::clone(&f.frame), shrunk.clone())
            .unwrap();
        assert!(
            c.used().source_fact_bytes
                > before.source_fact_bytes + 1664 + 832 + f.frame.bytes.len()
        );
    }
    c.check_signal_obligations(&[f.obligation]).unwrap();
    assert_eq!(c.charged(), charged);
    assert!(grown_used.source_fact_bytes > initial_used.source_fact_bytes);
    assert!(c.used().source_fact_bytes > grown_used.source_fact_bytes);
    assert_eq!(c.rows().cloned().collect::<Vec<_>>(), initial);
    assert_eq!(&c.history()[..history.len()], history.as_slice());
    for (index, row) in c.history()[history.len()..].iter().enumerate() {
        let HistoryRecord::SignalFrameRefreshed(refresh) = row else {
            panic!("expected XSTATE frame refresh")
        };
        if index < 2 {
            assert_eq!(refresh.before, f.fetch);
            assert_eq!(refresh.after, grown);
        } else {
            assert_eq!(refresh.before, grown);
            assert_eq!(refresh.after, shrunk);
        }
        assert_eq!(refresh.before_frame, f.frame);
        assert_eq!(refresh.after_frame, f.frame);
    }
}

#[test]
fn partial_actual_return_never_resolves_the_frame_and_complete_return_keeps_history() {
    let f = Fixture::new(true);
    let mut c = f.census();
    let token = c.reserve(charge()).unwrap();
    record(&mut c, token, &f);
    let (original, prospective) = pair(&mut c, token, &f);
    let persistent = c
        .insert(
            token,
            OriginKind::UnknownPersistent {
                kind: ResumeKind::NonlocalJump,
            },
            PC,
            f.fetch.clone(),
        )
        .unwrap();
    let initial = c.rows().cloned().collect::<Vec<_>>();
    let before = c.history().to_vec();
    let charged = c.charged();
    let witness = f.returned();
    c.consume_frame(token, original, witness.clone()).unwrap();
    assert_eq!(
        c.check_signal_obligations(std::slice::from_ref(&f.obligation)),
        Err(CensusError::StaleObservation)
    );
    assert_eq!(c.active_frames().count(), 1);
    c.consume_frame(token, prospective, witness.clone())
        .unwrap();
    c.check_signal_obligations(std::slice::from_ref(&f.obligation))
        .unwrap();
    assert_eq!(
        c.check_signal_obligations(&[]),
        Err(CensusError::PersistentUnknown)
    );
    assert_eq!(c.active_frames().count(), 0);
    assert_eq!(
        c.active().map(|row| row.row.id).collect::<Vec<_>>(),
        [persistent]
    );
    assert_eq!(c.rows().cloned().collect::<Vec<_>>(), initial);
    assert_eq!(c.charged(), charged);
    assert_eq!(&c.history()[..before.len()], before.as_slice());
    for row in &c.history()[before.len()..] {
        let HistoryRecord::SignalFrameReturned(retired) = row else {
            panic!("expected retained signal return")
        };
        assert_eq!(retired.frame, f.frame);
        assert_eq!(retired.before, f.fetch);
        assert_eq!(retired.witness, witness);
    }
    assert_eq!(
        c.project(&[scope()]).unwrap()[0].resumes,
        BTreeMap::from([(PC, BTreeSet::from([ResumeKind::NonlocalJump]))])
    );
    unchanged(&mut c, CensusError::InactiveOrigin, |c| {
        c.consume_frame(token, original, witness)
    });
    unchanged(&mut c, CensusError::StaleObservation, |c| {
        c.insert_frame(token, Arc::clone(&f.frame), false, f.fetch.clone())
    });
}

#[test]
fn return_requires_full_state_actual_phase_and_exact_syscall_information() {
    for mutation in 0..14 {
        let f = Fixture::new(true);
        let mut c = f.census();
        let token = c.reserve(charge()).unwrap();
        let (original, _) = pair(&mut c, token, &f);
        let mut witness = f.returned();
        match mutation {
            0 => witness.frame.serial += 1,
            1 => witness.expected.registers.r11 ^= 1,
            2 => witness.expected.xstate[160] ^= 1,
            3 => witness.expected.signal_mask ^= 1,
            4 => witness.entry.phase = StopPhase::UserCheckpoint,
            5 => witness.returned.phase = StopPhase::UserCheckpoint,
            6 => witness.entry.token.sequence = f.fetch.token.sequence,
            7 => witness.syscall_count = 32,
            8 => witness.syscall_count = 89,
            9 => witness.syscall_bytes[0] = 1,
            10 => witness.syscall_bytes[4] ^= 1,
            11 => witness.syscall_bytes[8] ^= 1,
            12 => witness.syscall_bytes[24] ^= 1,
            13 => witness.syscall_bytes[32] = 2,
            _ => unreachable!(),
        }
        unchanged(&mut c, CensusError::InvalidConsumption, |c| {
            c.consume_frame(token, original, witness)
        });
    }
}

#[derive(Clone, Copy, Debug)]
enum Operation {
    Insert,
    Delivery,
    Refresh,
    Return,
}
fn prepared(f: &Fixture, operation: Operation) -> (ResumeCensus, Option<OriginId>) {
    let mut c = f.census();
    let id = if matches!(operation, Operation::Refresh | Operation::Return) {
        let token = c.reserve(charge()).unwrap();
        record(&mut c, token, f);
        let (id, _) = pair(&mut c, token, f);
        c.finish_reservation(token).unwrap();
        Some(id)
    } else {
        None
    };
    (c, id)
}
fn apply(
    operation: Operation,
    f: &Fixture,
    c: &mut ResumeCensus,
    token: Reservation,
    id: Option<OriginId>,
) -> Result<(), CensusError> {
    match operation {
        Operation::Insert => c
            .insert_frame(token, Arc::clone(&f.frame), false, f.fetch.clone())
            .map(|_| ()),
        Operation::Delivery => c.record_delivery(
            token,
            f.frame.id,
            f.obligation.clone(),
            f.delivery.clone(),
            f.fetch.clone(),
        ),
        Operation::Refresh => c.refresh_frame(token, id.unwrap(), f.edited(), f.current(12)),
        Operation::Return => c.consume_frame(token, id.unwrap(), f.returned()),
    }
}

#[test]
fn one_byte_short_reservations_refuse_before_each_signal_history_mutation() {
    for operation in [
        Operation::Insert,
        Operation::Delivery,
        Operation::Refresh,
        Operation::Return,
    ] {
        let f = Fixture::new(true);
        let (mut control, id) = prepared(&f, operation);
        let token = control.reserve(charge()).unwrap();
        let used = control.used();
        apply(operation, &f, &mut control, token, id).unwrap();
        let after = control.used();
        let bytes = after.source_fact_bytes - used.source_fact_bytes;
        // An independently checked positive payload floor prevents a zero-cost
        // implementation from making the measured one-byte-short case vacuous.
        let minimum = match operation {
            Operation::Insert | Operation::Refresh => 2 * 832 + f.frame.bytes.len(),
            Operation::Delivery => 2 * 832,
            Operation::Return => 4 * 832,
        };
        assert!(
            bytes > minimum,
            "{operation:?} did not charge complete retained payloads"
        );
        let exact = BudgetCharge {
            source_fact_bytes: bytes,
            origins: after.origins - used.origins,
            witnesses: after.witnesses - used.witnesses,
            ..BudgetCharge::default()
        };
        let (mut c, id) = prepared(&f, operation);
        let short = c
            .reserve(BudgetCharge {
                source_fact_bytes: bytes - 1,
                ..exact
            })
            .unwrap();
        unchanged(&mut c, CensusError::ReservationExhausted, |c| {
            apply(operation, &f, c, short, id)
        });
        let unused = c.charged();
        let before_used = c.used();
        c.finish_reservation(short).unwrap();
        assert_eq!(c.charged(), unused);
        assert_eq!(c.used(), before_used);
        let enough = c.reserve(exact).unwrap();
        apply(operation, &f, &mut c, enough, id).unwrap();
        assert_eq!(
            c.used().source_fact_bytes,
            before_used.source_fact_bytes + bytes
        );
        assert_eq!(
            c.charged().source_fact_bytes,
            unused.source_fact_bytes + bytes
        );
    }
}

#[test]
fn exhausted_lifetime_and_serial_capacity_do_not_refund_or_insert_frame_rows() {
    let f = Fixture::new(true);
    let mut c = f.census();
    let token = c
        .reserve(BudgetCharge {
            source_fact_bytes: limits().source_fact_bytes,
            ..BudgetCharge::default()
        })
        .unwrap();
    let used = c.used();
    let charged = c.charged();
    c.finish_reservation(token).unwrap();
    assert_eq!(c.used(), used);
    assert_eq!(c.charged(), charged);
    unchanged(&mut c, CensusError::Capacity, |c| {
        c.reserve(BudgetCharge {
            source_fact_bytes: 1,
            ..BudgetCharge::default()
        })
    });
    let mut c = f.census();
    let token = c.reserve(charge()).unwrap();
    c.state.next_serial = u64::MAX;
    unchanged(&mut c, CensusError::Capacity, |c| {
        c.insert_frame(token, Arc::clone(&f.frame), false, f.fetch.clone())
    });
}
