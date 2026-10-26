//! Synthetic bookkeeping only. No OwnedInstructionCompletion is constructed;
//! private model views cannot reach the production consuming entry point.
use super::super::super::super::trusted::{AdmissionStop, OwnedSignal};
use super::super::super::runtime_instruction::{DebugDisposition, classify};
use super::*;
use crate::lifecycle::LifecycleRegistry;
use crate::linux::remote::SignalStop;
use crate::selected::SyscallAliases;
use liteinst_admission::scan::{Boundary, Snapshot, WriteControl};
use liteinst2::contracts::SourceIdentity;
use std::time::Duration;

const PC: u64 = 0x401000;
const SESSION: u64 = 91;
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
fn before() -> ObservedStop {
    let registry = LifecycleRegistry::new(crate::lifecycle::Limits::default(), 101, PC).unwrap();
    let task = registry.task(registry.root_task()).unwrap();
    ObservedStop {
        token: DynamicStop {
            session: SESSION,
            sequence: 10,
            tid: 101,
            task: Some(task.id),
        },
        task: DynamicTask {
            task: task.id,
            process: task.process,
            address_space: task.address_space,
            generation: 0,
        },
        logical_pc: PC,
        registers: RegisterSnapshot {
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
            rip: PC,
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
        },
        xstate: vec![0x5a; 832],
        signal_mask: 0x200,
        phase: StopPhase::UserCheckpoint,
        signal: None,
    }
}
fn source() -> SourceRecord {
    SourceRecord {
        identity: CodeIdentity {
            source: SourceIdentity([0x31; 32]),
            mapping: 17,
            generation: 0,
        },
        index: 2,
    }
}
fn seeded() -> (ResumeCensus, OriginId) {
    let before = before();
    let mut census = ResumeCensus::new(SESSION, before.task.address_space, 0, limits()).unwrap();
    let charge = super::super::runtime::initial_runtime_origin_charge(MAX_XSTATE_BYTES).unwrap();
    let reserve = census.reserve(charge).unwrap();
    let origin = census
        .insert(reserve, OriginKind::CurrentHeldPc, PC, before)
        .unwrap();
    census.finish_reservation(reserve).unwrap();
    (census, origin)
}
#[derive(Clone)]
struct Fixture {
    source: SourceRecord,
    origin: OriginId,
    execution: ExecutionId,
    until: Instant,
    encoding: Vec<u8>,
    stops: [AdmissionStop; 8],
    states: [TaskStateSnapshot; 8],
    trace: NativeTrace,
}
impl Fixture {
    fn new(prepared: &PreparedOrdinaryCensus, same_pc: bool) -> Self {
        let b = &prepared.before;
        let state = TaskStateSnapshot {
            registers: b.registers,
            xstate: b.xstate.clone(),
            mask: b.signal_mask,
        };
        let mut states = std::array::from_fn(|_| state.clone());
        for value in &mut states[4..] {
            if !same_pc {
                value.registers.rip = PC + 4;
                value.registers.rax = 6;
                value.registers.eflags = 0x206;
            }
        }
        let mut raw = [0; 128];
        raw[..4].copy_from_slice(&libc::SIGTRAP.to_ne_bytes());
        raw[8..12].copy_from_slice(&libc::TRAP_TRACE.to_ne_bytes());
        raw[16..24].copy_from_slice(&states[4].registers.rip.to_ne_bytes());
        let stops = std::array::from_fn(|index| {
            let mut token = b.token.clone();
            token.sequence += index as u64;
            AdmissionStop {
                token,
                identity: b.task,
                phase: if index == 0 {
                    AdmissionPhase::EntryReady
                } else if index == 4 {
                    AdmissionPhase::NativeCompleted
                } else {
                    AdmissionPhase::Restored
                },
                signal: None,
            }
        });
        Self {
            source: prepared.binding.source,
            origin: prepared.binding.origin,
            execution: prepared.binding.execution,
            until: prepared.binding.until,
            encoding: prepared.binding.encoding.bytes().to_vec(),
            stops,
            states,
            trace: NativeTrace {
                ordinal: 3,
                tid: 101,
                status: (libc::SIGTRAP << 8) | 0x7f,
                signal: raw,
                dr6: TRACE_DR6,
            },
        }
    }
    fn checkpoint(&self, index: usize) -> NativeCheckpoint<'_> {
        NativeCheckpoint {
            stop: &self.stops[index],
            state: &self.states[index],
        }
    }
    fn view(&self) -> CompletionModel<'_> {
        CompletionModel {
            source: self.source,
            origin: self.origin,
            execution: self.execution,
            until: self.until,
            encoding: &self.encoding,
            logical: self.checkpoint(0),
            opening: std::array::from_fn(|i| self.checkpoint(i + 1)),
            step: self.checkpoint(4),
            closing: std::array::from_fn(|i| self.checkpoint(i + 5)),
            trace: self.trace,
        }
    }
}
fn owned_signal(actual: &Fixture) -> OwnedSignal {
    OwnedSignal {
        raw: actual.trace.signal,
        view: SignalStop {
            signal: libc::SIGTRAP,
            code: libc::TRAP_TRACE,
            address: Some(actual.states[4].registers.rip),
            instruction_pointer: actual.states[4].registers.rip,
            pid: actual.trace.tid,
            sequence: actual.stops[4].token.sequence,
        },
    }
}
struct Case {
    census: ResumeCensus,
    reservation: Reservation,
    prepared: PreparedOrdinaryCensus,
    actual: Fixture,
}
impl Case {
    fn new(same_pc: bool) -> Self {
        let (mut census, origin) = seeded();
        let reservation = census.reserve(ordinary_census_charge().unwrap()).unwrap();
        let bytes: &[u8] = if same_pc {
            &[0xeb, 0xfe]
        } else {
            &[0x48, 0x83, 0xc0, 1]
        };
        let prepared = census
            .prepare_model(
                reservation,
                origin,
                ExecutionId::from_owner(SESSION, 1).unwrap(),
                source(),
                Encoding::new(PC, bytes).unwrap(),
                Instant::now() + Duration::from_secs(60),
            )
            .unwrap();
        let actual = Fixture::new(&prepared, same_pc);
        Self {
            census,
            reservation,
            prepared,
            actual,
        }
    }
    fn reject(&mut self, expected: CensusError) {
        let state = self.census.state.clone();
        let before = self.prepared.before.clone();
        let buffers = self
            .prepared
            .buffers
            .iter()
            .map(|v| (v.as_ptr(), v.len(), v.capacity()))
            .collect::<Vec<_>>();
        let record = self.prepared.evidence.clone();
        assert_eq!(
            self.census
                .commit_model(self.reservation, &self.actual.view(), &mut self.prepared)
                .unwrap_err(),
            expected
        );
        assert_eq!(self.census.state, state);
        assert_eq!(self.prepared.before, before);
        assert_eq!(
            self.prepared
                .buffers
                .iter()
                .map(|v| (v.as_ptr(), v.len(), v.capacity()))
                .collect::<Vec<_>>(),
            buffers
        );
        assert_eq!(self.prepared.evidence, record);
        assert!(!self.prepared.committed);
    }
    fn commit(&mut self) -> OriginId {
        self.census
            .commit_model(self.reservation, &self.actual.view(), &mut self.prepared)
            .unwrap()
            .current
    }
}

#[test]
fn ordinary_fixed_schedule_prepays_six_refreshes_and_full_sixteen_states() {
    let charge = ordinary_census_charge().unwrap();
    assert_eq!(
        (
            charge.epochs,
            charge.reports,
            charge.plan_history,
            charge.origins,
            charge.witnesses
        ),
        (0, 0, 0, 1, 7)
    );
    let fixed = 16 * size_of::<ObservedStop>()
        + 6 * size_of::<HistoryRecord>()
        + size_of::<OwnerConsumption>()
        + size_of::<StoredOrigin>();
    assert_eq!(
        charge.source_fact_bytes,
        16 * 65536 + size_of::<PreparedOrdinaryCensus>() + size_of::<OrdinaryEvidence>() + fixed
    );
    let case = Case::new(false);
    assert_eq!(
        case.prepared.allocated_bytes().unwrap(),
        16 * 65536 + size_of::<PreparedOrdinaryCensus>() + size_of::<OrdinaryEvidence>()
    );
    assert_eq!(
        case.prepared.preparation_debit,
        case.prepared.allocated_bytes().unwrap()
    );
    assert_eq!(
        case.prepared.remaining_charge().unwrap(),
        BudgetCharge {
            origins: 1,
            witnesses: 7,
            source_fact_bytes: fixed,
            ..BudgetCharge::default()
        }
    );
    assert_eq!(case.census.history().len(), 0);
    assert_eq!(case.census.active().count(), 1);
}

#[test]
fn ordinary_current_borrow_requires_exact_active_register_origin_and_generation() {
    let mut case = Case::new(false);
    let id = case.prepared.binding.origin;
    assert!(std::ptr::eq(
        case.census.current_observation(id).unwrap(),
        &case.census.state.origins[0].current
    ));
    let mut foreign = id;
    foreign.census += 1;
    assert_eq!(
        case.census.current_observation(foreign).unwrap_err(),
        CensusError::UnknownOrigin
    );
    case.census.state.origins[0].current.task.generation = 1;
    assert_eq!(
        case.census.current_observation(id).unwrap_err(),
        CensusError::StaleObservation
    );
    case.census.state.origins[0].current.task.generation = 0;
    case.census.state.origins[0].row.kind = OriginKind::ParentSyscallReturn { syscall: 39 };
    assert_eq!(
        case.census.current_observation(id).unwrap_err(),
        CensusError::WrongOriginPhase
    );
    case.census.state.origins[0].active = false;
    assert_eq!(
        case.census.current_observation(id).unwrap_err(),
        CensusError::InactiveOrigin
    );
}

#[test]
fn ordinary_completed_same_pc_is_distinct_from_unchanged_generic_progress() {
    let mut case = Case::new(true);
    let mut guessed = case.prepared.before.clone();
    guessed.token.sequence += 4;
    assert_eq!(
        OwnerConsumption::original_progress(
            case.actual.execution,
            case.prepared.before.clone(),
            vec![0xeb, 0xfe],
            guessed
        )
        .unwrap_err(),
        CensusError::InvalidConsumption
    );
    let mut observed_trace = case.prepared.before.clone();
    observed_trace.token = case.actual.stops[4].token.clone();
    observed_trace.phase = StopPhase::OwnedOrdinaryComplete {
        execution: case.actual.execution,
    };
    observed_trace.signal = Some(DynamicSignalInfo {
        raw: case.actual.trace.signal,
    });
    let unchanged = case.census.state.clone();
    assert_eq!(
        case.census
            .insert(
                case.reservation,
                OriginKind::CurrentHeldPc,
                PC,
                observed_trace
            )
            .unwrap_err(),
        CensusError::WrongOriginPhase
    );
    assert_eq!(case.census.state, unchanged);
    let old = case.prepared.binding.origin;
    let current = case.commit();
    assert_ne!(current, old);
    assert_eq!(
        case.census.current_observation(old).unwrap_err(),
        CensusError::InactiveOrigin
    );
    let observed = case.census.current_observation(current).unwrap();
    assert_eq!(observed.logical_pc, PC);
    assert_eq!(observed.token, case.actual.stops[7].token);
    assert_eq!(observed.registers, case.actual.states[4].registers);
    assert_eq!(observed.phase, StopPhase::UserCheckpoint);
    assert!(observed.signal.is_none());
    assert_eq!(case.census.generation(), 0);
    assert_eq!(case.census.history().len(), 7);
}

#[test]
fn ordinary_history_keeps_every_full_before_step_and_closed_observation() {
    let mut case = Case::new(false);
    let old_initial = case.census.state.origins[0].row.initial.clone();
    let old = case.prepared.binding.origin;
    let current = case.commit();
    assert_eq!(case.census.state.origins[0].row.initial, old_initial);
    assert_eq!(
        case.census.state.origins[0].current.token,
        case.actual.stops[3].token
    );
    for (index, record) in case.census.history().iter().enumerate() {
        if index == 3 {
            let HistoryRecord::Consumed { origin, evidence } = record else {
                panic!("missing consumption")
            };
            assert_eq!(*origin, old);
            assert_eq!(evidence.before.token, case.actual.stops[3].token);
            assert_eq!(evidence.successor.token, case.actual.stops[4].token);
            assert!(same_architecture(&evidence.before, &case.actual.states[3]));
            assert!(same_architecture(
                &evidence.successor,
                &case.actual.states[4]
            ));
            assert_eq!(
                evidence.successor.phase,
                StopPhase::OwnedOrdinaryComplete {
                    execution: case.actual.execution
                }
            );
            assert_eq!(
                evidence.successor.signal.as_ref().unwrap().raw,
                case.actual.trace.signal
            );
            let Consumption::OwnedOrdinary(records) = &evidence.evidence else {
                panic!("wrong evidence kind")
            };
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].trace, Some(case.actual.trace));
            assert_eq!(records[0].binding.encoding.bytes(), case.actual.encoding);
        } else {
            let HistoryRecord::Refreshed {
                origin,
                before,
                after,
            } = record
            else {
                panic!("missing refresh")
            };
            assert_eq!(*origin, if index < 3 { old } else { current });
            assert_eq!(before.token, case.actual.stops[index].token);
            assert_eq!(after.token, case.actual.stops[index + 1].token);
            assert!(same_architecture(before, &case.actual.states[index]));
            assert!(same_architecture(after, &case.actual.states[index + 1]));
        }
    }
    let row = &case.census.state.origins[1];
    assert_eq!(row.row.initial.token, case.actual.stops[4].token);
    assert_eq!(row.current.token, case.actual.stops[7].token);
    assert_eq!(row.row.pc, PC + 4);
    assert_eq!(row.row.created_generation, 0);
}

#[test]
fn ordinary_rejects_foreign_source_execution_origin_encoding_and_deadline_atomically() {
    for kind in 0..9 {
        let mut case = Case::new(false);
        match kind {
            0 => case.actual.source.identity.source.0[0] ^= 1,
            1 => case.actual.source.identity.mapping += 1,
            2 => case.actual.source.identity.generation += 1,
            3 => case.actual.source.index += 1,
            4 => case.actual.execution.serial += 1,
            5 => case.actual.execution.session += 1,
            6 => case.actual.origin.serial += 1,
            7 => case.actual.encoding[3] ^= 1,
            8 => case.actual.until += Duration::from_millis(1),
            _ => unreachable!(),
        }
        case.reject(CensusError::IdentityMismatch);
    }
}

#[test]
fn ordinary_final_row_corruptions_cannot_partially_consume_old_origin() {
    for kind in 0..15 {
        let mut case = Case::new(false);
        let foreign = before().task;
        match kind {
            0 => case.actual.states[7].registers.rax ^= 1,
            1 => case.actual.states[7].registers.eflags ^= 1,
            2 => case.actual.states[7].xstate[400] ^= 1,
            3 => case.actual.states[7].mask ^= 1,
            4 => case.actual.states[7].registers.rip += 1,
            5 => case.actual.stops[7].token.task = None,
            6 => case.actual.stops[7].identity.generation += 1,
            7 => case.actual.stops[7].token.sequence = case.actual.stops[6].token.sequence,
            8 => case.actual.stops[7].phase = AdmissionPhase::Fetch,
            9 => case.actual.stops[7].signal = Some(owned_signal(&case.actual)),
            10 => {
                case.actual.states[7].xstate.pop();
            }
            11 => case.actual.stops[7].identity.task = foreign.task,
            12 => case.actual.stops[7].identity.process = foreign.process,
            13 => case.actual.stops[7].identity.address_space = foreign.address_space,
            14 => case.actual.stops[7].token.session += 1,
            _ => unreachable!(),
        }
        case.reject(CensusError::InvalidConsumption);
    }
}

#[test]
fn ordinary_each_actual_chain_row_requires_its_genuine_phase_and_newer_token() {
    for index in 1..8 {
        let mut case = Case::new(false);
        case.actual.stops[index].token.sequence = case.actual.stops[index - 1].token.sequence;
        case.reject(CensusError::InvalidConsumption);
        let mut case = Case::new(false);
        case.actual.stops[index].phase = AdmissionPhase::Guard;
        case.reject(CensusError::InvalidConsumption);
        let mut case = Case::new(false);
        case.actual.stops[index].token.tid += 1;
        case.reject(CensusError::InvalidConsumption);
    }
    let mut case = Case::new(false);
    case.actual.stops[0].token.sequence += 1;
    case.reject(CensusError::InvalidConsumption);
    for index in 0..8 {
        let mut case = Case::new(false);
        case.actual.stops[index].signal = Some(owned_signal(&case.actual));
        case.reject(CensusError::InvalidConsumption);
    }
}

#[test]
fn ordinary_trace_identity_and_all_classification_fields_are_exact() {
    for kind in 0..10 {
        let mut case = Case::new(false);
        match kind {
            0 => case.actual.trace.ordinal += 1,
            1 => case.actual.trace.tid += 1,
            2 => case.actual.trace.status = 0,
            3 => case.actual.trace.status |= libc::PTRACE_EVENT_EXEC << 16,
            4 => case.actual.trace.status = (libc::SIGSEGV << 8) | 0x7f,
            5 => case.actual.trace.dr6 ^= 1,
            6 => case.actual.trace.signal[..4].copy_from_slice(&libc::SIGSEGV.to_ne_bytes()),
            7 => case.actual.trace.signal[4..8].copy_from_slice(&1_i32.to_ne_bytes()),
            8 => case.actual.trace.signal[8..12].copy_from_slice(&libc::SI_KERNEL.to_ne_bytes()),
            9 => case.actual.trace.signal[16] ^= 1,
            _ => unreachable!(),
        }
        // The separate retained trace must fail its own exact predicates;
        // NativeCompleted's owned-control signal field remains None.
        case.reject(CensusError::InvalidConsumption);
    }
}

#[test]
fn ordinary_logical_and_opening_whole_state_must_stay_exact() {
    for index in 0..4 {
        for kind in 0..4 {
            let mut case = Case::new(false);
            match kind {
                0 => case.actual.states[index].registers.r15 ^= 1,
                1 => case.actual.states[index].registers.eflags ^= 1,
                2 => case.actual.states[index].xstate[511] ^= 1,
                3 => case.actual.states[index].mask ^= 1,
                _ => unreachable!(),
            }
            case.reject(CensusError::InvalidConsumption);
        }
    }
    let mut case = Case::new(false);
    case.census.state.origins[0].current.xstate[0] ^= 1;
    case.reject(CensusError::StaleObservation);
}

#[test]
fn ordinary_reservation_keeps_all_six_existing_limit_gates() {
    // Add a real prospective parent prefix in otherwise-zero dimensions.
    // This does not claim ordinary execution itself creates these objects.
    for dimension in 0..6 {
        let (mut census, _) = seeded();
        let mut requested = ordinary_census_charge().unwrap();
        requested.epochs = 1;
        requested.reports = 1;
        requested.plan_history = 1;
        let exact = census.charged().add(requested).unwrap();
        census.limits = Limits {
            epochs: exact.epochs,
            source_fact_bytes: exact.source_fact_bytes,
            reports: exact.reports,
            origins: exact.origins,
            witnesses: exact.witnesses,
            plan_history: exact.plan_history,
        };
        match dimension {
            0 => census.limits.epochs -= 1,
            1 => census.limits.source_fact_bytes -= 1,
            2 => census.limits.reports -= 1,
            3 => census.limits.origins -= 1,
            4 => census.limits.witnesses -= 1,
            5 => census.limits.plan_history -= 1,
            _ => unreachable!(),
        }
        let old = census.state.clone();
        assert_eq!(
            census.reserve(requested).unwrap_err(),
            CensusError::Capacity
        );
        assert_eq!(census.state, old);
    }
}

#[test]
fn ordinary_one_byte_short_preparation_and_late_reservation_refuse_atomically() {
    let (mut census, origin) = seeded();
    let mut charge = ordinary_census_charge().unwrap();
    charge.source_fact_bytes -= 1;
    let token = census.reserve(charge).unwrap();
    let old = census.state.clone();
    assert!(matches!(
        census.prepare_model(
            token,
            origin,
            ExecutionId::from_owner(SESSION, 1).unwrap(),
            source(),
            Encoding::new(PC, &[0xeb, 0xfe]).unwrap(),
            Instant::now() + Duration::from_secs(60)
        ),
        Err(CensusError::ReservationExhausted)
    ));
    assert_eq!(census.state, old);
    for kind in 0..3 {
        let mut case = Case::new(false);
        let remaining = &mut case.census.state.reservation.as_mut().unwrap().1;
        match kind {
            0 => remaining.source_fact_bytes -= 1,
            1 => remaining.origins = 0,
            2 => remaining.witnesses = 6,
            _ => unreachable!(),
        }
        case.reject(CensusError::ReservationExhausted);
    }
}

#[test]
fn ordinary_preallocated_capacity_and_serial_checks_precede_every_mutation() {
    for kind in 0..4 {
        let mut case = Case::new(false);
        match kind {
            0 => case.prepared.buffers[14] = Vec::new(),
            1 => case.prepared.buffers[4].push(0),
            2 => case.prepared.evidence = None,
            3 => case.census.state.next_serial = u64::MAX,
            _ => unreachable!(),
        }
        case.reject(CensusError::Capacity);
    }
}

#[test]
fn ordinary_payload_transfers_preserve_exact_allocations_and_charge_once() {
    let mut case = Case::new(false);
    let mut pointers = vec![case.prepared.before.xstate.as_ptr() as usize];
    pointers.extend(case.prepared.buffers.iter().map(|v| v.as_ptr() as usize));
    pointers.sort();
    assert_eq!(pointers.len(), 16);
    assert!(pointers.windows(2).all(|v| v[0] != v[1]));
    let old_used = case.census.used();
    let charged = case.census.charged();
    let metadata = case.prepared.remaining_charge().unwrap();
    case.commit();
    let mut retained = Vec::new();
    for record in case.census.history() {
        let (a, b) = match record {
            HistoryRecord::Refreshed { before, after, .. } => (before, after),
            HistoryRecord::Consumed { evidence, .. } => (&evidence.before, &evidence.successor),
            _ => panic!("unexpected record"),
        };
        retained.extend([a.xstate.as_ptr() as usize, b.xstate.as_ptr() as usize]);
        assert_eq!(a.xstate.capacity(), 65536);
        assert_eq!(b.xstate.capacity(), 65536);
    }
    let row = &case.census.state.origins[1];
    retained.extend([
        row.row.initial.xstate.as_ptr() as usize,
        row.current.xstate.as_ptr() as usize,
    ]);
    retained.sort();
    assert_eq!(retained, pointers);
    assert_eq!(
        case.prepared.allocated_bytes().unwrap(),
        size_of::<PreparedOrdinaryCensus>()
    );
    assert_eq!(case.census.used(), old_used.add(metadata).unwrap());
    assert_eq!(case.census.charged(), charged);
    assert!(case.census.used().source_fact_bytes <= charged.source_fact_bytes);
}

#[test]
fn ordinary_failures_and_finished_reservations_never_refund_prepaid_storage() {
    let mut case = Case::new(false);
    let used = case.census.used();
    let charged = case.census.charged();
    case.actual.trace.dr6 ^= 1;
    case.reject(CensusError::InvalidConsumption);
    case.census.finish_reservation(case.reservation).unwrap();
    assert_eq!(case.census.used(), used);
    assert_eq!(case.census.charged(), charged);
    assert!(case.prepared.allocated_bytes().unwrap() > 16 * 65536);
    assert_eq!(
        case.census
            .check_reserved(case.reservation, BudgetCharge::default())
            .unwrap_err(),
        CensusError::StaleReservation
    );
}

#[test]
fn ordinary_duplicate_claim_model_foreign_reservation_and_expiry_never_replay() {
    let mut case = Case::new(false);
    case.commit();
    let old = case.census.state.clone();
    assert_eq!(
        case.census
            .commit_model(case.reservation, &case.actual.view(), &mut case.prepared)
            .unwrap_err(),
        CensusError::IdentityMismatch
    );
    assert_eq!(case.census.state, old);
    let mut case = Case::new(false);
    case.reservation.serial += 1;
    case.reject(CensusError::IdentityMismatch);
    let mut case = Case::new(false);
    case.prepared.binding.until = Instant::now() - Duration::from_secs(1);
    case.actual.until = case.prepared.binding.until;
    case.reject(CensusError::StaleObservation);
}

#[test]
fn ordinary_candidate_binding_keeps_full_snapshot_identity_and_selected_first() {
    let before = before();
    for bytes in [&[0xeb, 0xfe][..], &[0x0f, 0xa2][..]] {
        let snapshot = Snapshot::new(
            MappingId(17),
            Generation(0),
            PC,
            bytes.to_vec(),
            Boundary::Unknown,
            Boundary::Unknown,
            WriteControl::Owned,
        )
        .unwrap();
        let candidate = classify(
            &snapshot,
            &before.registers,
            DebugDisposition::Absent,
            &SyscallAliases::new(),
        )
        .unwrap();
        if bytes == [0xeb, 0xfe] {
            assert_eq!(
                validate_candidate(source(), &candidate, &before)
                    .unwrap()
                    .bytes(),
                bytes
            );
            for kind in 0..2 {
                let mut wrong = source();
                if kind == 0 {
                    wrong.identity.mapping += 1
                } else {
                    wrong.identity.generation += 1
                }
                assert_eq!(
                    validate_candidate(wrong, &candidate, &before).unwrap_err(),
                    CensusError::IdentityMismatch
                );
            }
        } else {
            assert_eq!(
                validate_candidate(source(), &candidate, &before).unwrap_err(),
                CensusError::IdentityMismatch
            );
        }
        assert!(std::ptr::eq(candidate.snapshot(), &snapshot));
    }
}

#[test]
fn ordinary_preparation_prebinds_checked_origin_serial_before_effects() {
    let (mut census, origin) = seeded();
    let token = census.reserve(ordinary_census_charge().unwrap()).unwrap();
    census.state.next_serial = u64::MAX;
    let old = census.state.clone();
    assert!(matches!(
        census.prepare_model(
            token,
            origin,
            ExecutionId::from_owner(SESSION, 1).unwrap(),
            source(),
            Encoding::new(PC, &[0xeb, 0xfe]).unwrap(),
            Instant::now() + Duration::from_secs(60)
        ),
        Err(CensusError::Capacity)
    ));
    assert_eq!(census.state, old);
    let mut case = Case::new(false);
    assert_eq!(
        case.prepared.binding.candidate_serial,
        case.census.state.next_serial
    );
    case.census.state.next_serial += 1;
    case.reject(CensusError::StaleObservation);
}
