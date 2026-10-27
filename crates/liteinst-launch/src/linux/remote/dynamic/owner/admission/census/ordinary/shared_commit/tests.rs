//! Supplied-model controls only: no native completion or permit is minted.
use super::*;
use crate::lifecycle::LifecycleRegistry;
use crate::linux::remote::dynamic::owner::trusted::AdmissionStop;
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
    let charge = crate::linux::remote::dynamic::owner::admission::census::runtime::initial_runtime_origin_charge(MAX_XSTATE_BYTES).unwrap();
    let reserve = census.reserve(charge).unwrap();
    let origin = census
        .insert(reserve, OriginKind::CurrentHeldPc, PC, before)
        .unwrap();
    census.finish_reservation(reserve).unwrap();
    (census, origin)
}

#[derive(Clone)]
struct Model {
    binding: Binding,
    stops: [AdmissionStop; 8],
    before: TaskStateSnapshot,
    step: TaskStateSnapshot,
    trace: NativeTrace,
}
impl Model {
    fn new(prepared: &PreparedSharedOrdinaryCensus, same_pc: bool) -> Self {
        let b = prepared.history.prior().unwrap();
        let before = TaskStateSnapshot {
            registers: *b.registers,
            xstate: b.xstate.to_vec(),
            mask: b.signal_mask,
        };
        let mut step = before.clone();
        if !same_pc {
            step.registers.rip += 4;
            step.registers.rax += 1;
            step.registers.eflags = 0x206;
        }
        let stops = std::array::from_fn(|index| {
            let mut token = b.token.clone();
            token.sequence += index as u64;
            AdmissionStop {
                token,
                identity: b.task,
                signal: None,
                phase: if index == 0 {
                    AdmissionPhase::EntryReady
                } else if index == 4 {
                    AdmissionPhase::NativeCompleted
                } else {
                    AdmissionPhase::Restored
                },
            }
        });
        let mut signal = [0; 128];
        signal[..4].copy_from_slice(&libc::SIGTRAP.to_ne_bytes());
        signal[8..12].copy_from_slice(&libc::TRAP_TRACE.to_ne_bytes());
        signal[16..24].copy_from_slice(&step.registers.rip.to_ne_bytes());
        Self {
            binding: prepared.binding.unwrap(),
            stops,
            before,
            step,
            trace: NativeTrace {
                ordinal: 3,
                tid: 101,
                status: (libc::SIGTRAP << 8) | 0x7f,
                signal,
                dr6: TRACE_DR6,
            },
        }
    }
    fn view(&self) -> CompletionModel<'_> {
        CompletionModel {
            source: self.binding.source,
            origin: self.binding.origin,
            execution: self.binding.execution,
            until: self.binding.until,
            encoding: self.binding.encoding.bytes(),
            logical: NativeCheckpoint {
                stop: &self.stops[0],
                state: &self.before,
            },
            opening: std::array::from_fn(|i| NativeCheckpoint {
                stop: &self.stops[i + 1],
                state: &self.before,
            }),
            step: NativeCheckpoint {
                stop: &self.stops[4],
                state: &self.step,
            },
            closing: std::array::from_fn(|i| NativeCheckpoint {
                stop: &self.stops[i + 5],
                state: &self.step,
            }),
            trace: self.trace,
        }
    }
}

struct Case {
    census: ResumeCensus,
    reservation: Reservation,
    pending: SharedOrdinaryPreparation,
    model: Model,
}
impl Case {
    fn new(same_pc: bool) -> Self {
        let (mut census, origin) = seeded();
        let reservation = census
            .reserve(ordinary_shared_census_charge().unwrap())
            .unwrap();
        let request = SharedRequest {
            origin,
            execution: ExecutionId::from_owner(SESSION, 1).unwrap(),
            source: source(),
            encoding: Encoding::new(
                PC,
                if same_pc {
                    &[0xeb, 0xfe]
                } else {
                    &[0x48, 0x83, 0xc0, 1]
                },
            )
            .unwrap(),
            until: Instant::now() + Duration::from_secs(60),
        };
        let mut pending = SharedOrdinaryPreparation::empty();
        pending
            .prepare_with(&mut census, reservation, |c, p| {
                c.prepare_shared_model(reservation, request, p)
            })
            .unwrap();
        let model = Model::new(pending.prepared.as_ref().unwrap(), same_pc);
        Self {
            census,
            reservation,
            pending,
            model,
        }
    }
    fn copy(&mut self) -> Result<(), CensusError> {
        let prepared = self.pending.prepared_mut()?;
        self.census
            .validate_shared_model(self.reservation, &self.model.view(), prepared)?;
        prepared.stage = Stage::Copying;
        prepared.history.stage_model(&self.model.view())?;
        prepared.copy_origins(&self.model.view())
    }
    fn commit(&mut self) -> Result<OriginId, CensusError> {
        let result = (|| {
            self.copy()?;
            Ok(self
                .census
                .publish_shared_ordinary(
                    self.reservation,
                    &self.model.view(),
                    self.pending.prepared.as_mut().unwrap(),
                )?
                .current)
        })();
        if let Err(error) = result {
            self.pending.prepared.as_mut().unwrap().fail(error);
        }
        result
    }
}

#[test]
fn ordinary_shared_shape_has_five_exact_distinct_payloads() {
    let mut case = Case::new(false);
    let prepared = case.pending.prepared_mut().unwrap();
    let view = prepared.history.partial_view();
    let archive = view.archive.unwrap();
    let mut pointers = archive
        .payloads
        .iter()
        .map(|p| {
            assert_eq!(p.identity.capacity, MAX_XSTATE_BYTES);
            p.identity.pointer
        })
        .collect::<Vec<_>>();
    for buffer in &prepared.origins {
        assert_eq!(buffer.capacity(), MAX_XSTATE_BYTES);
        assert!(buffer.is_empty());
        pointers.push(buffer.as_ptr() as usize);
    }
    pointers.sort_unstable();
    pointers.dedup();
    assert_eq!(pointers.len(), 5);
    assert_eq!(archive.payloads[0].bytes, before().xstate);
    assert!(archive.payloads[1..].iter().all(|p| p.bytes.is_empty()));
    assert_eq!(
        prepared.allocated_bytes().unwrap(),
        shared_preparation_bytes().unwrap()
    );
    assert_eq!(
        prepared.preparation_debit,
        Some(shared_preparation_bytes().unwrap())
    );
    let charge = ordinary_shared_census_charge().unwrap();
    assert_eq!(
        (
            charge.epochs,
            charge.reports,
            charge.origins,
            charge.witnesses,
            charge.plan_history
        ),
        (0, 0, 1, 7, 0)
    );
    assert_eq!(
        charge.source_fact_bytes,
        shared_preparation_bytes().unwrap()
            + shared_fixed_commit_bytes().unwrap()
            + shared_temporary_bytes().unwrap()
    );
    assert_eq!(MAX_XSTATE_BYTES * (16 - 5), 720896);
    // Prospective refusal happens before any attempt/header/payload exists;
    // no charged or used dimension is changed by a one-short resource bound.
    for axis in 0..3 {
        let (mut census, _) = seeded();
        let charged = census.charged();
        match axis {
            0 => {
                census.limits.source_fact_bytes =
                    charged.source_fact_bytes + charge.source_fact_bytes - 1
            }
            1 => census.limits.origins = charged.origins + charge.origins - 1,
            2 => census.limits.witnesses = charged.witnesses + charge.witnesses - 1,
            _ => unreachable!(),
        }
        let before = census.state.clone();
        assert_eq!(census.reserve(charge), Err(CensusError::Capacity));
        assert_eq!(census.state, before);
    }
}

#[test]
fn ordinary_shared_model_publishes_exact_seven_rows_and_full_states() {
    for same_pc in [false, true] {
        let mut case = Case::new(same_pc);
        let old = case.model.binding.origin;
        let used = case.census.used();
        let id = case.commit().unwrap();
        assert_eq!(case.census.history().len(), 7);
        assert_eq!(case.census.rows().count(), 2);
        assert_eq!(case.census.active().count(), 1);
        let mut sequence = case.model.stops[0].token.clone();
        let mut pointers = Vec::new();
        for (index, row) in case.census.history().iter().enumerate() {
            let (origin, before, after) = match case.census.history_view(row).unwrap() {
                HistoryView::Refreshed {
                    origin,
                    before,
                    after,
                } => {
                    assert_ne!(index, 3);
                    (origin, before, after)
                }
                HistoryView::Consumed { origin, evidence } => {
                    assert_eq!(index, 3);
                    assert!(matches!(
                        evidence.evidence,
                        ConsumptionEvidenceView::SharedOrdinary(_)
                    ));
                    (origin, evidence.before, evidence.successor)
                }
                HistoryView::Other(_) => panic!("unexpected logical history kind"),
            };
            assert_eq!(origin, if index <= 3 { old } else { id });
            assert_eq!(before.token, &sequence);
            assert_eq!(after.token, &case.model.stops[index + 1].token);
            assert!(after.token.sequence > before.token.sequence);
            assert_eq!(before.task, case.model.stops[0].identity);
            assert_eq!(after.task, before.task);
            let expected_before = if index <= 3 {
                &case.model.before
            } else {
                &case.model.step
            };
            let expected_after = if index < 3 {
                &case.model.before
            } else {
                &case.model.step
            };
            assert_eq!(
                (*before.registers, before.xstate, before.signal_mask),
                (
                    expected_before.registers,
                    expected_before.xstate.as_slice(),
                    expected_before.mask
                )
            );
            assert_eq!(
                (*after.registers, after.xstate, after.signal_mask),
                (
                    expected_after.registers,
                    expected_after.xstate.as_slice(),
                    expected_after.mask
                )
            );
            assert_eq!(
                after.phase,
                if index == 3 {
                    StopPhase::OwnedOrdinaryComplete {
                        execution: case.model.binding.execution,
                    }
                } else {
                    StopPhase::UserCheckpoint
                }
            );
            assert_eq!(
                after.signal.map(|s| s.raw),
                if index == 3 {
                    Some(case.model.trace.signal)
                } else {
                    None
                }
            );
            pointers.push(before.xstate.as_ptr());
            pointers.push(after.xstate.as_ptr());
            sequence = after.token.clone();
        }
        let archive = &case.census.state.origins[1]
            .ordinary_history
            .as_ref()
            .unwrap()
            .archive;
        let view = archive.partial_view();
        for (index, count) in [(0, 1), (1, 6), (2, 7)] {
            assert_eq!(
                pointers
                    .iter()
                    .filter(|p| **p as usize == view.payloads[index].identity.pointer)
                    .count(),
                count
            );
        }
        let active = case.census.active().next().unwrap();
        assert_eq!(active.row.id, id);
        assert_eq!(active.current.token, sequence);
        assert_eq!(active.current.xstate, case.model.step.xstate);
        let mut all = view.payloads.map(|p| p.identity.pointer).to_vec();
        all.extend([
            active.current.xstate.as_ptr() as usize,
            active.row.initial.xstate.as_ptr() as usize,
        ]);
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), 5);
        assert_eq!(
            case.census.used().source_fact_bytes - used.source_fact_bytes,
            shared_fixed_commit_bytes().unwrap()
        );
        assert_eq!(
            case.pending.prepared.as_ref().unwrap().stage,
            Stage::Committed
        );
        assert_eq!(
            case.pending
                .prepared
                .as_ref()
                .unwrap()
                .allocated_bytes()
                .unwrap(),
            size_of::<PreparedSharedOrdinaryCensus>()
        );
        assert_eq!(
            case.pending.settlement,
            Some(Ok(shared_preparation_bytes().unwrap()))
        );
    }
}

#[test]
fn ordinary_shared_allocation_prefixes_settle_once_on_error_and_unwind() {
    for ordinal in 0..5 {
        for unwind in [false, true] {
            let (mut census, origin) = seeded();
            let reservation = census
                .reserve(ordinary_shared_census_charge().unwrap())
                .unwrap();
            let used = census.used();
            let charged = census.charged();
            let request = SharedRequest {
                origin,
                execution: ExecutionId::from_owner(SESSION, 1).unwrap(),
                source: source(),
                encoding: Encoding::new(PC, &[0x90]).unwrap(),
                until: Instant::now() + Duration::from_secs(60),
            };
            let mut pending = SharedOrdinaryPreparation::empty();
            pending.fault = if unwind {
                AllocationFault {
                    before: None,
                    after: Some(ordinal),
                }
            } else {
                AllocationFault {
                    before: Some(ordinal),
                    after: None,
                }
            };
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                pending.prepare_with(&mut census, reservation, |c, p| {
                    c.prepare_shared_model(reservation, request, p)
                })
            }));
            if unwind {
                assert_eq!(
                    outcome.unwrap_err().downcast_ref::<u32>(),
                    Some(&0x5348_4152)
                );
                assert!(pending.unwound);
            } else {
                assert_eq!(outcome.unwrap(), Err(CensusError::Allocation));
            }
            let actual = pending
                .prepared
                .as_ref()
                .map_or(0, |p| p.allocated_bytes().unwrap());
            assert_eq!(pending.settlement, Some(Ok(actual)));
            assert_eq!(
                census.used().source_fact_bytes - used.source_fact_bytes,
                actual
            );
            assert_eq!(census.charged(), charged);
            assert!(census.history().is_empty());
            assert_eq!(census.active().next().unwrap().row.id, origin);
            let snapshot = pending.history_snapshot().unwrap();
            let state = census.state.clone();
            assert_eq!(
                pending.prepare_with(&mut census, reservation, |_, _| Ok(())),
                Err(CensusError::InvalidConsumption)
            );
            assert_eq!(pending.history_snapshot().unwrap(), snapshot);
            assert_eq!(census.state, state);
        }
    }
}

#[test]
fn ordinary_shared_canonical_capture_and_copy_prefixes_are_required() {
    let mut case = Case::new(false);
    let duplicate = case.model.before.clone();
    let mut model = case.model.view();
    model.opening[1].state = &duplicate;
    let p = case.pending.prepared.as_mut().unwrap();
    assert!(
        case.census
            .validate_shared_model(case.reservation, &model, p)
            .is_ok()
    );
    let state = case.census.state.clone();
    assert_eq!(
        p.history.stage_model(&model),
        Err(shared::SharedError::Provenance)
    );
    assert_eq!(case.census.state, state);
    for index in 0..2 {
        let mut case = Case::new(false);
        case.pending.prepared.as_mut().unwrap().copy_fault = Some((index, 256));
        let state = case.census.state.clone();
        assert_eq!(case.commit(), Err(CensusError::InvalidConsumption));
        assert_eq!(case.census.state, state);
        let p = case.pending.prepared.as_ref().unwrap();
        assert_eq!(p.origins[index].len(), 256);
        assert_eq!(p.copies[index].copied, 256);
        assert!(p.copies[index].started && !p.copies[index].complete);
        assert_eq!(p.first_failure, Some(CensusError::InvalidConsumption));
        assert!(p.history.archive().unwrap().records().is_ok());
        assert_eq!(
            p.preparation_debit,
            Some(shared_preparation_bytes().unwrap())
        );
    }
}

#[test]
fn ordinary_shared_full_validator_rejects_changed_binding_state_trace_and_sequence() {
    for axis in 0..21 {
        let case = Case::new(false);
        let mut changed = case.model.clone();
        match axis {
            0 => changed.binding.source.identity.mapping += 1,
            1 => changed.binding.execution.serial += 1,
            2 => changed.binding.origin.serial += 1,
            3 => changed.binding.until += Duration::from_secs(1),
            4 => changed.binding.encoding.bytes[0] ^= 1,
            5 => changed.stops[0].token.sequence += 1,
            6 => changed.stops[0].identity.generation += 1,
            7 => changed.before.registers.rax ^= 1,
            8 => changed.before.xstate[0] ^= 1,
            9 => changed.before.mask ^= 1,
            10 => changed.stops[2].token.sequence = changed.stops[1].token.sequence,
            11 => changed.stops[3].phase = AdmissionPhase::EntryReady,
            12 => changed.step.registers.orig_rax = 39,
            13 => changed.stops[4].phase = AdmissionPhase::Restored,
            14 => changed.trace.ordinal = 2,
            15 => changed.trace.tid += 1,
            16 => changed.trace.status = (libc::SIGSEGV << 8) | 0x7f,
            17 => changed.trace.dr6 ^= 1,
            18 => changed.trace.signal[8] ^= 1,
            19 => changed.trace.signal[16] ^= 1,
            20 => changed.stops[7].token.sequence = changed.stops[6].token.sequence,
            _ => unreachable!(),
        }
        let state = case.census.state.clone();
        assert!(
            case.census
                .validate_shared_model(
                    case.reservation,
                    &changed.view(),
                    case.pending.prepared.as_ref().unwrap()
                )
                .is_err(),
            "axis {axis}"
        );
        assert_eq!(case.census.state, state);
    }
}

#[test]
fn ordinary_shared_final_checks_precede_every_publication() {
    for axis in 0..4 {
        let mut case = Case::new(false);
        case.copy().unwrap();
        match axis {
            0 => case.census.state.next_serial += 1,
            1 => case.census.state.origins[0].current.xstate[0] ^= 1,
            2 => case.pending.prepared.as_mut().unwrap().preparation_debit = Some(0),
            3 => case.pending.prepared.as_mut().unwrap().origins[1][0] ^= 1,
            _ => unreachable!(),
        }
        let state = case.census.state.clone();
        let snapshot = case.pending.history_snapshot().unwrap();
        assert!(
            case.census
                .publish_shared_ordinary(
                    case.reservation,
                    &case.model.view(),
                    case.pending.prepared.as_mut().unwrap()
                )
                .is_err()
        );
        assert_eq!(case.census.state, state);
        assert_eq!(case.pending.history_snapshot().unwrap(), snapshot);
        assert!(case.census.history().is_empty());
        assert_eq!(case.census.rows().count(), 1);
    }
}

#[test]
fn ordinary_shared_resolver_rejects_wrong_owner_evidence_and_endpoints() {
    for axis in 0..5 {
        let mut case = Case::new(false);
        case.commit().unwrap();
        let record = case.census.history()[0].clone();
        match axis {
            0 => case.census.state.origins[1].ordinary_history = None,
            1 => case.census.state.origins[1].row.initial.xstate[0] ^= 1,
            2 => {
                case.census.state.origins[1]
                    .ordinary_history
                    .as_mut()
                    .unwrap()
                    .evidence[0]
                    .binding
                    .execution
                    .serial += 1
            }
            3 => {
                case.census.state.origins[1]
                    .ordinary_history
                    .as_mut()
                    .unwrap()
                    .evidence[0]
                    .trace = None
            }
            4 => {
                let duplicate = case.census.state.origins[1].clone();
                case.census.state.origins.push(duplicate);
            }
            _ => unreachable!(),
        }
        assert!(case.census.history_view(&record).is_err());
        assert!(case.census.history_snapshot().is_err());
    }
    let mut case = Case::new(false);
    case.commit().unwrap();
    let HistoryRecord::SharedOrdinary(mut changed) = case.census.history()[0].clone() else {
        panic!()
    };
    let SharedHistoryRecord::Refreshed {
        origin,
        before,
        after,
    } = changed.row
    else {
        panic!()
    };
    changed.row = SharedHistoryRecord::Refreshed {
        origin,
        before: after,
        after: before,
    };
    assert!(
        case.census
            .history_view(&HistoryRecord::SharedOrdinary(changed))
            .is_err()
    );
}

#[test]
fn ordinary_shared_history_snapshots_keep_bytes_ids_and_checked_prefixes() {
    let mut case = Case::new(false);
    case.commit().unwrap();
    let history = case.census.history_snapshot().unwrap();
    assert_eq!(history.len(), 7);
    assert_eq!(history.rows().len(), 7);
    assert_eq!(
        history.prefix(3).unwrap(),
        case.census.history_snapshot_prefix(3).unwrap()
    );
    assert!(history.prefix(8).is_err());
    assert!(case.census.history_snapshot_prefix(8).is_err());
    let mut archive = case.census.state.origins[1]
        .ordinary_history
        .as_ref()
        .unwrap()
        .archive
        .test_snapshot();
    let original = archive.clone();
    archive.bytes[1][0] ^= 1;
    assert_ne!(archive, original);
    archive = original.clone();
    archive.identities[1].pointer ^= 1;
    assert_ne!(archive, original);
    // Same historical identity is valid after the owner becomes inactive and
    // a newer generation exists. Retirement passes this exact old identity.
    case.census.state.origins[1].active = false;
    case.census.state.generation += 1;
    assert_eq!(case.census.history_snapshot().unwrap(), history);
    let row = &case.census.history()[0];
    assert!(
        crate::linux::remote::dynamic::owner::admission::census::history::resolve(
            case.census.identity + 1,
            &case.census.state.origins,
            row
        )
        .is_err()
    );
}
