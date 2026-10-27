//! Pure atomicity/allocation comparisons. No successful native seal or live
//! state is fabricated; private models cannot call the production entrypoint.
use super::super::stack_calls::PreparedCallRecord;
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

pub(in crate::linux::remote::dynamic::owner::admission::census) mod model;
use model::*;

struct Case {
    census: ResumeCensus,
    reservation: Reservation,
    prepared: PreparedStackCensus,
    calls: RuntimeCallLedger,
    actual: Model,
}
impl Case {
    fn new(operation: StackOperation) -> Self {
        let (mut census, origin) = seeded();
        let mut charge = stack_census_charge().unwrap();
        if operation == StackOperation::DirectCall {
            charge.source_fact_bytes += PreparedCallRecord::reservation_bytes().unwrap();
        }
        let reservation = census.reserve(charge).unwrap();
        let mut actual = Model::new(&census, reservation, origin, operation);
        let mut calls = RuntimeCallLedger::empty();
        calls.allocate_payloads(limits().origins).unwrap();
        let mut prepared = PreparedStackCensus::empty();
        prepared.allocate_payloads().unwrap();
        prepared.settle_storage(&mut census, reservation).unwrap();
        census
            .prepare_stack_model(actual.binding.clone(), &mut prepared)
            .unwrap();
        if operation == StackOperation::DirectCall {
            let mut call = exact_storage::value(PreparedCallRecord::empty()).unwrap();
            call.allocate_payloads().unwrap();
            call.settle_storage(&mut census, reservation).unwrap();
            calls
                .prepare_model_test(&census, actual.binding.clone(), &mut call)
                .unwrap();
            let mut pending = Some(call);
            actual.call = Some(calls.append_model_test(&census, &mut pending).unwrap().id());
            assert!(pending.is_none());
        }
        Self {
            census,
            reservation,
            prepared,
            calls,
            actual,
        }
    }
    fn reject(&mut self) {
        let state = self.census.state.clone();
        let before = self.prepared.before.clone();
        let buffers = self
            .prepared
            .buffers
            .iter()
            .map(|b| (b.as_ptr(), b.len(), b.capacity()))
            .collect::<Vec<_>>();
        let evidence = self.prepared.evidence.clone();
        let call_count = self.calls.count();
        let call_bytes = self.calls.allocated_bytes().unwrap();
        assert!(
            self.census
                .commit_stack_model(
                    self.reservation,
                    &self.actual.view(),
                    &mut self.prepared,
                    &self.calls
                )
                .is_err()
        );
        assert_eq!(self.census.state, state);
        assert_eq!(self.prepared.before, before);
        assert_eq!(
            self.prepared
                .buffers
                .iter()
                .map(|b| (b.as_ptr(), b.len(), b.capacity()))
                .collect::<Vec<_>>(),
            buffers
        );
        assert_eq!(self.prepared.evidence, evidence);
        assert!(!self.prepared.committed);
        assert_eq!(self.calls.count(), call_count);
        assert_eq!(self.calls.allocated_bytes().unwrap(), call_bytes);
    }
    fn commit(&mut self) -> OriginId {
        self.census
            .commit_stack_model(
                self.reservation,
                &self.actual.view(),
                &mut self.prepared,
                &self.calls,
            )
            .unwrap()
            .current
    }
}

#[test]
fn stack_census_prepays_exact_six_refreshes_and_sixteen_state_owners() {
    let charge = stack_census_charge().unwrap();
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
    assert_eq!(
        charge.source_fact_bytes,
        size_of::<PreparedStackCensus>()
            + 16 * 65536
            + size_of::<StackEvidence>()
            + 16 * size_of::<ObservedStop>()
            + 6 * size_of::<HistoryRecord>()
            + size_of::<OwnerConsumption>()
            + size_of::<StoredOrigin>()
    );
    let case = Case::new(StackOperation::Return);
    assert_eq!(
        case.prepared.allocated_bytes().unwrap(),
        preparation_bytes().unwrap()
    );
    assert_eq!(
        case.prepared.remaining_charge().unwrap().source_fact_bytes,
        fixed_commit_bytes().unwrap()
    );
    assert!(
        stack_census_temporary_bytes().unwrap()
            >= size_of::<CompletionModel<'_>>() + 3 * size_of::<Binding>()
    );
}
#[test]
fn stack_census_retains_every_partial_allocation_before_error_or_unwind() {
    for ordinal in 0..=STATES {
        let (mut census, _) = seeded();
        let reservation = census.reserve(stack_census_charge().unwrap()).unwrap();
        let charged = census.state.charged;
        let mut prepared = PreparedStackCensus::empty();
        assert_eq!(
            prepared.allocate_with(
                |i| if i == ordinal {
                    Err(CensusError::Allocation)
                } else {
                    Ok(())
                },
                |_| {}
            ),
            Err(CensusError::Allocation)
        );
        assert_eq!(
            prepared.allocated_bytes().unwrap(),
            size_of::<PreparedStackCensus>() + ordinal * MAX_XSTATE_BYTES
        );
        prepared.settle_storage(&mut census, reservation).unwrap();
        let used = census.state.used;
        prepared.settle_storage(&mut census, reservation).unwrap();
        assert_eq!(census.state.used, used);
        assert_eq!(census.state.charged, charged);
        assert!(prepared.allocate_payloads().is_err());
        let (mut unwind_census, _) = seeded();
        let unwind_reservation = unwind_census
            .reserve(stack_census_charge().unwrap())
            .unwrap();
        let unwind_charge = unwind_census.state.charged;
        let prior = unwind_census.state.used.source_fact_bytes;
        let mut unwind = PreparedStackCensus::empty();
        let panic = catch_unwind(AssertUnwindSafe(|| {
            unwind.allocate_with(
                |_| Ok(()),
                |i| {
                    if i == ordinal {
                        std::panic::panic_any(0x51_u32)
                    }
                },
            )
        }));
        assert_eq!(*panic.unwrap_err().downcast::<u32>().unwrap(), 0x51);
        unwind.mark_aborted();
        let payload = if ordinal < STATES {
            (ordinal + 1) * MAX_XSTATE_BYTES
        } else {
            STATES * MAX_XSTATE_BYTES + size_of::<StackEvidence>()
        };
        assert_eq!(
            unwind.allocated_bytes().unwrap(),
            size_of::<PreparedStackCensus>() + payload
        );
        unwind
            .settle_storage(&mut unwind_census, unwind_reservation)
            .unwrap();
        assert_eq!(
            unwind_census.state.used.source_fact_bytes,
            prior + size_of::<PreparedStackCensus>() + payload
        );
        assert_eq!(unwind_census.state.charged, unwind_charge);
        assert!(unwind.allocate_payloads().is_err());
        assert!(unwind.require_allocated().is_err());
    }
}
#[test]
fn stack_census_requires_settlement_and_keeps_failed_settlement_atomic() {
    let (mut census, origin) = seeded();
    let reservation = census.reserve(stack_census_charge().unwrap()).unwrap();
    let actual = Model::new(&census, reservation, origin, StackOperation::Return);
    let mut prepared = PreparedStackCensus::empty();
    prepared.allocate_payloads().unwrap();
    assert_eq!(
        census.prepare_stack_model(actual.binding.clone(), &mut prepared),
        Err(CensusError::ReservationExhausted)
    );
    let state = census.state.clone();
    let wrong = Reservation {
        census: reservation.census,
        serial: reservation.serial + 1,
    };
    assert!(prepared.settle_storage(&mut census, wrong).is_err());
    assert_eq!(census.state, state);
    assert_eq!(prepared.settled_bytes, 0);
    prepared.settle_storage(&mut census, reservation).unwrap();
    census
        .prepare_stack_model(actual.binding.clone(), &mut prepared)
        .unwrap();
    assert_eq!(
        prepared.before.as_ref().unwrap().xstate,
        census.current_observation(origin).unwrap().xstate
    );
    for axis in 0..3 {
        let (mut limited, origin) = seeded();
        let mut charge = stack_census_charge().unwrap();
        match axis {
            0 => charge.source_fact_bytes -= 1,
            1 => charge.origins = 0,
            2 => charge.witnesses -= 1,
            _ => unreachable!(),
        }
        let reservation = limited.reserve(charge).unwrap();
        let model = Model::new(&limited, reservation, origin, StackOperation::Return);
        let mut storage = PreparedStackCensus::empty();
        storage.allocate_payloads().unwrap();
        storage.settle_storage(&mut limited, reservation).unwrap();
        let state = limited.state.clone();
        let pointers = storage.buffers.each_ref().map(|v| v.as_ptr());
        assert!(
            limited
                .prepare_stack_model(model.binding, &mut storage)
                .is_err()
        );
        assert_eq!(limited.state, state);
        assert!(!storage.prepared);
        assert!(storage.before.is_none());
        assert_eq!(storage.buffers.each_ref().map(|v| v.as_ptr()), pointers);
    }
}
#[test]
fn stack_census_ret_commits_exact_chain_and_preserves_prepaid_owners() {
    let mut case = Case::new(StackOperation::Return);
    let old = case.actual.binding.origin;
    let charged = case.census.state.charged;
    let current = case.commit();
    assert_ne!(old, current);
    assert_eq!(case.calls.count(), 0);
    assert_eq!(case.census.state.charged, charged);
    assert_eq!(case.census.state.history.len(), 7);
    assert_eq!(case.census.state.origins.len(), 2);
    let observed = case.census.current_observation(current).unwrap();
    assert_eq!(observed.token, case.actual.stops[7].token);
    assert_eq!(observed.registers, case.actual.states[7].registers);
    assert_eq!(observed.xstate, case.actual.states[7].xstate);
    assert_eq!(observed.signal_mask, case.actual.states[7].mask);
    assert!(case.census.state.origins[1].runtime_kernel.is_none());
    for (index, record) in case.census.state.history.iter().enumerate() {
        let (origin, before, after) = match record {
            HistoryRecord::Refreshed {
                origin,
                before,
                after,
            } if index != 3 => (*origin, before, after),
            HistoryRecord::Consumed { origin, evidence } if index == 3 => {
                let Consumption::OwnedStack(records) = &evidence.evidence else {
                    panic!("stack evidence missing")
                };
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].binding.as_ref(), Some(&case.actual.binding));
                assert_eq!(records[0].trace, Some(case.actual.trace));
                assert_eq!(
                    records[0].words,
                    Some(case.actual.view().words.captures.map(|v| v.word.bytes))
                );
                assert_eq!(records[0].call, None);
                (*origin, &evidence.before, &evidence.successor)
            }
            _ => panic!("stack history order differs"),
        };
        assert_eq!(origin, if index <= 3 { old } else { current });
        assert_eq!(before.token, case.actual.stops[index].token);
        assert_eq!(after.token, case.actual.stops[index + 1].token);
        assert_eq!(before.task, case.actual.stops[index].identity);
        assert_eq!(after.task, case.actual.stops[index + 1].identity);
        assert!(same_architecture(before, &case.actual.states[index]));
        assert!(same_architecture(after, &case.actual.states[index + 1]));
        assert_eq!(before.xstate.capacity(), MAX_XSTATE_BYTES);
        assert_eq!(after.xstate.capacity(), MAX_XSTATE_BYTES);
        let step = StopPhase::OwnedStackComplete {
            execution: case.actual.binding.execution,
        };
        assert_eq!(
            before.phase,
            if index == 4 {
                step
            } else {
                StopPhase::UserCheckpoint
            }
        );
        assert_eq!(
            after.phase,
            if index == 3 {
                step
            } else {
                StopPhase::UserCheckpoint
            }
        );
        assert_eq!(
            before.signal.as_ref().map(|v| v.raw),
            if index == 4 {
                Some(case.actual.trace.signal)
            } else {
                None
            }
        );
        assert_eq!(
            after.signal.as_ref().map(|v| v.raw),
            if index == 3 {
                Some(case.actual.trace.signal)
            } else {
                None
            }
        );
    }

    assert!(case.prepared.buffers.iter().all(|b| b.capacity() == 0));
    assert!(case.prepared.evidence.is_none());
    assert_eq!(case.prepared.before.as_ref().unwrap().xstate.capacity(), 0);
    assert!(
        case.census
            .commit_stack_model(
                case.reservation,
                &case.actual.view(),
                &mut case.prepared,
                &case.calls
            )
            .is_err()
    );
    assert!(
        case.prepared
            .settle_storage(&mut case.census, case.reservation)
            .is_err()
    );
    case.census.finish_reservation(case.reservation).unwrap();
    assert_eq!(case.census.state.charged, charged);
}
#[test]
fn stack_census_call_boundary_retains_return_without_opening_its_page() {
    let mut case = Case::new(StackOperation::DirectCall);
    let bytes = case.calls.allocated_bytes().unwrap();
    assert_eq!(case.actual.binding.operand.geometry.next_pc, 0x401000);
    assert_eq!(
        case.actual.binding.fetch.pages(),
        AddressRange::new(0x400000, 0x401000).unwrap()
    );
    assert!(
        std::str::from_utf8(&case.actual.opened)
            .unwrap()
            .contains("00401000-00402000 r--p")
    );
    case.actual
        .binding
        .source
        .require_snapshot(
            case.actual.binding.source,
            &case.actual.snapshot,
            &case.actual.binding.operand.geometry,
            &case.actual.binding.fetch,
        )
        .unwrap();
    case.commit();
    assert_eq!(case.calls.count(), 1);
    assert_eq!(case.calls.allocated_bytes().unwrap(), bytes);
    let HistoryRecord::Consumed { evidence, .. } = &case.census.state.history[3] else {
        panic!("missing actual model consumption")
    };
    let Consumption::OwnedStack(records) = &evidence.evidence else {
        panic!("wrong evidence kind")
    };
    assert_eq!(records[0].call, case.actual.call);
    assert_eq!(records[0].trace, Some(case.actual.trace));
    assert_eq!(
        records[0].words,
        Some(case.actual.captures.each_ref().map(|v| v.word.bytes))
    );
}
#[test]
fn stack_census_missing_call_or_return_with_call_refuses_atomically() {
    let mut call = Case::new(StackOperation::DirectCall);
    let id = call.actual.call;
    call.actual.call = None;
    call.reject();
    let mut ret = Case::new(StackOperation::Return);
    ret.actual.call = id;
    ret.reject();
}
#[test]
fn stack_census_rejects_every_checkpoint_identity_phase_and_order_corruption() {
    for index in 0..8 {
        let mut case = Case::new(StackOperation::Return);
        case.actual.stops[index].token.session += 1;
        case.reject();
        let mut case = Case::new(StackOperation::Return);
        case.actual.stops[index].token.tid += 1;
        case.reject();
        let mut case = Case::new(StackOperation::Return);
        case.actual.stops[index].identity.generation = 1;
        case.reject();
        if index > 0 {
            let mut case = Case::new(StackOperation::Return);
            case.actual.stops[index].token.sequence = case.actual.stops[index - 1].token.sequence;
            case.reject();
        }
    }
    let mut case = Case::new(StackOperation::Return);
    case.actual.stops[4].phase = AdmissionPhase::Restored;
    case.reject();
    let mut case = Case::new(StackOperation::Return);
    case.actual.stops[7].phase = AdmissionPhase::NativeCompleted;
    case.reject();
    let mut case = Case::new(StackOperation::Return);
    let mut supplied = case
        .census
        .current_observation(case.actual.binding.origin)
        .unwrap()
        .clone();
    supplied.token = case.actual.stops[4].token.clone();
    supplied.registers = case.actual.states[4].registers;
    supplied.logical_pc = supplied.registers.rip;
    supplied.phase = StopPhase::OwnedStackComplete {
        execution: case.actual.binding.execution,
    };
    supplied.signal = Some(DynamicSignalInfo {
        raw: case.actual.trace.signal,
    });
    let state = case.census.state.clone();
    assert_eq!(
        case.census.insert(
            case.reservation,
            OriginKind::CurrentHeldPc,
            supplied.logical_pc,
            supplied
        ),
        Err(CensusError::WrongOriginPhase)
    );
    assert_eq!(case.census.state, state);
}
#[test]
fn stack_census_rejects_full_state_and_raw_trace_corruption() {
    for index in 0..8 {
        let mut case = Case::new(StackOperation::Return);
        case.actual.states[index].registers.rbx ^= 1;
        case.reject();
        let mut case = Case::new(StackOperation::Return);
        case.actual.states[index].xstate[700] ^= 1;
        case.reject();
        let mut case = Case::new(StackOperation::Return);
        case.actual.states[index].mask ^= 1;
        case.reject();
    }
    for axis in 0..7 {
        let mut case = Case::new(StackOperation::Return);
        match axis {
            0 => case.actual.trace.ordinal = 4,
            1 => case.actual.trace.tid += 1,
            2 => case.actual.trace.status = (libc::SIGTRAP << 8) | 0x7f | (1 << 16),
            3 => case.actual.trace.dr6 ^= 1,
            4 => case.actual.trace.signal[4] = 1,
            5 => case.actual.trace.signal[8] = 0,
            6 => case.actual.trace.signal[16] ^= 1,
            _ => unreachable!(),
        }
        case.reject();
    }
}
#[test]
fn stack_census_requires_each_word_capture_and_its_exact_phase_association() {
    for index in 0..4 {
        let mut case = Case::new(StackOperation::Return);
        case.actual.captures[index].complete = false;
        case.reject();
        let mut case = Case::new(StackOperation::Return);
        case.actual.captures[index].association = None;
        case.reject();
        let mut case = Case::new(StackOperation::Return);
        case.actual.captures[index].first_failure = Some((
            super::super::super::runtime_stack_native::acquire::StackCaptureStage::State,
            super::super::super::runtime_stack_native::acquire::StackCaptureFailure::Unwound,
        ));
        case.reject();

        let mut case = Case::new(StackOperation::Return);
        case.actual.captures[index].association = Some(StackCaptureAssociation::D {
            stop: case.actual.stops[7].clone(),
            until: case.actual.binding.until,
        });
        if index != 3 {
            case.reject();
        }
    }
    let mut case = Case::new(StackOperation::Return);
    case.actual.captures[2].association = Some(StackCaptureAssociation::FailedHeld {
        original: case.actual.stops[3].clone(),
        raw_wait: (case.actual.trace.tid, case.actual.trace.status),
        ordinal: 3,
        until: case.actual.binding.until,
    });
    case.reject();
}
#[test]
fn stack_census_rejects_pagemap_descriptor_and_independent_query_corruption() {
    for index in 0..4 {
        let mut case = Case::new(StackOperation::Return);
        case.actual.captures[index].word.pagemap.fd += 1;
        case.reject();
        let mut case = Case::new(StackOperation::Return);
        case.actual.captures[index]
            .observation
            .state
            .returned_pointer += 8;
        case.reject();
        let mut case = Case::new(StackOperation::Return);
        case.actual.captures[index].observation.state.xstate_request = None;
        case.reject();
        let mut case = Case::new(StackOperation::Return);
        case.actual.captures[index].word.pagemap.bytes[7] &= 0x7f;
        case.reject();
        let mut case = Case::new(StackOperation::Return);
        case.actual.captures[index].word.peek[0]
            .as_mut()
            .unwrap()
            .request
            .errno = Some(libc::EIO);
        case.reject();
    }
}
#[test]
fn stack_census_rejects_changed_stack_word_neighbor_or_opened_extra_page() {
    for operation in [StackOperation::DirectCall, StackOperation::Return] {
        for index in 0..4 {
            let mut case = Case::new(operation);
            case.actual.captures[index].word.bytes[0] ^= 1;
            case.reject();
        }
    }
    let mut case = Case::new(StackOperation::DirectCall);
    case.actual.opened = String::from_utf8(case.actual.opened.clone())
        .unwrap()
        .replace("00401000-00402000 r--p", "00401000-00402000 r-xp")
        .into_bytes();
    case.reject();
    let mut case = Case::new(StackOperation::Return);
    case.actual.captures[3].observation.maps[0] = b'1';
    case.reject();
}
#[test]
fn stack_census_unproven_orig_rax_deadline_and_capacity_refusals_keep_prefix() {
    let mut case = Case::new(StackOperation::Return);
    case.census.state.origins[0].current.registers.orig_rax = 39;
    case.reject();
    let mut case = Case::new(StackOperation::Return);
    case.actual.states[4].registers.orig_rax = 39;
    case.reject();
    let mut case = Case::new(StackOperation::Return);
    case.prepared.binding.as_mut().unwrap().until = Instant::now();
    case.reject();
    let mut case = Case::new(StackOperation::Return);
    case.prepared.settled_bytes -= 1;
    case.reject();
    let mut case = Case::new(StackOperation::Return);
    case.prepared.mark_aborted();
    case.reject();
}
