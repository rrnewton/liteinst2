//! Allocation and immutable-ledger models only. These records cannot create an
//! actual operand permit, owned completion, source authority or native release.
use super::super::super::runtime_capture::SourceWindowId;
use super::super::runtime_stack::binding::SourceRecord;
use super::super::runtime_stack::tests::model::{Model, limits, seeded};
use super::*;
use liteinst_admission::scan::Snapshot;
use std::panic::{AssertUnwindSafe, catch_unwind};

struct Case {
    census: ResumeCensus,
    reservation: Reservation,
    actual: Model,
    calls: RuntimeCallLedger,
    pending: Option<Box<PreparedCallRecord>>,
}
impl Case {
    fn new() -> Self {
        let (mut census, origin) = seeded();
        let reservation = census
            .reserve(BudgetCharge {
                source_fact_bytes: PreparedCallRecord::reservation_bytes().unwrap(),
                ..BudgetCharge::default()
            })
            .unwrap();
        let actual = Model::new(&census, reservation, origin, StackOperation::DirectCall);
        let mut calls = RuntimeCallLedger::empty();
        calls.allocate_payloads(limits().origins).unwrap();
        let mut record = exact_storage::value(PreparedCallRecord::empty()).unwrap();
        record.allocate_payloads().unwrap();
        record.settle_storage(&mut census, reservation).unwrap();
        calls
            .prepare_model(&census, actual.binding.clone(), &mut record)
            .unwrap();
        Self {
            census,
            reservation,
            actual,
            calls,
            pending: Some(record),
        }
    }
    fn reject_append(&mut self) {
        let state = self.census.state.clone();
        let slots = self.calls.slots.as_ref().unwrap().as_ptr();
        let bytes = self.calls.allocated_bytes().unwrap();
        let before = self.pending.as_ref().unwrap();
        let owner = std::ptr::from_ref::<PreparedCallRecord>(before);
        let binding = before.binding.clone();
        let observed = before.before.clone();
        let buffer = before.before.as_ref().unwrap().xstate.as_ptr();
        assert!(
            self.calls
                .append_model(&self.census, &mut self.pending)
                .is_err()
        );
        let after = self.pending.as_ref().unwrap();
        assert_eq!(std::ptr::from_ref::<PreparedCallRecord>(after), owner);
        assert_eq!(after.binding, binding);
        assert_eq!(after.before, observed);
        assert_eq!(after.before.as_ref().unwrap().xstate.as_ptr(), buffer);
        assert_eq!(self.calls.slots.as_ref().unwrap().as_ptr(), slots);
        assert_eq!(self.calls.allocated_bytes().unwrap(), bytes);
        assert_eq!(self.calls.count, 0);
        assert_eq!(self.census.state, state);
    }
}

#[test]
fn stack_calls_fixed_slots_and_full_record_are_prepaid_once() {
    let mut calls = RuntimeCallLedger::empty();
    assert_eq!(
        calls.allocated_bytes().unwrap(),
        size_of::<RuntimeCallLedger>()
    );
    assert_eq!(
        RuntimeCallLedger::reservation_bytes(0),
        Err(CensusError::Capacity)
    );
    assert_eq!(
        RuntimeCallLedger::reservation_bytes(usize::MAX),
        Err(CensusError::Capacity)
    );
    calls.allocate_payloads(2).unwrap();
    assert_eq!(
        calls.allocated_bytes().unwrap(),
        RuntimeCallLedger::reservation_bytes(2).unwrap()
    );
    assert_eq!(calls.slots.as_ref().unwrap().len(), 2);
    assert!(calls.slots.as_ref().unwrap().iter().all(Option::is_none));
    let pointer = calls.slots.as_ref().unwrap().as_ptr();
    assert!(calls.allocate_payloads(2).is_err());
    assert_eq!(calls.slots.as_ref().unwrap().as_ptr(), pointer);
    let case = Case::new();
    let record = case.pending.as_ref().unwrap();
    assert_eq!(
        record.allocated_bytes().unwrap(),
        size_of::<PreparedCallRecord>() + MAX_XSTATE_BYTES
    );
    assert_eq!(
        record.settled_bytes,
        PreparedCallRecord::reservation_bytes().unwrap()
    );
    assert_eq!(
        record.before.as_ref().unwrap().xstate.capacity(),
        MAX_XSTATE_BYTES
    );
    assert_eq!(record.buffer.capacity(), 0);
}

#[test]
fn stack_calls_record_error_and_unwind_keep_allocated_prefix_and_charge() {
    for unwind in [false, true] {
        let (mut census, _) = seeded();
        let reservation = census
            .reserve(BudgetCharge {
                source_fact_bytes: PreparedCallRecord::reservation_bytes().unwrap(),
                ..BudgetCharge::default()
            })
            .unwrap();
        let charged = census.state.charged;
        let prior = census.state.used.source_fact_bytes;
        let mut record = exact_storage::value(PreparedCallRecord::empty()).unwrap();
        if unwind {
            let panic = catch_unwind(AssertUnwindSafe(|| {
                record.allocate_with(|| Ok(()), || std::panic::panic_any(0x71_u32))
            }));
            assert_eq!(*panic.unwrap_err().downcast::<u32>().unwrap(), 0x71);
            record.mark_aborted();
            assert_eq!(record.buffer.capacity(), MAX_XSTATE_BYTES);
        } else {
            assert_eq!(
                record.allocate_with(|| Err(CensusError::Allocation), || {}),
                Err(CensusError::Allocation)
            );
            assert_eq!(record.buffer.capacity(), 0);
        }
        let bytes = record.allocated_bytes().unwrap();
        record.settle_storage(&mut census, reservation).unwrap();
        assert_eq!(census.state.used.source_fact_bytes, prior + bytes);
        record.settle_storage(&mut census, reservation).unwrap();
        assert_eq!(census.state.used.source_fact_bytes, prior + bytes);
        assert_eq!(census.state.charged, charged);
        assert!(record.allocate_payloads().is_err());
        assert!(record.require_empty_allocated().is_err());
    }
}

#[test]
fn stack_calls_append_moves_exact_owner_before_any_completion() {
    let mut case = Case::new();
    let pointer = std::ptr::from_ref::<PreparedCallRecord>(case.pending.as_ref().unwrap());
    let state_pointer = case
        .pending
        .as_ref()
        .unwrap()
        .before
        .as_ref()
        .unwrap()
        .xstate
        .as_ptr();
    let combined = case.calls.allocated_bytes().unwrap()
        + case.pending.as_ref().unwrap().allocated_bytes().unwrap();
    let state = case.census.state.clone();
    let recorded = case
        .calls
        .append_model(&case.census, &mut case.pending)
        .unwrap();
    let id = recorded.id();
    assert_eq!(std::ptr::from_ref(recorded.row), pointer);
    assert_eq!(
        recorded.row.before.as_ref().unwrap().xstate.as_ptr(),
        state_pointer
    );
    assert!(case.pending.is_none());
    assert_eq!(case.calls.count, 1);
    assert_eq!(case.calls.allocated_bytes().unwrap(), combined);
    assert_eq!(case.census.state, state);
    assert!(case.census.state.history.is_empty());
    case.calls
        .require_completed_call(
            Some(id),
            &case.actual.binding,
            case.census
                .current_observation(case.actual.binding.origin)
                .unwrap(),
        )
        .unwrap();
    assert!(
        case.calls
            .append_model(&case.census, &mut case.pending)
            .is_err()
    );
    assert_eq!(case.calls.count, 1);
    assert_eq!(case.census.state, state);
}

#[test]
fn stack_calls_reject_stale_or_foreign_append_without_taking_record() {
    for axis in 0..7 {
        let mut case = Case::new();
        let record = case.pending.as_mut().unwrap();
        match axis {
            0 => record.binding.as_mut().unwrap().census += 1,
            1 => record.binding.as_mut().unwrap().candidate_serial += 1,
            2 => record.before.as_mut().unwrap().xstate[700] ^= 1,
            3 => record.before.as_mut().unwrap().token.sequence += 1,
            4 => record.settled_bytes -= 1,
            5 => record.binding.as_mut().unwrap().until = Instant::now(),
            6 => record.mark_aborted(),
            _ => unreachable!(),
        }
        case.reject_append();
    }
    let mut case = Case::new();
    let state = case.census.state.clone();
    let record = case.pending.as_mut().unwrap();
    assert!(
        record
            .settle_storage(
                &mut case.census,
                Reservation {
                    census: case.reservation.census + 1,
                    serial: case.reservation.serial,
                }
            )
            .is_err()
    );
    assert_eq!(case.census.state, state);
}

#[test]
fn stack_calls_source_identity_keeps_full_window_and_boundary_return() {
    let case = Case::new();
    let binding = &case.actual.binding;
    let snapshot = &case.actual.snapshot;
    assert_eq!(binding.operand.geometry.next_pc, 0x401000);
    assert_eq!(binding.fetch.pages().end(), 0x401000);
    assert_eq!(binding.source.range, snapshot.range());
    assert_eq!(snapshot.bytes().len(), 8192);
    binding
        .source
        .require_snapshot(
            binding.source,
            snapshot,
            &binding.operand.geometry,
            &binding.fetch,
        )
        .unwrap();
    let copied = Snapshot::new(
        snapshot.mapping,
        snapshot.generation,
        snapshot.range().start(),
        snapshot.bytes().to_vec(),
        snapshot.before,
        snapshot.after,
        snapshot.writes,
    )
    .unwrap();
    let projection = SourceRecord::from_parts(
        binding.source.id,
        binding.source.initial,
        binding.source.target,
        &copied,
    );
    assert!(
        binding
            .source
            .require_snapshot(
                projection,
                &copied,
                &binding.operand.geometry,
                &binding.fetch
            )
            .is_err()
    );
    for axis in 0..3 {
        let mut changed = binding.source;
        match axis {
            0 => {
                changed.target =
                    AddressRange::new(binding.operand.geometry.next_pc, 0x402000).unwrap()
            }
            1 => changed.range = AddressRange::new(0x400000, 0x401000).unwrap(),
            2 => {
                changed.id = SourceWindowId::synthetic_for_test(
                    changed.id.identity(),
                    changed.id.index() + 1,
                )
            }
            _ => unreachable!(),
        }
        assert!(
            binding
                .source
                .require_snapshot(changed, snapshot, &binding.operand.geometry, &binding.fetch)
                .is_err()
        );
    }
}

#[test]
fn stack_calls_ret_and_expired_history_never_remove_or_refund() {
    let mut case = Case::new();
    let id = case
        .calls
        .append_model(&case.census, &mut case.pending)
        .unwrap()
        .id();
    let bytes = case.calls.allocated_bytes().unwrap();
    let state = case.census.state.clone();
    let ret = Model::new(
        &case.census,
        case.reservation,
        case.actual.binding.origin,
        StackOperation::Return,
    );
    case.calls
        .require_completed_call(
            None,
            &ret.binding,
            case.census.current_observation(ret.binding.origin).unwrap(),
        )
        .unwrap();
    assert!(
        case.calls
            .require_completed_call(
                Some(id),
                &ret.binding,
                case.census.current_observation(ret.binding.origin).unwrap()
            )
            .is_err()
    );
    assert_eq!(case.calls.count, 1);
    let record = case.calls.slots.as_mut().unwrap()[0].as_mut().unwrap();
    let until = Instant::now();
    record.binding.as_mut().unwrap().until = until;
    record.binding.as_mut().unwrap().operand.until = until;
    case.calls
        .require_record(0, case.calls.slots.as_ref().unwrap()[0].as_ref().unwrap())
        .unwrap();
    assert_eq!(case.calls.count, 1);
    assert_eq!(case.calls.allocated_bytes().unwrap(), bytes);
    assert_eq!(case.census.state, state);
}
