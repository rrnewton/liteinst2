//! Supplied-data controls only. No native permit, successful completion seal,
//! RecordedCall or real task is constructed. The actual safe storage/copy and
//! descriptive Eq projections are exercised independently of native acquisition.
use super::super::tests::model::{Model, seeded};
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

const PANIC: u32 = 0x4f42_5331;
#[derive(Clone, Copy)]
pub(super) struct Fault {
    pub(super) before: Option<usize>,
    pub(super) after: Option<usize>,
}
pub(super) fn before(fault: Option<Fault>, index: usize) -> Result<(), CensusConsumerError> {
    if fault.is_some_and(|f| f.before == Some(index)) {
        Err(CensusConsumerError::Allocation)
    } else {
        Ok(())
    }
}
pub(super) fn after(fault: Option<Fault>, index: usize) {
    if fault.is_some_and(|f| f.after == Some(index)) {
        std::panic::panic_any(PANIC);
    }
}
fn supplied_state() -> ObservedStop {
    let (census, origin) = seeded();
    let mut state = census.current_observation(origin).unwrap().clone();
    let mut bytes = exact_storage::empty_bytes(MAX_XSTATE_BYTES).unwrap();
    bytes.extend_from_slice(&state.xstate);
    state.xstate = bytes;
    state
}
fn allocations(out: &PreparedStackObservation) -> [BufferIdentity; STATES] {
    std::array::from_fn(|i| BufferIdentity::of(&out.buffers[i]))
}
fn check_prefix(out: &PreparedStackObservation, count: usize) {
    assert_eq!(out.allocation.filled, count);
    assert_eq!(out.payload, count * MAX_XSTATE_BYTES);
    assert_eq!(
        out.allocated_bytes().unwrap(),
        size_of::<PreparedStackObservation>() + count * MAX_XSTATE_BYTES
    );
    for (i, buffer) in out.buffers.iter().enumerate() {
        assert!(buffer.is_empty());
        assert_eq!(
            buffer.capacity(),
            if i < count { MAX_XSTATE_BYTES } else { 0 }
        );
        assert!(out.states[i].is_none());
    }
}
#[test]
fn consumer_observer_stack_storage_exact_shape_and_reuse() {
    let mut out = PreparedStackObservation::empty();
    assert_eq!(
        out.allocated_bytes().unwrap(),
        size_of::<PreparedStackObservation>()
    );
    assert_eq!(
        PreparedStackObservation::reservation_bytes().unwrap(),
        size_of::<PreparedStackObservation>() + 16 * 65536
    );
    out.allocate_payloads().unwrap();
    check_prefix(&out, 16);
    assert!(out.allocation.complete);
    assert!(!out.capture.started);
    let addresses = allocations(&out);
    let progress = out.allocation;
    assert_eq!(out.allocate_payloads(), Err(CensusConsumerError::Reused));
    out.mark_aborted();
    assert_eq!(out.allocation, progress);
    assert_eq!(allocations(&out), addresses);
    assert_eq!(out.capture, ConsumerProgress::default());
}
#[test]
fn consumer_observer_stack_allocation_error_prefixes() {
    for index in 0..16 {
        let mut out = PreparedStackObservation::empty();
        out.allocation_fault = Some(Fault {
            before: Some(index),
            after: None,
        });
        assert_eq!(
            out.allocate_payloads(),
            Err(CensusConsumerError::Allocation)
        );
        check_prefix(&out, index);
        assert!(!out.allocation.complete);
        assert_eq!(
            out.allocation.first_failure,
            Some(CensusConsumerError::Allocation)
        );
        let addresses = allocations(&out);
        let progress = out.allocation;
        out.mark_aborted();
        assert_eq!(out.allocate_payloads(), Err(CensusConsumerError::Reused));
        assert_eq!(out.allocation, progress);
        assert_eq!(allocations(&out), addresses);
        check_prefix(&out, index);
    }
}
#[test]
fn consumer_observer_stack_allocation_unwind_prefixes() {
    for index in 0..16 {
        let mut out = PreparedStackObservation::empty();
        out.allocation_fault = Some(Fault {
            before: None,
            after: Some(index),
        });
        let panic = catch_unwind(AssertUnwindSafe(|| out.allocate_payloads())).unwrap_err();
        assert_eq!(*panic.downcast::<u32>().unwrap(), PANIC);
        check_prefix(&out, index + 1);
        assert!(!out.allocation.complete);
        let addresses = allocations(&out);
        out.mark_aborted();
        let progress = out.allocation;
        assert_eq!(progress.first_failure, Some(CensusConsumerError::Aborted));
        out.allocation.fail(CensusConsumerError::Mismatch);
        assert_eq!(out.allocate_payloads(), Err(CensusConsumerError::Reused));
        assert_eq!(out.allocation, progress);
        assert_eq!(allocations(&out), addresses);
    }
}
#[test]
fn consumer_observer_stack_copy_preserves_full_state_and_allocation_identity() {
    let mut source = supplied_state();
    let mut out = PreparedStackObservation::empty();
    out.allocate_payloads().unwrap();
    out.capture.begin().unwrap();
    let destination = allocations(&out);
    for (i, expected) in destination.iter().enumerate() {
        out.copy(i, &source).unwrap();
        assert_eq!(out.states[i].as_ref(), Some(&source));
        assert_eq!(
            out.states[i].as_ref().unwrap().xstate.as_ptr() as usize,
            expected.pointer
        );
        assert_eq!(
            out.states[i].as_ref().unwrap().xstate.capacity(),
            MAX_XSTATE_BYTES
        );
        assert_eq!(out.buffers[i].capacity(), 0);
        assert_eq!(
            out.actual_allocations[i],
            Some(BufferIdentity::of(&source.xstate))
        );
        out.matches(i, &source).unwrap();
    }
    assert_eq!(out.capture.filled, 16);
    assert!(!out.capture.complete); // copying data is not actual seven-row validation
    assert_eq!(
        out.allocated_bytes().unwrap(),
        PreparedStackObservation::reservation_bytes().unwrap()
    );
    type Mutation = fn(&mut ObservedStop);
    let changes: [Mutation; 9] = [
        |v| v.token.sequence ^= 1,
        |v| v.task.generation ^= 1,
        |v| v.logical_pc ^= 1,
        |v| v.registers.rax ^= 1,
        |v| v.signal_mask ^= 1,
        |v| v.xstate[0] ^= 1,
        |v| v.token.tid ^= 1,
        |v| {
            v.phase = if v.phase == StopPhase::UserCheckpoint {
                StopPhase::OriginalSignal
            } else {
                StopPhase::UserCheckpoint
            }
        },
        |v| {
            v.signal = if v.signal.is_none() {
                Some(DynamicSignalInfo { raw: [0; 128] })
            } else {
                None
            }
        },
    ];
    for change in changes {
        let pointer = source.xstate.as_ptr();
        change(&mut source);
        assert_eq!(out.matches(0, &source), Err(CensusConsumerError::Mismatch));
        assert_eq!(source.xstate.as_ptr(), pointer);
        change(&mut source);
        out.matches(0, &source).unwrap();
    }
    let source_bytes = source.xstate.clone();
    let mut replacement = exact_storage::empty_bytes(MAX_XSTATE_BYTES).unwrap();
    replacement.extend_from_slice(&source_bytes);
    let old = std::mem::replace(&mut source.xstate, replacement);
    assert_eq!(source, *out.states[0].as_ref().unwrap());
    assert_eq!(out.matches(0, &source), Err(CensusConsumerError::Mismatch));
    source.xstate = old;
    out.matches(0, &source).unwrap();
}
#[test]
fn consumer_observer_stack_copy_refuses_malformed_or_reused_owner() {
    for length in [575, MAX_XSTATE_BYTES] {
        let mut source = supplied_state();
        source.xstate.resize(length, 0);
        let mut destination = None;
        let mut buffer = exact_storage::empty_bytes(MAX_XSTATE_BYTES).unwrap();
        let allocation = BufferIdentity::of(&buffer);
        assert_eq!(
            copy_state(&source, &mut destination, &mut buffer),
            Err(CensusConsumerError::Mismatch)
        );
        assert!(destination.is_none());
        assert_eq!(BufferIdentity::of(&buffer), allocation);
    }
    let source = supplied_state();
    let mut destination = None;
    let mut wrong = exact_storage::empty_bytes(MAX_XSTATE_BYTES - 1).unwrap();
    let allocation = BufferIdentity::of(&wrong);
    assert_eq!(
        copy_state(&source, &mut destination, &mut wrong),
        Err(CensusConsumerError::Mismatch)
    );
    assert_eq!(BufferIdentity::of(&wrong), allocation);
    let mut buffer = exact_storage::empty_bytes(MAX_XSTATE_BYTES).unwrap();
    copy_state(&source, &mut destination, &mut buffer).unwrap();
    let stored = destination.as_ref().unwrap().clone();
    let allocation = BufferIdentity::of(&destination.as_ref().unwrap().xstate);
    assert_eq!(
        copy_state(&source, &mut destination, &mut buffer),
        Err(CensusConsumerError::Mismatch)
    );
    assert_eq!(destination.as_ref(), Some(&stored));
    assert_eq!(
        BufferIdentity::of(&destination.as_ref().unwrap().xstate),
        allocation
    );
    let extra = exact_storage::empty_bytes(MAX_XSTATE_BYTES).unwrap();
    assert_eq!(
        state_bytes(&destination, &extra),
        Err(CensusConsumerError::Mismatch)
    );
    assert_eq!(state_bytes(&destination, &buffer), Ok(MAX_XSTATE_BYTES));
}
#[test]
fn consumer_observer_stack_partial_view_compares_every_owned_family() {
    let (mut census, origin) = seeded();
    let reservation = census.reserve(BudgetCharge::default()).unwrap();
    let model = Model::new(&census, reservation, origin, StackOperation::DirectCall);
    let mut out = PreparedStackObservation::empty();
    out.allocate_payloads().unwrap();
    out.census = Some(CensusHeader::of(&census));
    out.start = Some(3);
    out.rows = [Some(RowHeader {
        kind: RowKind::Refresh,
        origin,
    }); 7];
    out.evidence = Some(StackEvidence {
        binding: Some(model.binding.clone()),
        trace: Some(model.view().trace),
        words: Some([[3; 16]; 4]),
        call: None,
    });
    out.evidence_allocation = Some((17, 1));
    out.old_origin = Some(OriginHeader::of(&census.state.origins[0]));
    out.new_origin = out.old_origin;
    out.old_current_allocation = Some(BufferIdentity::of(&census.state.origins[0].current.xstate));
    let source = supplied_state();
    out.copy(0, &source).unwrap();
    let v = out.partial_view();
    assert_eq!(v.address, std::ptr::from_ref(&out) as usize);
    assert_eq!(v.census, out.census.as_ref());
    assert_eq!(v.states, &out.states);
    assert_eq!(v.buffers, &out.buffers);
    assert_eq!(v.rows, &out.rows);
    assert_eq!(v.actual_allocations, &out.actual_allocations);
    assert_eq!(
        v.copied_allocations[0],
        Some(BufferIdentity::of(&out.states[0].as_ref().unwrap().xstate))
    );
    assert_eq!(
        v.evidence.as_ref().unwrap().binding,
        out.evidence
            .as_ref()
            .unwrap()
            .binding
            .as_ref()
            .map(ConsumerBindingView::of)
    );
    macro_rules! changed {
        ($body:expr) => {{
            let mut changed = out.partial_view();
            ($body)(&mut changed);
            assert_ne!(out.partial_view(), changed);
        }};
    }
    changed!(|v: &mut StackPartialView<'_>| v.address ^= 1);
    changed!(|v: &mut StackPartialView<'_>| v.payload ^= 1);
    changed!(|v: &mut StackPartialView<'_>| v.start = Some(4));
    changed!(|v: &mut StackPartialView<'_>| v.evidence_allocation = Some((18, 1)));
    changed!(
        |v: &mut StackPartialView<'_>| v.old_current_allocation.as_mut().unwrap().pointer ^= 1
    );
    changed!(|v: &mut StackPartialView<'_>| v.copied_allocations[0].as_mut().unwrap().length ^= 1);
    changed!(|v: &mut StackPartialView<'_>| v.buffer_allocations[1].capacity ^= 1);
    changed!(|v: &mut StackPartialView<'_>| v
        .evidence
        .as_mut()
        .unwrap()
        .trace
        .as_mut()
        .unwrap()
        .dr6 ^= 1);
    changed!(|v: &mut StackPartialView<'_>| v
        .evidence
        .as_mut()
        .unwrap()
        .binding
        .as_mut()
        .unwrap()
        .candidate_serial ^= 1);
    let mut header = out.census.unwrap();
    type Change = fn(&mut CensusHeader);
    let changes: &[Change] = &[
        |v| v.identity ^= 1,
        |v| v.session ^= 1,
        |v| v.generation ^= 1,
        |v| v.next_serial ^= 1,
        |v| v.origins_pointer ^= 1,
        |v| v.origins_length ^= 1,
        |v| v.origins_capacity ^= 1,
        |v| v.history_pointer ^= 1,
        |v| v.history_length ^= 1,
        |v| v.history_capacity ^= 1,
        |v| v.limits.epochs ^= 1,
        |v| v.limits.source_fact_bytes ^= 1,
        |v| v.limits.reports ^= 1,
        |v| v.limits.origins ^= 1,
        |v| v.limits.witnesses ^= 1,
        |v| v.limits.plan_history ^= 1,
        |v| v.used.epochs ^= 1,
        |v| v.used.source_fact_bytes ^= 1,
        |v| v.used.reports ^= 1,
        |v| v.used.origins ^= 1,
        |v| v.used.witnesses ^= 1,
        |v| v.used.plan_history ^= 1,
        |v| v.charged.origins ^= 1,
        |v| v.charged.witnesses ^= 1,
        |v| v.charged.source_fact_bytes ^= 1,
        |v| v.charged.epochs ^= 1,
        |v| v.charged.reports ^= 1,
        |v| v.charged.plan_history ^= 1,
        |v| v.reservation.as_mut().unwrap().0.serial ^= 1,
        |v| v.reservation.as_mut().unwrap().0.census ^= 1,
        |v| v.reservation.as_mut().unwrap().1.epochs ^= 1,
        |v| v.reservation.as_mut().unwrap().1.source_fact_bytes ^= 1,
        |v| v.reservation.as_mut().unwrap().1.reports ^= 1,
        |v| v.reservation.as_mut().unwrap().1.origins ^= 1,
        |v| v.reservation.as_mut().unwrap().1.witnesses ^= 1,
        |v| v.reservation.as_mut().unwrap().1.plan_history ^= 1,
    ];
    for change in changes {
        change(&mut header);
        let mut changed = out.partial_view();
        changed.census = Some(&header);
        assert_ne!(out.partial_view(), changed);
        change(&mut header);
        assert_eq!(out.census, Some(header));
    }
    let (other, _) = seeded();
    let mut foreign = out.census.unwrap();
    foreign.space = other.space;
    assert_ne!(foreign.space, out.census.unwrap().space);
    let mut changed = out.partial_view();
    changed.census = Some(&foreign);
    assert_ne!(out.partial_view(), changed);
    let mut rows = out.rows;
    rows[6].as_mut().unwrap().kind = RowKind::Consumption;
    let mut changed = out.partial_view();
    changed.rows = &rows;
    assert_ne!(out.partial_view(), changed);
    rows = out.rows;
    rows[0].as_mut().unwrap().origin.serial ^= 1;
    let mut changed = out.partial_view();
    changed.rows = &rows;
    assert_ne!(out.partial_view(), changed);
    let origin_header = out.old_origin.unwrap();
    let mut changed_id = origin_header.id;
    changed_id.serial ^= 1;
    for changed_origin in [
        OriginHeader {
            id: changed_id,
            ..origin_header
        },
        OriginHeader {
            pc: origin_header.pc ^ 1,
            ..origin_header
        },
        OriginHeader {
            generation: origin_header.generation ^ 1,
            ..origin_header
        },
        OriginHeader {
            frame_absent: false,
            ..origin_header
        },
        OriginHeader {
            kind: OriginKind::ParentSyscallReturn { syscall: 39 },
            ..origin_header
        },
        OriginHeader {
            kernel: Some((origin, None)),
            ..origin_header
        },
    ] {
        let mut changed = out.partial_view();
        changed.old_origin = Some(&changed_origin);
        assert_ne!(out.partial_view(), changed);
        let mut changed = out.partial_view();
        changed.new_origin = Some(&changed_origin);
        assert_ne!(out.partial_view(), changed);
    }
    let mut capture = out.capture;
    capture.first_failure = Some(CensusConsumerError::Aborted);
    let mut changed = out.partial_view();
    changed.capture = &capture;
    assert_ne!(out.partial_view(), changed);
    let mut allocation = out.allocation;
    allocation.complete = false;
    let mut changed = out.partial_view();
    changed.allocation = &allocation;
    assert_ne!(out.partial_view(), changed);
    let mut actual_allocations = out.actual_allocations;
    actual_allocations[0].as_mut().unwrap().capacity ^= 1;
    let mut changed = out.partial_view();
    changed.actual_allocations = &actual_allocations;
    assert_ne!(out.partial_view(), changed);
    let mut states = out.states.clone();
    let mut changed = out.partial_view();
    changed.states = &states;
    assert_eq!(out.partial_view(), changed);
    states[0].as_mut().unwrap().xstate[7] ^= 1;
    let mut changed = out.partial_view();
    changed.states = &states;
    assert_ne!(out.partial_view(), changed);
    let mut words = [[3; 16]; 4];
    words[3][15] ^= 1;
    let mut changed = out.partial_view();
    changed.evidence.as_mut().unwrap().words = Some(&words);
    assert_ne!(out.partial_view(), changed);
    assert!(!out.capture.complete);
}
#[test]
fn consumer_observer_progress_preserves_original_failure_and_complete_records() {
    let mut p = ConsumerProgress::default();
    assert_eq!(p.require_complete(), Err(CensusConsumerError::Incomplete));
    p.begin().unwrap();
    p.filled = 4;
    p.fail(CensusConsumerError::Mismatch);
    let first = p;
    p.abort();
    p.fail(CensusConsumerError::Capacity);
    assert_eq!(p, first);
    assert_eq!(p.begin(), Err(CensusConsumerError::Reused));
    let mut complete = ConsumerProgress::default();
    complete.begin().unwrap();
    complete.filled = 16;
    complete.complete = true;
    complete.require_complete().unwrap();
    let before = complete;
    complete.abort();
    assert_eq!(complete, before);
    complete.require_complete().unwrap();
}
