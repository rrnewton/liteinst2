//! Supplied-record mirror controls only; no live task, seal or cleanup fact.
use super::super::super::tests::model::{Model, seeded};
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};
const PANIC: u32 = 0x5052_5331;
#[derive(Clone, Copy)]
pub(super) struct Fault {
    pub(super) before: Option<usize>,
    pub(super) after: Option<usize>,
}
pub(super) fn before(fault: Option<Fault>, index: usize) -> Result<(), CensusConsumerError> {
    if fault.is_some_and(|value| value.before == Some(index)) {
        Err(CensusConsumerError::Allocation)
    } else {
        Ok(())
    }
}
pub(super) fn after(fault: Option<Fault>, index: usize) {
    if fault.is_some_and(|value| value.after == Some(index)) {
        std::panic::panic_any(PANIC);
    }
}
fn source() -> PreparedStackObservation {
    let (mut census, origin) = seeded();
    let reservation = census.reserve(BudgetCharge::default()).unwrap();
    let model = Model::new(&census, reservation, origin, StackOperation::DirectCall);
    let mut out = PreparedStackObservation::empty();
    out.allocate_payloads().unwrap();
    out.census = Some(CensusHeader::of(&census));
    out.start = Some(2);
    out.rows = [Some(RowHeader {
        kind: RowKind::Refresh,
        origin,
    }); 7];
    out.evidence = Some(StackEvidence {
        binding: Some(model.binding.clone()),
        trace: Some(model.view().trace),
        words: Some([[9; 16]; 4]),
        call: None,
    });
    out.evidence_allocation = Some((19, 1));
    out.old_origin = Some(OriginHeader::of(&census.state.origins[0]));
    out.new_origin = out.old_origin;
    out.old_current_allocation = Some(BufferIdentity::of(&census.state.origins[0].current.xstate));
    let mut observed = census.current_observation(origin).unwrap().clone();
    let mut bytes = exact_storage::empty_bytes(MAX_XSTATE_BYTES).unwrap();
    bytes.extend_from_slice(&observed.xstate);
    observed.xstate = bytes;
    out.capture.begin().unwrap();
    out.copy(0, &observed).unwrap();
    // Diagnostic initialized buffer prefix and original first failure. This
    // supplied specimen never passes the real seven-transition copy function.
    out.buffers[1].extend_from_slice(&[1, 2, 3]);
    out.capture.fail(CensusConsumerError::Mismatch);
    out
}
fn mirror(source: &PreparedStackObservation) -> PreparedStackPrefixMirror {
    let mut out = PreparedStackPrefixMirror::empty();
    out.allocate_payloads().unwrap();
    out.capture(source).unwrap();
    out
}
#[test]
fn consumer_stack_prefix_mirror_retains_every_allocation_error_and_unwind_prefix() {
    assert_eq!(
        PreparedStackPrefixMirror::reservation_bytes().unwrap(),
        size_of::<PreparedStackPrefixMirror>() + 16 * 65536
    );
    for index in 0..16 {
        for unwind in [false, true] {
            let mut out = PreparedStackPrefixMirror::empty();
            out.allocation_fault = Some(Fault {
                before: (!unwind).then_some(index),
                after: unwind.then_some(index),
            });
            if unwind {
                let payload =
                    catch_unwind(AssertUnwindSafe(|| out.allocate_payloads())).unwrap_err();
                assert_eq!(*payload.downcast::<u32>().unwrap(), PANIC);
            } else {
                assert_eq!(
                    out.allocate_payloads(),
                    Err(CensusConsumerError::Allocation)
                );
            }
            let count = index + usize::from(unwind);
            assert_eq!(out.allocation.filled, count);
            assert!(!out.allocation.complete);
            assert_eq!(
                out.allocated_bytes().unwrap(),
                size_of::<PreparedStackPrefixMirror>() + count * MAX_XSTATE_BYTES
            );
            let pointers = std::array::from_fn::<_, 16, _>(|i| out.states[i].identity());
            for (i, id) in pointers.iter().enumerate() {
                assert_eq!(id.capacity, if i < count { MAX_XSTATE_BYTES } else { 0 });
                assert_eq!(id.length, 0);
            }
            out.mark_aborted();
            let first = out.allocation;
            assert_eq!(
                first.first_failure,
                Some(if unwind {
                    CensusConsumerError::Aborted
                } else {
                    CensusConsumerError::Allocation
                })
            );
            out.allocation.fail(CensusConsumerError::Capacity);
            assert_eq!(out.allocate_payloads(), Err(CensusConsumerError::Reused));
            assert_eq!(out.allocation, first);
            assert_eq!(
                std::array::from_fn::<_, 16, _>(|i| out.states[i].identity()),
                pointers
            );
        }
    }
}
#[test]
fn consumer_stack_prefix_mirror_checks_full_failed_header_families() {
    let mut source = source();
    let out = mirror(&source);
    assert!(!source.capture.complete);
    assert_eq!(
        source.capture.first_failure,
        Some(CensusConsumerError::Mismatch)
    );
    out.require_preserved(&source).unwrap();
    macro_rules! changed {
        ($field:expr, $value:expr) => {{
            let old = $field;
            $field = $value;
            assert_eq!(
                out.require_preserved(&source),
                Err(CensusConsumerError::Mismatch)
            );
            $field = old;
            out.require_preserved(&source).unwrap();
        }};
    }
    changed!(source.allocation.filled, 15);
    changed!(
        source.capture.first_failure,
        Some(CensusConsumerError::Aborted)
    );
    changed!(source.capture.complete, true);
    changed!(source.payload, source.payload + 1);
    changed!(source.census.as_mut().unwrap().identity, 0);
    changed!(source.census.as_mut().unwrap().session, 0);
    changed!(source.census.as_mut().unwrap().next_serial, 900);
    changed!(source.census.as_mut().unwrap().generation, 1);
    changed!(source.census.as_mut().unwrap().origins_pointer, 0);
    changed!(source.census.as_mut().unwrap().history_capacity, 0);
    changed!(source.census.as_mut().unwrap().reservation, None);
    macro_rules! budget {
        ($axis:ident) => {{
            changed!(source.census.as_mut().unwrap().charged.$axis, 999);
            changed!(source.census.as_mut().unwrap().used.$axis, 999);
            changed!(source.census.as_mut().unwrap().limits.$axis, 999);
        }};
    }
    budget!(epochs);
    budget!(source_fact_bytes);
    budget!(reports);
    budget!(origins);
    budget!(witnesses);
    budget!(plan_history);
    changed!(source.start, Some(999));
    changed!(source.rows[2], None);
    changed!(
        source
            .evidence
            .as_mut()
            .unwrap()
            .binding
            .as_mut()
            .unwrap()
            .candidate_serial,
        999
    );
    changed!(
        source
            .evidence
            .as_mut()
            .unwrap()
            .binding
            .as_mut()
            .unwrap()
            .operand
            .value,
        999
    );
    changed!(
        source
            .evidence
            .as_mut()
            .unwrap()
            .binding
            .as_mut()
            .unwrap()
            .profile
            .initial_rsp,
        0
    );
    changed!(source.evidence.as_mut().unwrap().trace, None);
    changed!(source.evidence.as_mut().unwrap().words, Some([[4; 16]; 4]));
    changed!(source.evidence_allocation, None);
    changed!(source.old_origin, None);
    changed!(source.new_origin, None);
    changed!(source.old_current_allocation, None);
    changed!(source.actual_allocations[0], None);
}
#[test]
fn consumer_stack_prefix_mirror_checks_full_state_bytes_and_allocation_identity() {
    let mut source = source();
    let out = mirror(&source);
    type Mutation = fn(&mut ObservedStop);
    let mutations: [Mutation; 8] = [
        |s| s.token.sequence ^= 1,
        |s| s.task.generation ^= 1,
        |s| s.logical_pc ^= 1,
        |s| s.registers.rax ^= 1,
        |s| s.signal_mask ^= 1,
        |s| s.xstate[0] ^= 1,
        |s| {
            s.phase = if s.phase == StopPhase::UserCheckpoint {
                StopPhase::OriginalSignal
            } else {
                StopPhase::UserCheckpoint
            }
        },
        |s| {
            s.signal = if s.signal.is_none() {
                Some(DynamicSignalInfo { raw: [0; 128] })
            } else {
                None
            }
        },
    ];
    for mutate in mutations {
        mutate(source.states[0].as_mut().unwrap());
        assert_eq!(
            out.require_preserved(&source),
            Err(CensusConsumerError::Mismatch)
        );
        mutate(source.states[0].as_mut().unwrap());
        out.require_preserved(&source).unwrap();
    }
    source.buffers[1][0] ^= 1;
    assert_eq!(
        out.require_preserved(&source),
        Err(CensusConsumerError::Mismatch)
    );
    source.buffers[1][0] ^= 1;
    out.require_preserved(&source).unwrap();
    let state = source.states[0].as_mut().unwrap();
    let mut replacement = exact_storage::empty_bytes(MAX_XSTATE_BYTES).unwrap();
    replacement.extend_from_slice(&state.xstate);
    let previous = std::mem::replace(&mut state.xstate, replacement);
    assert_eq!(
        out.require_preserved(&source),
        Err(CensusConsumerError::Mismatch)
    );
    source.states[0].as_mut().unwrap().xstate = previous;
    out.require_preserved(&source).unwrap();
    let mut replacement = exact_storage::empty_bytes(MAX_XSTATE_BYTES).unwrap();
    replacement.extend_from_slice(&source.buffers[1]);
    let previous = std::mem::replace(&mut source.buffers[1], replacement);
    assert_eq!(
        out.require_preserved(&source),
        Err(CensusConsumerError::Mismatch)
    );
    source.buffers[1] = previous;
    out.require_preserved(&source).unwrap();
}
#[test]
fn consumer_stack_prefix_mirror_keeps_zero_lengths_and_failed_capture_prefixes() {
    let empty_source = PreparedStackObservation::empty();
    let mut out = mirror(&empty_source);
    out.require_preserved(&empty_source).unwrap();
    assert!(out.capture.complete);
    assert!(!empty_source.capture.started);
    let progress = out.capture;
    assert_eq!(out.capture(&empty_source), Err(CensusConsumerError::Reused));
    out.mark_aborted();
    assert_eq!(out.capture, progress);
    let mut out = PreparedStackPrefixMirror::empty();
    assert_eq!(
        out.capture(&empty_source),
        Err(CensusConsumerError::Incomplete)
    );
    out.mark_aborted();
    assert_eq!(
        out.capture.first_failure,
        Some(CensusConsumerError::Incomplete)
    );
    assert_eq!(
        out.require_preserved(&empty_source),
        Err(CensusConsumerError::Incomplete)
    );
    let mut zero = source();
    zero.states[0].as_mut().unwrap().xstate.clear();
    let zero_copy = mirror(&zero);
    zero_copy.require_preserved(&zero).unwrap();
    assert!(zero_copy.capture.complete);
    assert_eq!(zero.states[0].as_ref().unwrap().xstate.len(), 0);
    let mut source = source();
    let mut out = PreparedStackPrefixMirror::empty();
    out.allocate_payloads().unwrap();
    // Both owned capacities exceed the fixed one-state source shape. Preserve
    // the captured header and first failure, do not grow a diagnostic buffer.
    source.buffers[0] = exact_storage::empty_bytes(MAX_XSTATE_BYTES).unwrap();
    let before = out.states[0].identity();
    assert_eq!(out.capture(&source), Err(CensusConsumerError::Mismatch));
    assert!(out.header.is_some());
    assert_eq!(out.capture.filled, 1);
    assert_eq!(out.states[0].identity(), before);
    out.mark_aborted();
    assert_eq!(
        out.capture.first_failure,
        Some(CensusConsumerError::Mismatch)
    );
    assert_eq!(
        out.allocated_bytes().unwrap(),
        PreparedStackPrefixMirror::reservation_bytes().unwrap()
    );
}
