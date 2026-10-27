//! Observe the real appended row before opening; retain its typed identity.
use super::*;
use crate::linux::remote::dynamic::owner::admission::census::stack_calls::{
    PotentialCallId, RecordedCall,
};
use crate::linux::remote::dynamic::owner::admission::census::{
    CallLedgerRowSnapshot, StackChainInput,
};
use crate::linux::remote::dynamic::owner::admission::runtime_native::NativeCheckpoint;
use crate::linux::remote::dynamic::owner::admission::runtime_stack_native::StackWordViews;
use std::cell::RefCell;
thread_local! {static CALLS:RefCell<Vec<(PotentialCallId,CallLedgerRowSnapshot)>>=const {RefCell::new(Vec::new())};}

fn record_before_opening(
    owner: &Owner,
    native: &NativeLifecycle,
    call: &RecordedCall<'_>,
    binding: &RuntimeStackBinding<'_, '_>,
    prepared: &PreparedStackNative,
    census: &ResumeCensus,
    sources: &PreparedInitialSources,
) -> Result<(), GateError> {
    support::held(owner, binding.until());
    assert_eq!(
        native
            .admission_current(binding.stop().identity.task)
            .unwrap(),
        *binding.stop()
    );
    assert_eq!(
        census.current_observation(binding.origin()).unwrap(),
        binding.before()
    );
    assert_eq!(sources.runtime_baseline_maps().unwrap(), maps(owner.pid));
    let progress = prepared.progress();
    assert_eq!(progress.waits, [None; 7]);
    assert!(progress.effects().is_empty());
    assert!(!progress.instruction_completed && !progress.nx_closed);
    assert!(
        prepared
            .diagnostics()
            .words
            .iter()
            .all(|w| !w.complete && w.association.is_none())
    );
    let row = call.test_stack_call(binding);
    CALLS.with(|rows| rows.borrow_mut().push((call.id(), row)));
    Ok(())
}
fn before_opening(
    owner: &Owner,
    native: &NativeLifecycle,
    call: &RecordedCall<'_>,
    binding: &RuntimeStackBinding<'_, '_>,
    prepared: &PreparedStackNative,
    census: &ResumeCensus,
    sources: &PreparedInitialSources,
) -> Result<(), GateError> {
    support::held(owner, binding.until());
    assert_eq!(
        state(owner.pid),
        TaskStateSnapshot {
            registers: binding.before().registers,
            xstate: binding.before().xstate.clone(),
            mask: binding.before().signal_mask
        }
    );
    record_before_opening(owner, native, call, binding, prepared, census, sources)
}
/// Only the explicit AfterA lower-producer faults use this observer. It still
/// checks the original appended full CALL row, while the live state must equal
/// the separately retained successful test setter/readback, not the old state.
fn after_a_before_opening(
    owner: &Owner,
    native: &NativeLifecycle,
    call: &RecordedCall<'_>,
    binding: &RuntimeStackBinding<'_, '_>,
    prepared: &PreparedStackNative,
    census: &ResumeCensus,
    sources: &PreparedInitialSources,
) -> Result<(), GateError> {
    support::held(owner, binding.until());
    let intervention = prepared.intervention().unwrap();
    assert_eq!(
        intervention.point,
        runtime_stack_native::InterventionPoint::AfterA
    );
    assert!(intervention.started && intervention.complete);
    assert_eq!(
        intervention.setter,
        Some(NativeRequest {
            result: 0,
            errno: None
        })
    );
    let mut expected = TaskStateSnapshot {
        registers: binding.before().registers,
        xstate: binding.before().xstate.clone(),
        mask: binding.before().signal_mask,
    };
    match intervention.kind {
        runtime_stack_native::InterventionKind::Ac => expected.registers.eflags |= 1 << 18,
        runtime_stack_native::InterventionKind::PkruKeyZeroDeny => {
            let offset = intervention.pkru_offset.unwrap();
            let old = u32::from_le_bytes(expected.xstate[offset..offset + 4].try_into().unwrap());
            assert_eq!(Some(old), intervention.old_pkru);
            assert_eq!(intervention.changed_pkru, Some(old | 3));
            expected.xstate[offset..offset + 4].copy_from_slice(&(old | 3).to_le_bytes());
        }
    }
    let actual = intervention.after.unwrap();
    assert_eq!(actual.registers, expected.registers);
    assert_eq!(actual.mask, expected.mask);
    assert_eq!(state(owner.pid), expected);
    record_before_opening(owner, native, call, binding, prepared, census, sources)
}
pub(super) fn install_after_a(owner: &mut Owner) {
    install(owner);
    owner
        .runtime
        .as_mut()
        .unwrap()
        .stack
        .as_mut()
        .unwrap()
        .before_opening = Some(after_a_before_opening);
}
pub(super) fn install(owner: &mut Owner) {
    CALLS.with(|rows| rows.borrow_mut().clear());
    owner
        .runtime
        .as_mut()
        .unwrap()
        .stack
        .as_mut()
        .unwrap()
        .before_opening = Some(before_opening);
}
pub(super) fn check(owner: &Owner, expected: usize) {
    let stack = owner.runtime.as_ref().unwrap().stack.as_ref().unwrap();
    CALLS.with(|rows| {
        let rows = rows.borrow();
        assert_eq!(rows.len(), expected);
        for (id, before) in rows.iter() {
            assert!(
                stack.calls.test_row(*id) == *before,
                "CALL row changed after pre-opening observation"
            );
        }
    });
}
pub(super) fn chain(owner: &Owner, ordinal: usize, start: usize) {
    let runtime = owner.runtime.as_ref().unwrap();
    let stack = runtime.stack.as_ref().unwrap();
    let attempt = stack.attempts[ordinal].as_ref().unwrap();
    let native = attempt.native.diagnostics();
    let initial = stack.profile.identity().unwrap();
    let operand = attempt.operand.operand().unwrap();
    let (original, progress) = runtime.sources.original_maps();
    let original = &original[..progress.copied_bytes];
    let checkpoints = std::array::from_fn(|index| NativeCheckpoint {
        stop: native.stops[index].as_ref().unwrap(),
        state: &native.states[if index < 3 { 0 } else { 4 }].state,
    });
    let current = runtime.initial_origin.unwrap();
    let actual = runtime
        .native
        .as_ref()
        .unwrap()
        .admission_current(attempt.stop.identity.task)
        .unwrap();
    runtime
        .census
        .as_ref()
        .unwrap()
        .test_stack_chain(StackChainInput {
            start,
            reservation: attempt.reservation,
            identity: native.identity.unwrap(),
            logical_before: &attempt.before,
            checkpoints,
            trace: native.trace.unwrap(),
            words: StackWordViews {
                profile: initial.description(),
                operand: operand.description(),
                original_maps: original,
                baseline_maps: native.maps[0].unwrap().bytes(),
                opened_maps: native.maps[1].unwrap().bytes(),
                captures: [
                    attempt.operand.view(),
                    native.words[0],
                    native.words[1],
                    native.words[2],
                ],
            },
            call_id: native.call_id,
            sources: &runtime.sources,
            current,
            native_current: &actual,
        });
    if attempt.is_call {
        assert!(native.call_id.is_some());
    } else {
        assert_eq!(native.call_id, None);
    }
}
