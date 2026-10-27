//! Supplied storage only. No owner, native request, stop or seal is fabricated.
use super::*;

fn allocated() -> NativeInstructionStorage {
    let mut value = NativeInstructionStorage::empty(
        NativeInstructionStorage::allocation_test_shape(),
        Instant::now(),
    );
    for i in 0..15 {
        value.allocate_one(i).unwrap();
    }
    value
}
fn bytes(value: &NativeInstructionStorage) -> Vec<(usize, usize, Vec<u8>)> {
    let view = value.partial_view();
    let mut result = Vec::new();
    for state in view.states.into_iter().flatten() {
        result.push((
            state.state.xstate.as_ptr() as usize,
            state.state.xstate.capacity(),
            state.state.xstate.clone(),
        ));
        assert!(
            state.registers_request.is_none()
                && state.xstate_request.is_none()
                && state.mask_request.is_none()
        );
        assert_eq!(
            (
                state.requested_pointer,
                state.returned_pointer,
                state.returned_length,
                state.complete
            ),
            (0, 0, 0, false)
        );
    }
    for map in view.maps.into_iter().flatten() {
        result.push((
            map.initialized_storage().as_ptr() as usize,
            MAP_BYTES,
            map.initialized_storage().to_vec(),
        ));
        assert_eq!(
            (map.length, map.request, map.filesystem, map.complete),
            (0, None, None, false)
        );
    }
    if let Some(membership) = view.membership {
        result.push((membership.as_ptr() as usize, MAP_BYTES, membership.to_vec()));
    }
    result
}
fn no_native(value: &NativeInstructionStorage) {
    let progress = value.progress();
    assert_eq!(progress.waits, [None; WAITS]);
    assert_eq!(progress.queries_started, [false; WAITS]);
    assert!(progress.effects().is_empty());
    assert!(!progress.instruction_completed && !progress.nx_closed);
    assert!(value.completed().is_none());
}

#[test]
fn ordinary_pending_native_missing_owner_conversion_retains_every_present_byte() {
    for missing in 0..16 {
        let mut value = allocated();
        let partial = value.pending.as_mut().unwrap();
        // Deliberately remove supplied-data owners before measuring the retained
        // prefix. Conversion itself must neither drop nor replace the others.
        match missing {
            0..=8 => {
                partial.states[missing] = None;
            }
            9..=13 => {
                partial.maps[missing - 9] = None;
            }
            14 => {
                partial.membership = None;
            }
            _ => {
                partial.states[0] = None;
                partial.maps[4] = None;
                partial.membership = None;
            }
        }
        partial.encoding[14] = 0xa7;
        partial.progress.first_failure = Some((
            InstructionPhase::Allocated,
            InstructionFailure::Invalid("retained supplied failure"),
        ));
        let old = bytes(&value);
        let input = value.pending.take().unwrap();
        value.pending = Some(match input.into_allocated() {
            NativeStorageConversion::Partial(owner) => owner,
            NativeStorageConversion::Allocated(_) => panic!("missing owner was accepted"),
        });
        assert_eq!(bytes(&value), old);
        let partial = value.pending.as_ref().unwrap();
        assert_eq!(partial.encoding[14], 0xa7);
        assert_eq!(
            partial.progress.first_failure,
            Some((
                InstructionPhase::Allocated,
                InstructionFailure::Invalid("retained supplied failure")
            ))
        );
        assert!(value.finish_allocation().is_err());
        assert_eq!(bytes(&value), old);
        assert!(value.take_completed().is_err());
        no_native(&value);
    }
}

#[test]
fn ordinary_pending_native_conversion_is_move_only_and_does_not_complete_instruction() {
    let mut value = allocated();
    let old = bytes(&value);
    let amount = value.payload_bytes().unwrap();
    assert_eq!(amount, 9 * MAX_XSTATE + 6 * MAP_BYTES);
    value.finish_allocation().unwrap();
    assert_eq!(bytes(&value), old);
    assert_eq!(value.payload_bytes().unwrap(), amount);
    assert!(value.partial_view().allocated && !value.partial_view().pending);
    assert_eq!(value.partial_view().next, 15);
    assert_eq!(value.partial_view().first_failure, None);
    assert!(value.finish_allocation().is_err());
    assert!(value.allocate_one(0).is_err());
    assert!(value.take_completed().is_err());
    assert_eq!(bytes(&value), old);
    no_native(&value);
}

#[test]
fn ordinary_pending_native_failure_reuse_and_capacity_guards_retain_owners() {
    let mut value = allocated();
    let old = bytes(&value);
    value.pending.as_mut().unwrap().states[4]
        .as_mut()
        .unwrap()
        .state
        .xstate
        .truncate(MAX_XSTATE - 1);
    assert!(value.finish_allocation().is_err());
    assert_eq!(
        value.partial_view().states[4].unwrap().state.xstate.len(),
        MAX_XSTATE - 1
    );
    value.pending.as_mut().unwrap().states[4]
        .as_mut()
        .unwrap()
        .state
        .xstate
        .resize(MAX_XSTATE, 0);
    assert_eq!(bytes(&value), old);
    value.mark_aborted();
    assert!(value.finish_allocation().is_err());
    assert!(value.allocate_one(14).is_err());
    assert!(value.require_complete().is_err());
    assert_eq!(bytes(&value), old);
    assert_eq!(
        value.partial_view().first_failure,
        Some(InstructionFailure::Unwound)
    );
    no_native(&value);
}
