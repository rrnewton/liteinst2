//! Supplied storage only. No owner, native request, stop or seal is fabricated.
use super::*;

fn pending(value: &mut NativeInstructionStorage) -> &mut PendingInstructionStorage {
    match value.owner.as_mut() {
        Some(NativeStorageConversion::Partial(value)) => value,
        _ => panic!("supplied pending owner absent"),
    }
}

fn allocated() -> NativeInstructionStorage {
    let mut value = NativeInstructionStorage::empty(
        NativeInstructionStorage::allocation_test_shape(),
        Instant::now(),
    );
    for i in 0..16 {
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
fn profile(value: &NativeInstructionStorage) -> Option<native_oracle::ProfileOwnerSnapshot> {
    value
        .partial_view()
        .profile
        .map(native_oracle::profile_snapshot)
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
    for missing in 0..18 {
        let mut value = allocated();
        let partial = pending(&mut value);
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
            15 => {
                partial.states[0] = None;
                partial.maps[4] = None;
                partial.membership = None;
            }
            16 => {
                partial.profile = None;
            }
            _ => {
                partial.profile = None;
                partial.states[0] = None;
            }
        }
        partial.encoding[14] = 0xa7;
        partial.progress.first_failure = Some((
            InstructionPhase::Allocated,
            InstructionFailure::Invalid("retained supplied failure"),
        ));
        let old = bytes(&value);
        let old_profile = profile(&value);
        let input = match value.owner.take().unwrap() {
            NativeStorageConversion::Partial(owner) => owner,
            NativeStorageConversion::Allocated(_) => panic!("supplied pending owner absent"),
        };
        value.owner = Some(match input.into_allocated() {
            NativeStorageConversion::Partial(owner) => NativeStorageConversion::Partial(owner),
            NativeStorageConversion::Allocated(_) => panic!("missing owner was accepted"),
        });
        assert_eq!(bytes(&value), old);
        assert_eq!(profile(&value), old_profile);
        let partial = pending(&mut value);
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
        assert_eq!(profile(&value), old_profile);
        assert!(value.take_completed().is_err());
        no_native(&value);
    }
}

#[test]
fn ordinary_pending_native_conversion_is_move_only_and_does_not_complete_instruction() {
    let mut value = allocated();
    let old = bytes(&value);
    let old_profile = profile(&value);
    assert!(old_profile.is_some());
    let amount = value.payload_bytes().unwrap();
    assert_eq!(
        amount,
        9 * MAX_XSTATE + 6 * MAP_BYTES + size_of::<ControlProfile>()
    );
    value.finish_allocation().unwrap();
    assert_eq!(bytes(&value), old);
    assert_eq!(profile(&value), old_profile);
    assert_eq!(value.payload_bytes().unwrap(), amount);
    assert!(value.partial_view().allocated && !value.partial_view().pending);
    assert_eq!(value.partial_view().next, 16);
    assert_eq!(value.partial_view().first_failure, None);
    assert!(value.finish_allocation().is_err());
    assert!(value.allocate_one(0).is_err());
    assert!(value.take_completed().is_err());
    assert_eq!(bytes(&value), old);
    assert_eq!(profile(&value), old_profile);
    no_native(&value);

    // None is observable absence, never an empty complete attempt. Keep the
    // detached actual model owner alive and restore exactly that owner.
    let complete = value.allocation_custody_snapshot();
    let detached = value.owner.take();
    assert!(matches!(
        detached,
        Some(NativeStorageConversion::Allocated(_))
    ));
    assert_eq!(value.payload_bytes().unwrap(), 0);
    assert!(!value.partial_view().pending && !value.partial_view().allocated);
    assert!(value.partial_view().states.iter().all(Option::is_none));
    assert!(value.partial_view().maps.iter().all(Option::is_none));
    assert!(value.partial_view().profile.is_none());
    assert!(value.completed().is_none());
    assert!(value.require_complete().is_err());
    assert!(value.finish_allocation().is_err());
    assert!(value.take_completed().is_err());
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| value.progress())).is_err());
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| value.diagnostics())).is_err()
    );
    value.owner = detached;
    assert_eq!(value.allocation_custody_snapshot(), complete);
    // Wrong-stage finish refusal preserves the whole Allocated owner.
    assert!(value.finish_allocation().is_err());
    assert_eq!(value.allocation_custody_snapshot(), complete);
    value.mark_aborted();
    assert!(value.require_complete().is_err());
    // Diagnostics remain available for real retained failed allocations.
    assert_eq!(
        value.diagnostics().profile.test_retained_snapshot(),
        value
            .partial_view()
            .profile
            .unwrap()
            .test_retained_snapshot()
    );
    assert_eq!(
        value.progress().first_failure,
        Some((InstructionPhase::Allocated, InstructionFailure::Unwound))
    );
}

#[test]
fn ordinary_pending_native_failure_reuse_and_capacity_guards_retain_owners() {
    let mut prefix = NativeInstructionStorage::empty(
        NativeInstructionStorage::allocation_test_shape(),
        Instant::now(),
    );
    for ordinal in 0..15 {
        prefix.allocate_one(ordinal).unwrap();
    }
    let old_bytes = bytes(&prefix);
    let old_amount = prefix.payload_bytes().unwrap();
    assert_eq!(profile(&prefix), None);
    assert!(prefix.finish_allocation().is_err());
    prefix.allocate_one(15).unwrap();
    assert_eq!(bytes(&prefix), old_bytes);
    assert_eq!(
        prefix.payload_bytes().unwrap(),
        old_amount + size_of::<ControlProfile>()
    );
    let installed = profile(&prefix);
    assert!(installed.is_some());
    assert!(prefix.allocate_one(15).is_err());
    assert_eq!(profile(&prefix), installed);
    assert_eq!(bytes(&prefix), old_bytes);
    no_native(&prefix);

    let mut value = allocated();
    let old = bytes(&value);
    let old_profile = profile(&value);
    pending(&mut value).states[4]
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
    pending(&mut value).states[4]
        .as_mut()
        .unwrap()
        .state
        .xstate
        .resize(MAX_XSTATE, 0);
    assert_eq!(bytes(&value), old);
    assert_eq!(profile(&value), old_profile);
    value.mark_aborted();
    assert!(value.finish_allocation().is_err());
    assert!(value.allocate_one(14).is_err());
    assert!(value.allocate_one(15).is_err());
    assert!(value.require_complete().is_err());
    assert_eq!(bytes(&value), old);
    assert_eq!(profile(&value), old_profile);
    assert_eq!(
        value.partial_view().first_failure,
        Some(InstructionFailure::Unwound)
    );
    no_native(&value);
}
