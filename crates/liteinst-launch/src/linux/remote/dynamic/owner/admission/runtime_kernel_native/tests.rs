//! Pure allocation and descriptive-prefix controls. No native seal producer.
use super::*;

fn shape(operation: RuntimeKernelOperation) -> RuntimeKernelShape {
    RuntimeKernelShape {
        operation,
        fetch_start: 0x400000,
        fetch_end: 0x402000,
    }
}
fn attempt() -> PreparedRuntimeKernel {
    PreparedRuntimeKernel::new(shape(RuntimeKernelOperation::Getpid), Instant::now())
}
fn invalid<T>(result: Result<T, LaunchError>, expected: &'static str) {
    assert!(matches!(result, Err(LaunchError::Invalid(actual)) if actual == expected));
}

#[test]
fn runtime_kernel_native_fixed_layout_charges_all_unused_terminal_capacity() {
    let profile_bytes = 11 * size_of::<ControlProfile>();
    let expected =
        size_of::<PreparedRuntimeKernel>() + 11 * MAX_XSTATE + 12 * MAP_BYTES + profile_bytes;
    const { assert!(size_of::<PreparedRuntimeKernel>() < 11 * size_of::<ControlProfile>()) };
    for operation in [
        RuntimeKernelOperation::Getpid,
        RuntimeKernelOperation::Gettid,
        RuntimeKernelOperation::Exit,
        RuntimeKernelOperation::ExitGroup,
    ] {
        assert_eq!(shape(operation).operation, operation);
        assert_eq!(RuntimeKernelShape::reservation_bytes().unwrap(), expected);
    }
    let mut prepared = attempt();
    assert!(prepared.profiles.is_empty());
    assert_eq!(prepared.profiles.capacity(), 0);
    assert_eq!(
        prepared.allocated_bytes().unwrap(),
        size_of::<PreparedRuntimeKernel>()
    );
    prepared.allocate_payloads().unwrap();
    assert_eq!(prepared.allocated_bytes().unwrap(), expected);
    assert_eq!(prepared.payload_bytes().unwrap(), 1_507_328 + profile_bytes);
    assert_eq!(prepared.profiles.len(), 11);
    assert_eq!(prepared.profiles.capacity(), 11);
    assert!(prepared.states.iter().all(|state| {
        state.capacity() == MAX_XSTATE
            && state
                .view()
                .xstate_initialized
                .iter()
                .all(|byte| *byte == 0)
    }));
    assert!(prepared.maps.iter().all(|maps| {
        maps.capacity() == MAP_BYTES
            && maps
                .view()
                .unwrap()
                .initialized
                .iter()
                .all(|byte| *byte == 0)
    }));
    assert_eq!(prepared.effects_len, 0);
    assert!(prepared.raw.iter().all(|raw| raw.wait.is_none()));
    invalid(
        prepared.take_returned(),
        "runtime kernel return is not claimable",
    );
    invalid(
        prepared.take_terminal(),
        "runtime kernel terminal is not claimable",
    );
    let retained = prepared.allocated_bytes().unwrap();
    invalid(
        prepared.allocate_payloads(),
        "runtime kernel allocation reused",
    );
    assert_eq!(prepared.allocated_bytes().unwrap(), retained);
}

#[test]
fn runtime_kernel_native_partial_allocation_refusal_keeps_prior_storage() {
    let mut prepared = attempt();
    prepared.states[0].allocate().unwrap();
    prepared.maps[0].allocate().unwrap();
    let state_pointer = prepared.states[0].view().xstate_initialized.as_ptr();
    let maps_pointer = prepared.maps[0].view().unwrap().initialized.as_ptr();
    let retained = prepared.allocated_bytes().unwrap();
    assert_eq!(
        retained,
        size_of::<PreparedRuntimeKernel>() + MAX_XSTATE + MAP_BYTES
    );
    // Deliberately occupied first slot exercises the allocation-error path.
    // This is a pure failure-prefix control, not an allocator/native fault.
    invalid(
        prepared.allocate_payloads(),
        "runtime kernel state allocation reused",
    );
    assert_eq!(prepared.allocated_bytes().unwrap(), retained);
    assert_eq!(
        prepared.states[0].view().xstate_initialized.as_ptr(),
        state_pointer
    );
    assert_eq!(
        prepared.maps[0].view().unwrap().initialized.as_ptr(),
        maps_pointer
    );
    assert_eq!(
        prepared.first_failure,
        Some((
            RuntimeKernelPhase::Allocating,
            RuntimeKernelFailure::Invalid("runtime kernel state allocation reused")
        ))
    );
    assert!(!prepared.allocated);
    assert_eq!(prepared.effects_len, 0);
    assert!(prepared.raw.iter().all(|raw| raw.wait.is_none()));
}

#[test]
fn runtime_kernel_native_effect_capacity_is_thirty_seven_and_never_skips_pending() {
    // Six private calls and one bridge each reserve five actual effects;
    // original release and original ENTRY release require two additional rows.
    assert_eq!(EFFECTS, 6 * 5 + 5 + 2);
    const { assert!(EFFECTS > 32) };
    let mut prepared = attempt();
    for ordinal in 0..EFFECTS {
        assert!(prepared.can_begin_effect());
        prepared.effects[ordinal] = Some(RuntimeKernelEffectRecord {
            effect: RuntimeKernelEffect::SetRegisters { ordinal },
            result: None,
            complete: false,
        });
        prepared.effects_len += 1;
        assert!(!prepared.can_begin_effect());
        prepared.effects[ordinal].as_mut().unwrap().result = Some(Request {
            result: 0,
            errno: None,
        });
        prepared.effects[ordinal].as_mut().unwrap().complete = true;
    }
    assert!(!prepared.can_begin_effect());
    prepared.effects_len = 1;
    prepared.effects[0] = None;
    assert!(!prepared.can_begin_effect());
    prepared.effects_len = 0;
    prepared.first_failure = Some((
        RuntimeKernelPhase::Entry,
        RuntimeKernelFailure::Invalid("model fault"),
    ));
    assert!(!prepared.can_begin_effect());
}

#[test]
fn runtime_kernel_native_terminal_raw_header_has_no_fabricated_request_credit() {
    let mut prepared = attempt();
    prepared.allocate_payloads().unwrap();
    let status = 7 << 8;
    prepared.raw[5].wait = Some((42, status));
    let raw = prepared.raw_view(5).unwrap();
    assert_eq!((raw.ordinal, raw.tid, raw.status), (5, 42, status));
    assert!(!raw.queries_started);
    assert!(raw.state.is_none() && raw.maps.is_none());
    assert!(
        raw.fixed.syscall_info_request.is_none()
            && raw.fixed.signal_request.is_none()
            && raw.fixed.event_message_request.is_none()
    );
    assert!(raw.fixed.syscall_info.iter().all(|byte| *byte == 0));
    assert!(prepared.raw_view(4).is_none() && prepared.raw_view(9).is_none());
    invalid(
        prepared.take_terminal(),
        "runtime kernel terminal is not claimable",
    );
}

#[test]
fn runtime_kernel_native_error_and_unwind_keep_first_failure_and_never_seal() {
    let mut prepared = attempt();
    prepared.states[0].allocate().unwrap();
    let pointer = prepared.states[0].view().xstate_initialized.as_ptr();
    prepared.phase = RuntimeKernelPhase::Entry;
    let failure = prepared.guarded(|_| Err(LaunchError::Invalid("first fault")));
    invalid(failure, "first fault");
    prepared.phase = RuntimeKernelPhase::Closing;
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = prepared.guarded(|_| panic!("model unwind"));
    }));
    assert!(unwind.is_err());
    assert_eq!(
        prepared.first_failure,
        Some((
            RuntimeKernelPhase::Entry,
            RuntimeKernelFailure::Invalid("first fault")
        ))
    );
    assert_eq!(
        prepared.states[0].view().xstate_initialized.as_ptr(),
        pointer
    );
    assert_eq!(prepared.payload_bytes().unwrap(), MAX_XSTATE);
    invalid(
        prepared.take_returned(),
        "runtime kernel return is not claimable",
    );
    invalid(
        prepared.take_terminal(),
        "runtime kernel terminal is not claimable",
    );
}

#[test]
fn runtime_kernel_native_checked_storage_arithmetic_refuses_overflow() {
    assert_eq!(add(17, 19).unwrap(), 36);
    assert_eq!(mul(11, MAX_XSTATE).unwrap(), 720_896);
    invalid(add(usize::MAX, 1), "runtime kernel storage overflows");
    invalid(mul(usize::MAX, 2), "runtime kernel storage overflows");
}
