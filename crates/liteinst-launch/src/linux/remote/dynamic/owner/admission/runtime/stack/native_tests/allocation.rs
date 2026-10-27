//! Actual installed owners with explicit allocator-error/unwind injections.
//! Allocation hooks are models; the launched custody and cleanup are real.
use super::*;
use crate::linux::remote::dynamic::owner::admission::runtime_stack::storage::StackObservationStorage;

fn prefix(value: &StackObservationStorage, installed: usize) {
    let buffers = [&value.smaps, &value.maps, &value.state.state.xstate];
    for (index, buffer) in buffers.into_iter().enumerate() {
        let expected = usize::from(index < installed) * MAX_XSTATE;
        assert_eq!(buffer.capacity(), expected);
        assert_eq!(buffer.len(), expected);
        assert!(buffer.iter().all(|b| *b == 0));
        assert_eq!(
            value.installed_pointers[index],
            (index < installed).then_some(buffer.as_ptr() as usize)
        );
    }
    assert_eq!(value.allocation.retained_payload, installed * MAX_XSTATE);
    assert!(!value.state.complete);
    assert!(!value.maps_capture.started && !value.smaps_capture.started);
}
fn panic_is(payload: &(dyn std::any::Any + Send), fault: StackAllocationFault) {
    match fault.target {
        StackAllocationTarget::Root => assert_eq!(payload.downcast_ref::<u32>(), Some(&0x53544143)),
        StackAllocationTarget::Census => {
            assert_eq!(payload.downcast_ref::<u32>(), Some(&0x5354434e))
        }
        StackAllocationTarget::Call => assert_eq!(payload.downcast_ref::<u32>(), Some(&0x5343414c)),
        StackAllocationTarget::Native => assert_eq!(
            payload.downcast_ref::<&str>(),
            Some(&"owned stack native allocation model unwind")
        ),
        _ => assert_eq!(
            payload.downcast_ref::<&str>(),
            Some(&"owned stack allocation model unwind")
        ),
    }
}
fn expected_payload(fault: StackAllocationFault, window: usize) -> usize {
    let n = fault.ordinal + usize::from(fault.unwind);
    let native = 24 * MAX_XSTATE; // 9 state + 5 maps + membership + 3*3 word buffers.
    let root = 3 * MAX_XSTATE + 3 * window;
    let census_header = size_of::<PreparedStackCensus>();
    let evidence = PreparedStackCensus::test_evidence_bytes();
    let census_payload = 16 * MAX_XSTATE + evidence;
    match fault.target {
        StackAllocationTarget::Profile => panic!("profile is startup-only"),
        StackAllocationTarget::Root => [
            MAX_XSTATE,
            MAX_XSTATE,
            MAX_XSTATE,
            window,
            window,
            window,
            native,
            3 * MAX_XSTATE,
            census_header,
            census_payload,
            size_of::<PreparedCallRecord>(),
            MAX_XSTATE,
        ][..n]
            .iter()
            .sum(),
        StackAllocationTarget::Native => {
            root + if n <= 15 {
                n * MAX_XSTATE
            } else {
                15 * MAX_XSTATE + (n - 15) * 3 * MAX_XSTATE
            }
        }
        StackAllocationTarget::Word(index) => {
            root + 15 * MAX_XSTATE + index * 3 * MAX_XSTATE + n * MAX_XSTATE
        }
        StackAllocationTarget::Operand => root + native + n * MAX_XSTATE,
        StackAllocationTarget::Census => {
            root + native
                + 3 * MAX_XSTATE
                + census_header
                + if n <= 16 {
                    n * MAX_XSTATE
                } else {
                    census_payload
                }
        }
        StackAllocationTarget::Call => {
            root + native
                + 3 * MAX_XSTATE
                + census_header
                + census_payload
                + size_of::<PreparedCallRecord>()
                + n * MAX_XSTATE
        }
    }
}
fn measured(attempt: &RuntimeStackAttempt) -> usize {
    let native = attempt.native.diagnostics();
    let mut bytes = size_of::<RuntimeStackAttempt>()
        + attempt.before.xstate.capacity()
        + attempt.source.checkpoint.xstate.capacity()
        + attempt.source.identity.capacity();
    bytes += attempt
        .source
        .bytes
        .iter()
        .map(Vec::capacity)
        .sum::<usize>();
    bytes += native
        .states
        .iter()
        .map(|s| s.state.xstate.capacity())
        .sum::<usize>();
    bytes += native.maps.iter().filter(|m| m.is_some()).count() * MAX_XSTATE
        + native.membership_capacity;
    for word in native.words.into_iter().chain([attempt.operand.view()]) {
        bytes += word.observation.maps.capacity()
            + word.observation.smaps.capacity()
            + word.observation.state.state.xstate.capacity();
    }
    bytes += attempt
        .census
        .as_ref()
        .map_or(0, |c| c.allocated_bytes().unwrap());
    bytes += attempt
        .call
        .as_ref()
        .map_or(0, |c| c.allocated_bytes().unwrap());
    bytes
}
pub(super) fn run() {
    let program = Program::call(4096, false);
    for ordinal in 0..3 {
        for unwind in [false, true] {
            let fault = StackAllocationFault {
                target: StackAllocationTarget::Profile,
                ordinal,
                unwind,
            };
            let _ = support::with_owner(
                &program,
                true,
                |owner, initial, until, original| {
                    let options = support::options();
                    let capture = InitialCaptureProfile {
                        max_vmas: options.capture.max_vmas,
                        max_windows: options.capture.max_windows,
                        max_window_bytes: options.capture.max_window_bytes,
                        max_total_capture_bytes: options.capture.max_total_capture_bytes,
                    };
                    let mut runtime = RuntimeOwner::allocate(
                        RuntimeStartOptions {
                            capture,
                            limits: options.limits,
                            kernel: options.kernel,
                            stack: options.stack,
                        },
                        until,
                    )
                    .unwrap();
                    runtime.stack.as_mut().unwrap().configure_allocation(fault);
                    owner.runtime = Some(runtime);
                    let mut runtime = owner.runtime.take().unwrap();
                    // Same actual initializer and catch/reinstall ownership, with the
                    // closed Empty-only configuration installed before allocation.
                    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
                        runtime.initialize(owner, initial)
                    }));
                    owner.runtime = Some(runtime);
                    match result {
                        Err(payload) => {
                            assert!(unwind);
                            panic_is(payload.as_ref(), fault);
                        }
                        Ok(result) => {
                            assert!(!unwind);
                            assert!(matches!(
                                result,
                                Err(GateError::Control(LaunchError::Invalid(
                                    "owned stack captured evidence is outside the qualified profile"
                                )))
                            ));
                        }
                    }
                    let runtime = owner.runtime.as_ref().unwrap();
                    let stack = runtime.stack.as_ref().unwrap();
                    prefix(stack.profile.observation(), ordinal + usize::from(unwind));
                    assert_eq!(
                        stack.startup_actual,
                        (ordinal + usize::from(unwind)) * MAX_XSTATE
                    );
                    assert_eq!(stack.startup_settled, 0);
                    assert!(stack.startup_actual <= stack.startup_reserved);
                    assert!(stack.attempts.is_empty());
                    assert_eq!(stack.count, 0);
                    assert!(!stack.startup_complete);
                    assert!(stack.settlement_failure.is_none());
                    assert!(stack.failure.is_some());
                    assert!(
                        runtime.bootstrap.is_none()
                            && runtime.native.is_none()
                            && runtime.census.is_none()
                    );
                    assert_eq!(support::observe_state(owner, until), original.state);
                    assert_eq!(support::observe_maps(owner, until), original.maps);
                    owner.require_stop(initial).unwrap();
                    retention::retained(owner)
                },
                |owner, retained| retained(owner),
            );
        }
    }
    let targets = [
        (StackAllocationTarget::Root, 12),
        (StackAllocationTarget::Native, 18),
        (StackAllocationTarget::Word(0), 3),
        (StackAllocationTarget::Word(1), 3),
        (StackAllocationTarget::Word(2), 3),
        (StackAllocationTarget::Operand, 3),
        (StackAllocationTarget::Census, 17),
        (StackAllocationTarget::Call, 1),
    ];
    for (target, bound) in targets {
        for ordinal in 0..bound {
            for unwind in [false, true] {
                let fault = StackAllocationFault {
                    target,
                    ordinal,
                    unwind,
                };
                let _ = support::with_owner(
                    &program,
                    true,
                    |owner, initial, until, original| {
                        let before =
                            support::begin(owner, initial, until, original, support::options());
                        let runtime = owner.runtime.as_mut().unwrap();
                        let census = runtime.census.as_ref().unwrap();
                        let old_used = census.used();
                        let old_charged = census.charged();
                        let old_history = census.history().to_vec();
                        let old_origin = runtime.initial_origin;
                        let charge = storage::attempt_charge(
                            runtime.sources.window(0).unwrap().snapshot.bytes().len(),
                            true,
                        )
                        .unwrap();
                        runtime.stack.as_mut().unwrap().configure_allocation(fault);
                        let outcome = catch_unwind(AssertUnwindSafe(|| {
                            if unwind {
                                support::invoke_unwind(
                                    owner,
                                    original,
                                    AdmissionRequest::Advance,
                                    until,
                                )
                            } else {
                                support::invoke(owner, AdmissionRequest::Advance, until)
                            }
                        }));
                        match outcome {
                            Err(payload) => {
                                assert!(unwind);
                                panic_is(payload.as_ref(), fault);
                            }
                            Ok(result) => {
                                assert!(!unwind);
                                assert!(result.is_err());
                            }
                        }
                        let runtime = owner.runtime.as_ref().unwrap();
                        let stack = runtime.stack.as_ref().unwrap();
                        let a = stack.attempts[0].as_ref().unwrap();
                        let actual =
                            size_of::<RuntimeStackAttempt>() + expected_payload(fault, 8192);
                        assert_eq!(measured(a), actual);
                        assert_eq!(stack.count, 1);
                        assert!(stack.pending.is_none());
                        assert!(a.failure.is_some() && stack.failure.is_some());
                        assert!(
                            a.settlement_failure.is_none() && stack.settlement_failure.is_none()
                        );
                        assert!(!a.allocated);
                        assert_eq!(a.stage, AttemptStage::Allocated);
                        assert_eq!(a.native.progress().waits, [None; 7]);
                        assert!(a.native.progress().effects().is_empty());
                        assert!(!a.native.diagnostics().claimed);
                        assert!(!a.operand.progress().started);
                        assert!(
                            a.source
                                .progress
                                .iter()
                                .all(|p| !p.started && !p.attempted && !p.complete)
                        );
                        match target {
                            StackAllocationTarget::Word(index) => prefix(
                                a.native.diagnostics().words[index].observation,
                                ordinal + usize::from(unwind),
                            ),
                            StackAllocationTarget::Operand => {
                                prefix(a.operand.view().observation, ordinal + usize::from(unwind))
                            }
                            _ => {}
                        }
                        let census = runtime.census.as_ref().unwrap();
                        let mut expected_used = old_used;
                        expected_used.source_fact_bytes += actual;
                        assert_eq!(census.used(), expected_used);
                        assert_eq!(census.charged(), support::sum(old_charged, charge));
                        assert_eq!(census.history(), old_history);
                        assert_eq!(runtime.initial_origin, old_origin);
                        assert_eq!(support::observe_state(owner, until), before);
                        assert_eq!(
                            support::observe_maps(owner, until),
                            runtime.sources.runtime_baseline_maps().unwrap()
                        );
                        assert_eq!(
                            original.read_stack(owner, until),
                            *original.stack.as_ref().unwrap()
                        );
                        original.require_source(owner, until);
                        if unwind {
                            assert!(!owner.closing && owner.cancel.load(Ordering::Acquire));
                        } else {
                            assert!(owner.closing && owner.cancel.load(Ordering::Acquire));
                        }
                        retention::retained(owner)
                    },
                    |owner, retained| {
                        // Actual cleanup establishes closing after the real
                        // client disconnect established cancellation on unwind.
                        assert!(owner.closing && owner.cancel.load(Ordering::Acquire));
                        retained(owner);
                    },
                );
            }
        }
    }
    // Empty-header failure retains the complete reservation; post-install
    // unwind must additionally debit the real header before cleanup.
    for installed in [false, true] {
        let _ = support::with_owner(
            &program,
            true,
            |owner, initial, until, original| {
                let before = support::begin(owner, initial, until, original, support::options());
                let runtime = owner.runtime.as_mut().unwrap();
                let used = runtime.census.as_ref().unwrap().used();
                let charged = runtime.census.as_ref().unwrap().charged();
                let charge = storage::attempt_charge(8192, true).unwrap();
                let stack = runtime.stack.as_mut().unwrap();
                stack.fail_attempt_header = !installed;
                stack.panic_after_attempt_header = installed;
                let result = catch_unwind(AssertUnwindSafe(|| {
                    if installed {
                        support::invoke_unwind(owner, original, AdmissionRequest::Advance, until)
                    } else {
                        support::invoke(owner, AdmissionRequest::Advance, until)
                    }
                }));
                if installed {
                    assert_eq!(
                        support::panic_payload(result).downcast_ref::<u32>(),
                        Some(&0x48454144)
                    );
                } else {
                    assert!(matches!(
                        result.unwrap(),
                        Err(GateError::Refused(
                            "injected stack attempt header allocation failure"
                        ))
                    ));
                }
                let runtime = owner.runtime.as_ref().unwrap();
                let stack = runtime.stack.as_ref().unwrap();
                assert_eq!(stack.count, usize::from(installed));
                assert_eq!(stack.pending.is_some(), !installed);
                let mut expected = used;
                expected.source_fact_bytes +=
                    usize::from(installed) * size_of::<RuntimeStackAttempt>();
                assert_eq!(runtime.census.as_ref().unwrap().used(), expected);
                assert_eq!(
                    runtime.census.as_ref().unwrap().charged(),
                    support::sum(charged, charge)
                );
                assert_eq!(support::observe_state(owner, until), before);
                assert!(owner.cancel.load(Ordering::Acquire));
                assert_eq!(owner.closing, !installed);
                retention::retained(owner)
            },
            |owner, retained| {
                assert!(owner.closing && owner.cancel.load(Ordering::Acquire));
                retained(owner);
            },
        );
    }
}
