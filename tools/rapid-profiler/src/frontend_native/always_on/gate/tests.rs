//! Pure transition controls only: no assembly invocation or native qualification.
use super::*;

const RETS: [u64; 2] = [0x1018, 0x1020];
fn identity() -> Identity {
    Identity {
        gate: 0x8000,
        pid: 7,
        tid: 8,
        target: 0x1000,
        continuation: 0x5000,
    }
}
fn at_call() -> Frame {
    let mut frame = arm(Frame::default(), identity(), 0x7000, 0x9000).unwrap();
    // Values written by the static assembly immediately before CALL.
    frame.observed_target = identity().target;
    frame.pre_call_rsp = 0x8000;
    frame
}
fn entered() -> (Frame, GateEntry) {
    let mut frame = at_call();
    let token = entry(&mut frame, identity(), 0x1000, 0x7ff8, 0x5000).unwrap();
    (frame, token)
}

#[test]
fn exact_entry_each_original_ret_and_real_resume_are_required() {
    for pc in RETS {
        let (mut frame, token) = entered();
        let proof = returning(frame, identity(), &token, pc, 0x7ff8, 0x5000, &RETS).unwrap();
        assert_eq!(frame.phase, ENTERED); // Validation alone is not a completion.
        complete(&mut frame, identity(), proof, &RETS).unwrap();
        assert_eq!(frame.phase, COMPLETED);
        assert!(resumed(frame, identity(), 8352, &RETS).is_err());
        frame.resumed_rsp = 0x8000; // Actual post-CALL assembly store.
        assert_eq!(
            resumed(frame, identity(), 8352, &RETS).unwrap(),
            CallResult {
                value: 8352,
                pre_call_rsp: 0x8000,
                entry_rsp: 0x7ff8,
                resumed_rsp: 0x8000,
                return_pc: pc,
            }
        );
    }
}

#[test]
fn gate_process_thread_target_and_call_observation_cannot_be_substituted() {
    for field in 0..5 {
        let mut frame = at_call();
        match field {
            0 => frame.gate += 1,
            1 => frame.pid += 1,
            2 => frame.tid += 1,
            3 => frame.target += 1,
            _ => frame.observed_target += 1,
        }
        let before = frame;
        assert!(entry(&mut frame, identity(), 0x1000, 0x7ff8, 0x5000).is_err());
        assert_eq!(frame, before);
    }
    let mut frame = at_call();
    assert!(entry(&mut frame, identity(), 0x1001, 0x7ff8, 0x5000).is_err());
    assert!(entry(&mut frame, identity(), 0x1000, 0x7ff8, 0x5001).is_err());
}

#[test]
fn stack_extent_alignment_entry_ret_and_resumed_rsp_are_exact() {
    for (pre, rsp, start, end) in [
        (0x8008, 0x8000, 0x7000, 0x9000),    // Misaligned pre-CALL.
        (0x8000, 0x7ff0, 0x7000, 0x9000),    // Not pre-CALL minus eight.
        (0x8000, 0x7ff8, 0x7ff9, 0x9000),    // First byte inaccessible.
        (0x8000, 0x7ff8, 0x7000, 0x7fff),    // Last byte inaccessible.
        (0, u64::MAX - 7, 0x7000, u64::MAX), // Overflow/underflow.
    ] {
        let mut frame = at_call();
        frame.pre_call_rsp = pre;
        frame.stack_start = start;
        frame.stack_end = end;
        assert!(entry(&mut frame, identity(), 0x1000, rsp, 0x5000).is_err());
    }
    let (mut frame, token) = entered();
    assert!(returning(frame, identity(), &token, RETS[0], 0x7ff0, 0x5000, &RETS).is_err());
    let proof = returning(frame, identity(), &token, RETS[0], 0x7ff8, 0x5000, &RETS).unwrap();
    complete(&mut frame, identity(), proof, &RETS).unwrap();
    frame.resumed_rsp = 0x8008;
    assert!(resumed(frame, identity(), 0, &RETS).is_err());
}

#[test]
fn reentry_poison_and_counter_exhaustion_do_not_reset_outer_state() {
    for phase in [ARMED, ENTERED, COMPLETED, POISONED] {
        let old = Frame {
            phase,
            sequence: 4,
            ..Frame::default()
        };
        assert_eq!(
            arm(old, identity(), 0x7000, 0x9000),
            Err(GateError::Reentry)
        );
    }
    let old = Frame {
        sequence: u64::MAX,
        ..Frame::default()
    };
    assert_eq!(
        arm(old, identity(), 0x7000, 0x9000),
        Err(GateError::Sequence)
    );
    assert_eq!(
        arm(Frame::default(), identity(), 0, 8),
        Err(GateError::Stack)
    );
    assert_eq!(
        arm(Frame::default(), identity(), 1, 8),
        Err(GateError::Stack)
    );
}

#[test]
fn stale_token_wrong_return_word_and_unadmitted_ret_are_refused() {
    let (frame, mut token) = entered();
    assert!(
        returning(
            frame,
            identity(),
            &token,
            RETS[0] + 1,
            0x7ff8,
            0x5000,
            &RETS
        )
        .is_err()
    );
    assert!(returning(frame, identity(), &token, RETS[0], 0x7ff8, 0x5001, &RETS).is_err());
    token.sequence += 1;
    assert!(returning(frame, identity(), &token, RETS[0], 0x7ff8, 0x5000, &RETS).is_err());
    token.sequence -= 1;
    token.identity.gate += 1;
    assert!(returning(frame, identity(), &token, RETS[0], 0x7ff8, 0x5000, &RETS).is_err());
}

#[test]
fn completion_rechecks_identity_and_cannot_be_credited_twice_or_without_entry() {
    let (mut frame, token) = entered();
    let proof = returning(frame, identity(), &token, RETS[0], 0x7ff8, 0x5000, &RETS).unwrap();
    frame.sequence += 1;
    let before = frame;
    assert!(complete(&mut frame, identity(), proof, &RETS).is_err());
    assert_eq!(frame, before);
    let (mut frame, token) = entered();
    let proof = returning(frame, identity(), &token, RETS[0], 0x7ff8, 0x5000, &RETS).unwrap();
    complete(&mut frame, identity(), proof, &RETS).unwrap();
    assert!(returning(frame, identity(), &token, RETS[0], 0x7ff8, 0x5000, &RETS).is_err());
    assert!(entry(&mut frame, identity(), 0x1000, 0x7ff8, 0x5000).is_err());
    let mut no_callbacks = at_call();
    no_callbacks.resumed_rsp = no_callbacks.pre_call_rsp;
    assert!(resumed(no_callbacks, identity(), 0, &RETS).is_err());
}

#[test]
fn rust_side_failure_poison_preserves_observations() {
    let cell = UnsafeCell::new(at_call());
    let before = unsafe { cell.get().read() };
    drop(Invocation {
        frame: cell.get(),
        finished: false,
    });
    assert_eq!(
        unsafe { cell.get().read() },
        Frame {
            phase: POISONED,
            ..before
        }
    );
    unsafe {
        cell.get().write(before);
    }
    drop(Invocation {
        frame: cell.get(),
        finished: true,
    });
    assert_eq!(unsafe { cell.get().read() }, before);
}

#[test]
fn immutable_descriptor_is_send_sync_and_continuation_is_library_owned() {
    fn shared<T: Send + Sync>() {}
    shared::<CallGate>();
    let gate = CallGate {
        target: 0x1000,
        returns: RETS.into(),
        pid: 0,
    };
    assert_eq!(gate.target(), 0x1000);
    assert_eq!(gate.declared_returns(), RETS);
    assert_eq!(
        gate.continuation(),
        core::ptr::addr_of!(__rapid_profiler_ordinary_after_call_v1) as usize as u64
    );
    assert_ne!(gate.continuation(), 0);
}

#[test]
fn original_only_result_never_grants_callback_or_completion_credit() {
    let mut frame = at_call();
    frame.resumed_rsp = frame.pre_call_rsp;
    assert_eq!(
        original_resumed(frame, identity(), 42).unwrap(),
        OriginalCallResult {
            value: 42,
            pre_call_rsp: 0x8000,
            resumed_rsp: 0x8000,
        }
    );
    assert!(resumed(frame, identity(), 42, &RETS).is_err());
    for field in 0..4 {
        let mut changed = frame;
        match field {
            0 => changed.phase = COMPLETED,
            1 => changed.entry_rsp = 0x7ff8,
            2 => changed.return_word = 0x5000,
            _ => changed.return_pc = RETS[0],
        }
        assert!(original_resumed(changed, identity(), 42).is_err());
    }
    frame.resumed_rsp += 8;
    assert!(original_resumed(frame, identity(), 42).is_err());
}
