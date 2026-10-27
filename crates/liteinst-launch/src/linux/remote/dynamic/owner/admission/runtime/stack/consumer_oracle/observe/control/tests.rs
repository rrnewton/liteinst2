//! Supplied-record and allocation controls only. No Owner, ptrace, wait, live
//! stop, completed production profile or execution permission is constructed.
use super::*;

fn state() -> StateSlot {
    let mut state = super::super::empty_state();
    super::super::allocate_state(&mut state).unwrap();
    state.state.xstate.truncate(840);
    state.state.registers.rip = 0x201000;
    state.state.registers.rsp = 0x8000;
    state.state.registers.cs = 0x33;
    state.state.registers.ss = 0x2b;
    state.state.registers.eflags = 0x202;
    let success = Some(Request {
        result: 0,
        errno: None,
    });
    state.registers_request = success;
    state.xstate_request = success;
    state.mask_request = success;
    state.requested_pointer = state.state.xstate.as_ptr() as usize;
    state.returned_pointer = state.requested_pointer;
    state.returned_length = state.state.xstate.len();
    state.complete = true;
    state
}
fn initial() -> DynamicStop {
    DynamicStop {
        session: 7,
        tid: 42,
        task: None,
        sequence: 1,
    }
}
fn exec(state: &StateSlot, until: Instant) -> ExecAssociation {
    ExecAssociation {
        initial: initial(),
        until,
        state: StateStamp::of(state),
    }
}
fn profile() -> Box<ControlProfile> {
    let mut profile = exact_storage::value(ControlProfile::default()).unwrap();
    profile.debug.values = [0, 0, 0, 0, INITIAL_DEBUG, 0];
    profile.debug.requests = std::array::from_fn(|i| {
        Some(Request {
            result: profile.debug.values[i] as i64,
            errno: None,
        })
    });
    profile.rseq_request = Some(Request {
        result: 24,
        errno: None,
    });
    // Descriptive predicate model only; ControlProfile.complete stays false.
    profile.cet.complete = true;
    profile
}
fn observed(profile: &ControlProfile, state: &StateSlot, until: Instant) -> ExecObservation {
    ExecObservation {
        association: Some(exec(state, until)),
        before: Some(ReadResult::Ok),
        debug: Some(ReadResult::Ok),
        rseq: Some(ReadResult::Ok),
        rseq_pointer: profile.rseq.as_ptr() as usize,
        cet: Some(ReadResult::Ok),
        debug_required: Some(ReadResult::Ok),
        after: Some(ReadResult::Ok),
        complete: true,
    }
}
#[test]
fn consumer_observer_exec_control_keeps_content_descriptive_without_profile_completion() {
    let state = state();
    let until = Instant::now();
    let mut profile = profile();
    let record = observed(&profile, &state, until);
    record.require(&profile, &state, until).unwrap();
    assert!(profile.require(INITIAL_DEBUG).is_err());
    for index in 0..24 {
        profile.rseq[index] = 1;
        record.require(&profile, &state, until).unwrap();
        assert_eq!(profile.rseq[index], 1);
        assert!(profile.require(INITIAL_DEBUG).is_err());
        profile.rseq[index] = 0;
    }
    let mut unobserved = ExecObservation::empty();
    assert!(unobserved.require(&profile, &state, until).is_err());
    unobserved.complete = true;
    assert!(unobserved.require(&profile, &state, until).is_err());
}
#[test]
fn consumer_observer_exec_control_rejects_transport_debug_cet_and_partial_results() {
    let state = state();
    let until = Instant::now();
    let mut profile = profile();
    let mut record = observed(&profile, &state, until);
    for result in [-1, 0, 23, 25] {
        profile.rseq_request = Some(Request {
            result,
            errno: None,
        });
        assert!(record.require(&profile, &state, until).is_err());
    }
    profile.rseq_request = Some(Request {
        result: 24,
        errno: Some(libc::EIO),
    });
    assert!(
        matches!(require_rseq_transport(profile.rseq_request.unwrap()),
        Err(LaunchError::System { operation: "PTRACE_GET_RSEQ_CONFIGURATION", source })
        if source.raw_os_error() == Some(libc::EIO))
    );
    assert!(record.require(&profile, &state, until).is_err());
    profile.rseq_request = Some(Request {
        result: 24,
        errno: None,
    });
    for index in 0..6 {
        profile.debug.values[index] ^= 1;
        assert!(record.require(&profile, &state, until).is_err());
        profile.debug.values[index] ^= 1;
        let request = profile.debug.requests[index];
        profile.debug.requests[index] = None;
        assert!(record.require(&profile, &state, until).is_err());
        profile.debug.requests[index] = request;
    }
    profile.cet.complete = false;
    assert!(record.require(&profile, &state, until).is_err());
    profile.cet.complete = true;
    for index in 0..6 {
        let field = match index {
            0 => &mut record.before,
            1 => &mut record.debug,
            2 => &mut record.rseq,
            3 => &mut record.cet,
            4 => &mut record.debug_required,
            _ => &mut record.after,
        };
        *field = None;
        assert!(record.require(&profile, &state, until).is_err());
        record = observed(&profile, &state, until);
    }
    record.rseq_pointer ^= 8;
    assert!(record.require(&profile, &state, until).is_err());
    record.rseq_pointer ^= 8;
    record.complete = false;
    assert!(record.require(&profile, &state, until).is_err());
    let original: Result<(), LaunchError> = Err(LaunchError::Timeout("original"));
    assert_eq!(ReadResult::of(&original), ReadResult::Timeout("original"));
    assert!(matches!(original, Err(LaunchError::Timeout("original"))));
}
#[test]
fn consumer_observer_entry_control_requires_distinct_phase_wait_state_and_deadline() {
    let mut state = state();
    let until = Instant::now();
    let exec = exec(&state, until);
    let stopped = |signal| (signal << 8) | 0x7f;
    let actual = (42, stopped(libc::SIGTRAP | 0x80));
    let original = EntryAssociation {
        initial: initial(),
        phase: EntryPhase::ExecExit,
        wait_index: 0,
        actual,
        until,
        state: StateStamp::of(&state),
    };
    original
        .require(&exec, EntryPhase::ExecExit, actual, &state)
        .unwrap();
    for field in 0..9 {
        let mut changed = original.clone();
        match field {
            0 => changed.initial.session += 1,
            1 => changed.initial.sequence += 1,
            2 => changed.initial.tid += 1,
            3 => changed.phase = EntryPhase::Restored,
            4 => changed.wait_index = 1,
            5 => changed.actual.0 += 1,
            6 => changed.actual.1 = stopped(libc::SIGTRAP),
            7 => changed.until += std::time::Duration::from_nanos(1),
            _ => changed.state.pointer ^= 8,
        }
        assert_ne!(changed, original);
        assert!(
            changed
                .require(&exec, EntryPhase::ExecExit, actual, &state)
                .is_err()
        );
    }
    state.state.registers.r15 ^= 1;
    assert!(
        original
            .require(&exec, EntryPhase::ExecExit, actual, &state)
            .is_err()
    );
    state.state.registers.r15 ^= 1;
    state.state.mask ^= 1;
    assert!(
        original
            .require(&exec, EntryPhase::ExecExit, actual, &state)
            .is_err()
    );
    state.state.mask ^= 1;
    state.returned_length -= 1;
    assert!(
        original
            .require(&exec, EntryPhase::ExecExit, actual, &state)
            .is_err()
    );
    state.returned_length += 1;
    state.complete = false;
    assert!(
        original
            .require(&exec, EntryPhase::ExecExit, actual, &state)
            .is_err()
    );
    state.complete = true;
    let restored_wait = (42, stopped(libc::SIGTRAP));
    let restored = EntryAssociation {
        phase: EntryPhase::Restored,
        wait_index: 1,
        actual: restored_wait,
        ..original.clone()
    };
    restored
        .require(&exec, EntryPhase::Restored, restored_wait, &state)
        .unwrap();
    assert!(
        original
            .require(&exec, EntryPhase::Restored, restored_wait, &state)
            .is_err()
    );
    assert!(
        restored
            .require(&exec, EntryPhase::ExecExit, actual, &state)
            .is_err()
    );
    // A descriptive association is insufficient: no native capture completed.
    let mut incomplete = EntryControl::empty();
    incomplete.association = Some(original);
    assert!(
        incomplete
            .require(&exec, EntryPhase::ExecExit, actual, &state)
            .is_err()
    );
    incomplete.allocate().unwrap_err();
}
#[test]
fn consumer_observer_entry_control_storage_retains_exact_prefix_and_refuses_reuse() {
    let mut controls = EntryControls::empty();
    assert_eq!(controls.allocated_payload_bytes(), 0);
    assert_eq!(
        EntryControls::reserved_payload_bytes(),
        2 * size_of::<ControlProfile>()
    );
    controls.allocation_started = true;
    controls.exit.allocate().unwrap();
    let pointer = (&**controls.exit.profile.as_ref().unwrap() as *const ControlProfile) as usize;
    assert_eq!(
        controls.allocated_payload_bytes(),
        size_of::<ControlProfile>()
    );
    assert!(controls.allocate().is_err());
    assert!(controls.restored.profile.is_none());
    assert_eq!(
        (&**controls.exit.profile.as_ref().unwrap() as *const ControlProfile) as usize,
        pointer
    );
    assert!(!controls.allocated && !controls.exit.complete);
    let mut complete = EntryControls::empty();
    complete.allocate().unwrap();
    assert_eq!(
        complete.allocated_payload_bytes(),
        EntryControls::reserved_payload_bytes()
    );
    let exit = (&**complete.exit.profile.as_ref().unwrap() as *const ControlProfile) as usize;
    let restored =
        (&**complete.restored.profile.as_ref().unwrap() as *const ControlProfile) as usize;
    assert_ne!(exit, restored);
    assert!(complete.allocate().is_err());
    assert!(!complete.exit.complete && !complete.restored.complete);
    assert!(
        complete
            .exit
            .profile
            .as_ref()
            .unwrap()
            .require(INITIAL_DEBUG)
            .is_err()
    );
    assert!(
        complete
            .restored
            .profile
            .as_ref()
            .unwrap()
            .require(INITIAL_DEBUG)
            .is_err()
    );
}
