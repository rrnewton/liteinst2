//! Pure allocation and closed-dispatch controls. Fabricated census input is
//! never a native stack permit; these tests make no live execution claim.
use super::*;
use crate::lifecycle::LifecycleRegistry;
use liteinst_admission::scan::{Boundary, Snapshot, WriteControl};
use liteinst_admission::{AddressRange, Generation, MappingId};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Duration;

fn observed() -> ObservedStop {
    let model = LifecycleRegistry::new(crate::lifecycle::Limits::default(), 101, 0x400ffb).unwrap();
    let task = model.task(model.root_task()).unwrap();
    ObservedStop {
        token: DynamicStop {
            session: 431,
            sequence: 9,
            tid: 101,
            task: Some(task.id),
        },
        task: DynamicTask {
            task: task.id,
            process: task.process,
            address_space: task.address_space,
            generation: 0,
        },
        logical_pc: 0x400ffb,
        registers: RegisterSnapshot {
            r15: 15,
            r14: 14,
            r13: 13,
            r12: 12,
            rbp: 11,
            rbx: 10,
            r11: 9,
            r10: 8,
            r9: 7,
            r8: 6,
            rax: 5,
            rcx: 4,
            rdx: 3,
            rsi: 2,
            rdi: 1,
            orig_rax: u64::MAX,
            rip: 0x400ffb,
            cs: 0x33,
            eflags: 0x202,
            rsp: 0x700ff8,
            ss: 0x2b,
            fs_base: 0,
            gs_base: 0,
            ds: 0,
            es: 0,
            fs: 0,
            gs: 0,
        },
        xstate: vec![0x5a; 4096],
        signal_mask: 0x800,
        phase: StopPhase::UserCheckpoint,
        signal: None,
    }
}
fn limits() -> census::Limits {
    census::Limits {
        epochs: 16,
        source_fact_bytes: 64 * 1024 * 1024,
        reports: 128,
        origins: 32,
        witnesses: 256,
        plan_history: 128,
    }
}
fn geometry(call: bool) -> maps::FetchGeometry {
    use super::super::super::source_identity::{FileIdentity, ImageRole, SourceVma};
    maps::FetchGeometry::for_instruction(
        SourceVma {
            original_index: 0,
            current_index: 0,
            original_span: (0, 60),
            current_span: (0, 60),
            start: 0x400000,
            end: 0x402000,
            offset: 0,
            file: FileIdentity {
                major: 8,
                minor: 2,
                inode: 17,
            },
            role: ImageRole::Executable,
        },
        AddressRange::new(0x400ffb, 0x400ffb + if call { 5 } else { 1 }).unwrap(),
    )
    .unwrap()
}
fn attempt(call: bool) -> (ResumeCensus, Box<RuntimeStackAttempt>) {
    let before = observed();
    let stop = AdmissionStop {
        token: before.token.clone(),
        identity: before.task,
        phase: AdmissionPhase::Restored,
        signal: None,
    };
    let mut census = ResumeCensus::new(431, before.task.address_space, 0, limits()).unwrap();
    let initial = census
        .reserve(initial_runtime_origin_charge(MAX_XSTATE).unwrap())
        .unwrap();
    let origin = census
        .insert(
            initial,
            OriginKind::CurrentHeldPc,
            before.logical_pc,
            before.clone(),
        )
        .unwrap();
    census.finish_reservation(initial).unwrap();
    let reservation = census
        .reserve(storage::attempt_charge(8192, call).unwrap())
        .unwrap();
    let pending = PendingPreparation {
        reservation,
        origin,
        serial: 1,
        until: Instant::now() + Duration::from_secs(3),
        stage: AttemptStage::Allocated,
        failure: None,
    };
    let attempt = exact_storage::value(RuntimeStackAttempt::empty(
        &pending,
        stop,
        &before,
        geometry(call),
        8192,
        call,
    ))
    .unwrap();
    (census, attempt)
}
fn actual_owners(attempt: &RuntimeStackAttempt) -> usize {
    let mut result = size_of::<RuntimeStackAttempt>()
        + attempt.before.xstate.capacity()
        + attempt.source.checkpoint.xstate.capacity()
        + attempt.source.identity.capacity()
        + attempt
            .source
            .bytes
            .iter()
            .map(Vec::capacity)
            .sum::<usize>()
        + attempt.native.allocated_bytes().unwrap()
        - size_of::<PreparedStackNative>()
        + attempt.operand.allocated_bytes().unwrap()
        - size_of::<PreparedStackOperandCapture>();
    if let Some(census) = &attempt.census {
        result += census.allocated_bytes().unwrap();
    }
    if let Some(call) = &attempt.call {
        result += call.allocated_bytes().unwrap();
    }
    result
}
fn root_pointers(attempt: &RuntimeStackAttempt) -> Vec<(usize, usize, usize)> {
    [
        &attempt.before.xstate,
        &attempt.source.checkpoint.xstate,
        &attempt.source.identity,
        &attempt.source.bytes[0],
        &attempt.source.bytes[1],
        &attempt.source.bytes[2],
    ]
    .map(|v| (v.as_ptr() as usize, v.len(), v.capacity()))
    .to_vec()
}

#[test]
fn runtime_stack_default_profile_preserves_explicit_refusal() {
    assert_eq!(
        crate::DynamicRuntimeOptions::default().stack,
        crate::RuntimeStackProfile::Refuse
    );
}
#[test]
fn runtime_stack_dispatch_requires_exact_unprefixed_call_or_return() {
    let cases: &[(&[u8], bool)] = &[
        (&[0xe8, 0, 0, 0, 0], true),
        (&[0xc3], true),
        (&[0x48, 0xe8, 0, 0, 0, 0], false),
        (&[0x66, 0xe8, 0, 0, 0, 0], false),
        (&[0x67, 0xe8, 0, 0, 0, 0], false),
        (&[0x48, 0xc3], false),
        (&[0x66, 0xc3], false),
        (&[0xc2, 8, 0], false),
        (&[0xcb], false),
        (&[0xca, 8, 0], false),
        (&[0xff, 0xd0], false),
        (&[0xff, 0x10], false),
        (&[0xff, 0xe0], false),
        (&[0x50], false),
        (&[0x58], false),
        (&[0x48, 0x8b, 0x00], false),
        (&[0x0f, 0xa2], false),
        (&[0x0f, 0x05], false),
        (&[0x90], false),
    ];
    let before = observed();
    for (bytes, accepted) in cases {
        let snapshot = Snapshot::new(
            MappingId(81),
            Generation(0),
            before.logical_pc,
            bytes.to_vec(),
            Boundary::Unknown,
            Boundary::Unknown,
            WriteControl::Owned,
        )
        .unwrap();
        let classification = classify(
            &snapshot,
            &before.registers,
            DebugDisposition::Absent,
            &SyscallAliases::default(),
        );
        assert_eq!(
            classification.as_ref().is_ok_and(stack_candidate),
            *accepted,
            "{bytes:x?}"
        );
    }
}
#[test]
fn runtime_stack_reservation_has_exact_axes_and_call_increment() {
    let ret = storage::attempt_charge(8192, false).unwrap();
    let call = storage::attempt_charge(8192, true).unwrap();
    assert_eq!(
        (
            ret.epochs,
            ret.reports,
            ret.origins,
            ret.witnesses,
            ret.plan_history
        ),
        (0, 0, 1, 7, 0)
    );
    assert_eq!(
        (
            call.epochs,
            call.reports,
            call.origins,
            call.witnesses,
            call.plan_history
        ),
        (0, 0, 1, 7, 0)
    );
    assert_eq!(
        call.source_fact_bytes - ret.source_fact_bytes,
        PreparedCallRecord::reservation_bytes().unwrap()
    );
    assert_eq!(
        storage::attempt_charge(4096, false)
            .unwrap()
            .source_fact_bytes
            + 3 * 4096,
        ret.source_fact_bytes
    );
    assert!(storage::attempt_charge(usize::MAX, false).is_err());
    assert!(RuntimeStackState::startup_reservation(0).is_err());
    assert!(RuntimeStackState::startup_reservation(usize::MAX).is_err());
}
#[test]
fn runtime_stack_startup_owns_fixed_indices_and_profile_once() {
    let maximum = RuntimeStackState::startup_reservation(32).unwrap();
    let mut state = RuntimeStackState::empty(32, maximum);
    assert_eq!(state.startup_payload_bytes().unwrap(), 0);
    assert!(state.profile.identity().is_err());
    state.allocate_startup().unwrap();
    assert_eq!(state.attempts.len(), 32);
    assert!(state.attempts.iter().all(Option::is_none));
    assert_eq!(state.count, 0);
    assert_eq!(
        state.startup_actual,
        3 * MAX_XSTATE + 64 * size_of::<Option<Box<RuntimeStackAttempt>>>()
    );
    assert!(state.startup_actual < maximum);
    assert_eq!(state.startup_settled, 0);
    assert!(state.profile.identity().is_err());
    let actual = state.startup_payload_bytes().unwrap();
    assert!(state.allocate_startup().is_err());
    assert_eq!(state.startup_payload_bytes().unwrap(), actual);
}
#[test]
fn runtime_stack_root_allocation_errors_settle_every_installed_prefix() {
    for call in [false, true] {
        for ordinal in 0..if call { 12 } else { 10 } {
            let (mut census, mut attempt) = attempt(call);
            let before = census.current_observation(attempt.origin).unwrap().clone();
            let used = census.used();
            let charged = census.charged();
            attempt.allocation_fault.before = Some(ordinal);
            assert!(attempt.allocate_and_settle(&mut census).is_err());
            assert_eq!(attempt.allocation_ordinal, Some(ordinal));
            assert!(!attempt.allocated);
            assert!(attempt.settlement_failure.is_none());
            assert_eq!(
                census.used().source_fact_bytes - used.source_fact_bytes,
                actual_owners(&attempt)
            );
            assert_eq!(census.used().origins, used.origins);
            assert_eq!(census.used().witnesses, used.witnesses);
            assert_eq!(census.charged(), charged);
            assert_eq!(census.current_observation(attempt.origin).unwrap(), &before);
            assert!(attempt.native.progress().effects().is_empty());
            assert!(attempt.operand.operand().is_err());
            let pointers = root_pointers(&attempt);
            let settled = census.used();
            let first = attempt.failure;
            assert!(attempt.allocate_and_settle(&mut census).is_err());
            assert_eq!(census.used(), settled);
            assert_eq!(root_pointers(&attempt), pointers);
            assert_eq!(attempt.failure, first);
        }
    }
}
#[test]
fn runtime_stack_root_allocation_unwinds_settle_before_original_rethrow() {
    for call in [false, true] {
        for ordinal in 0..if call { 12 } else { 10 } {
            let (mut census, mut attempt) = attempt(call);
            let before = census.current_observation(attempt.origin).unwrap().clone();
            let used = census.used();
            let charged = census.charged();
            attempt.allocation_fault.after = Some(ordinal);
            let panic = catch_unwind(AssertUnwindSafe(|| {
                attempt.allocate_and_settle(&mut census)
            }))
            .unwrap_err();
            assert_eq!(*panic.downcast::<u32>().unwrap(), 0x5354_4143);
            assert_eq!(attempt.failure, Some(Failure::Unwound));
            assert_eq!(attempt.allocation_ordinal, Some(ordinal));
            assert!(attempt.settlement_failure.is_none());
            assert_eq!(
                census.used().source_fact_bytes - used.source_fact_bytes,
                actual_owners(&attempt)
            );
            assert_eq!(census.charged(), charged);
            assert_eq!(census.current_observation(attempt.origin).unwrap(), &before);
            assert!(attempt.native.progress().effects().is_empty());
            assert!(attempt.operand.operand().is_err());
            let pointers = root_pointers(&attempt);
            let settled = census.used();
            assert!(attempt.allocate_and_settle(&mut census).is_err());
            assert_eq!(census.used(), settled);
            assert_eq!(root_pointers(&attempt), pointers);
        }
    }
}
#[test]
fn runtime_stack_complete_allocation_preserves_input_and_keeps_temporary_headroom() {
    for call in [false, true] {
        let (mut census, mut attempt) = attempt(call);
        let before = census.current_observation(attempt.origin).unwrap().clone();
        let used = census.used();
        let charged = census.charged();
        attempt.allocate_and_settle(&mut census).unwrap();
        let pointers = root_pointers(&attempt);
        attempt.copy_before(&before).unwrap();
        assert_eq!(attempt.before, before);
        assert_eq!(attempt.source.checkpoint, before);
        let after = root_pointers(&attempt);
        for (old, new) in pointers.iter().zip(&after) {
            assert_eq!(old.0, new.0);
            assert_eq!(old.2, new.2);
        }
        assert_eq!(
            census.used().source_fact_bytes - used.source_fact_bytes,
            actual_owners(&attempt)
        );
        assert!(
            actual_owners(&attempt)
                < storage::attempt_charge(8192, call)
                    .unwrap()
                    .source_fact_bytes
        );
        assert_eq!(census.charged(), charged);
        assert!(attempt.native.progress().effects().is_empty());
        assert!(attempt.operand.operand().is_err());
    }
}

#[test]
fn runtime_stack_startup_partial_errors_keep_exact_payload_prefixes() {
    let slots = 32 * size_of::<Option<Box<RuntimeStackAttempt>>>();
    for ordinal in 0..3 {
        let reserved = RuntimeStackState::startup_reservation(32).unwrap();
        let mut state = RuntimeStackState::empty(32, reserved);
        state.startup_fault.before = Some(ordinal);
        assert!(state.allocate_startup().is_err());
        let expected = match ordinal {
            0 => 0,
            1 => 3 * MAX_XSTATE,
            2 => 3 * MAX_XSTATE + slots,
            _ => unreachable!(),
        };
        assert_eq!(state.startup_actual, expected);
        assert_eq!(state.startup_payload_bytes().unwrap(), expected);
        assert_eq!(state.startup_reserved, reserved);
        assert_eq!(state.startup_settled, 0);
        assert_eq!(state.startup_ordinal, Some(ordinal));
        assert!(!state.startup_complete);
        assert!(state.settlement_failure.is_none());
        assert!(state.profile.identity().is_err());
        let pointer = state.attempts.as_ptr();
        let first = state.failure;
        assert!(state.allocate_startup().is_err());
        assert_eq!(state.attempts.as_ptr(), pointer);
        assert_eq!(state.failure, first);
        assert_eq!(state.startup_payload_bytes().unwrap(), expected);
    }
}
#[test]
fn runtime_stack_startup_partial_unwinds_keep_exact_payload_prefixes() {
    let slots = 32 * size_of::<Option<Box<RuntimeStackAttempt>>>();
    for ordinal in 0..3 {
        let reserved = RuntimeStackState::startup_reservation(32).unwrap();
        let mut state = RuntimeStackState::empty(32, reserved);
        state.startup_fault.after = Some(ordinal);
        let panic = catch_unwind(AssertUnwindSafe(|| state.allocate_startup())).unwrap_err();
        assert_eq!(*panic.downcast::<u32>().unwrap(), 0x5354_4152);
        let expected = 3 * MAX_XSTATE + ordinal * slots;
        assert_eq!(state.startup_actual, expected);
        assert_eq!(state.startup_payload_bytes().unwrap(), expected);
        assert_eq!(state.startup_reserved, reserved);
        assert_eq!(state.startup_settled, 0);
        assert_eq!(state.failure, Some(Failure::Unwound));
        assert!(!state.startup_complete);
        assert!(state.settlement_failure.is_none());
        assert!(state.profile.identity().is_err());
        let pointer = state.attempts.as_ptr();
        assert!(state.allocate_startup().is_err());
        assert_eq!(state.attempts.as_ptr(), pointer);
        assert_eq!(state.startup_payload_bytes().unwrap(), expected);
    }
}
#[test]
fn runtime_stack_installed_header_settles_without_claiming_payload_or_permit() {
    let (mut census, mut attempt) = attempt(true);
    let used = census.used();
    let charged = census.charged();
    let pointer = (&*attempt) as *const RuntimeStackAttempt;
    attempt.settle_unstarted_header(&mut census);
    assert_eq!(
        census.used().source_fact_bytes - used.source_fact_bytes,
        size_of::<RuntimeStackAttempt>()
    );
    assert_eq!(attempt.settled, size_of::<RuntimeStackAttempt>());
    assert_eq!((&*attempt) as *const RuntimeStackAttempt, pointer);
    assert!(!attempt.allocation_started);
    assert!(!attempt.allocated);
    assert!(attempt.census.is_none());
    assert!(attempt.call.is_none());
    assert_eq!(
        attempt.native.allocated_bytes().unwrap(),
        size_of::<PreparedStackNative>()
    );
    assert_eq!(
        attempt.operand.allocated_bytes().unwrap(),
        size_of::<PreparedStackOperandCapture>()
    );
    assert!(attempt.operand.operand().is_err());
    assert!(attempt.native.progress().effects().is_empty());
    let settled = census.used();
    attempt.settle_unstarted_header(&mut census);
    assert_eq!(census.used(), settled);
    assert_eq!(census.charged(), charged);
}
#[test]
fn runtime_stack_header_settlement_failure_retains_original_failure_and_owner() {
    let (_census, mut attempt) = attempt(true);
    let (mut foreign, _foreign_attempt) = self::attempt(false);
    let used = foreign.used();
    let charged = foreign.charged();
    let pointer = (&*attempt) as *const RuntimeStackAttempt;
    attempt.failure = Some(Failure::Unwound);
    attempt.settle_unstarted_header(&mut foreign);
    assert_eq!(attempt.failure, Some(Failure::Unwound));
    assert!(attempt.settlement_failure.is_some());
    assert_eq!(attempt.settled, 0);
    assert_eq!(foreign.used(), used);
    assert_eq!(foreign.charged(), charged);
    assert_eq!((&*attempt) as *const RuntimeStackAttempt, pointer);
    assert!(attempt.allocate_and_settle(&mut foreign).is_err());
    assert_eq!(attempt.failure, Some(Failure::Unwound));
    assert_eq!(foreign.used(), used);
}

#[test]
fn runtime_stack_startup_nested_profile_failures_keep_each_real_payload() {
    for ordinal in 0..3 {
        for unwind in [false, true] {
            let reserved = RuntimeStackState::startup_reservation(32).unwrap();
            let mut state = RuntimeStackState::empty(32, reserved);
            state
                .profile
                .set_allocation_fault((!unwind).then_some(ordinal), unwind.then_some(ordinal));
            let result = catch_unwind(AssertUnwindSafe(|| state.allocate_startup()));
            if unwind {
                let panic = result.unwrap_err();
                assert_eq!(
                    panic.downcast_ref::<&str>(),
                    Some(&"owned stack allocation model unwind")
                );
                assert_eq!(state.failure, Some(Failure::Unwound));
            } else {
                assert!(result.unwrap().is_err());
            }
            let expected = (ordinal + usize::from(unwind)) * MAX_XSTATE;
            assert_eq!(state.startup_actual, expected);
            assert_eq!(state.startup_payload_bytes().unwrap(), expected);
            assert_eq!(state.startup_reserved, reserved);
            assert_eq!(state.startup_settled, 0);
            assert!(state.attempts.is_empty());
            assert_eq!(
                state.calls.allocated_bytes().unwrap(),
                size_of::<RuntimeCallLedger>()
            );
            assert!(state.profile.identity().is_err());
            assert!(state.settlement_failure.is_none());
            let first = state.failure;
            assert!(state.allocate_startup().is_err());
            assert_eq!(state.failure, first);
            assert_eq!(state.startup_payload_bytes().unwrap(), expected);
        }
    }
}
#[test]
fn runtime_stack_nested_native_and_word_failures_settle_each_real_prefix() {
    // 18 native allocation stages include the three complete B/C/D owners;
    // their nine inner payload points are independently injected below.
    for family in 0..5 {
        let count = if family == 0 { 18 } else { 3 };
        for ordinal in 0..count {
            for unwind in [false, true] {
                let (mut census, mut attempt) = attempt(true);
                let used = census.used();
                let charged = census.charged();
                let before = census.current_observation(attempt.origin).unwrap().clone();
                let fault_before = (!unwind).then_some(ordinal);
                let fault_after = unwind.then_some(ordinal);
                match family {
                    0 => attempt
                        .native
                        .set_allocation_fault(fault_before, fault_after),
                    1..=3 => attempt.native.set_word_allocation_fault(
                        family - 1,
                        fault_before,
                        fault_after,
                    ),
                    4 => attempt
                        .operand
                        .set_allocation_fault(fault_before, fault_after),
                    _ => unreachable!(),
                }
                let result = catch_unwind(AssertUnwindSafe(|| {
                    attempt.allocate_and_settle(&mut census)
                }));
                if unwind {
                    let panic = result.unwrap_err();
                    let message = if family == 0 {
                        "owned stack native allocation model unwind"
                    } else {
                        "owned stack allocation model unwind"
                    };
                    assert_eq!(panic.downcast_ref::<&str>(), Some(&message));
                    assert_eq!(attempt.failure, Some(Failure::Unwound));
                } else {
                    assert!(result.unwrap().is_err());
                }
                let completed = ordinal + usize::from(unwind);
                let nested_payloads = match family {
                    0 if ordinal < 15 => completed,
                    0 => 15 + 3 * (completed - 15),
                    1..=3 => 15 + 3 * (family - 1) + completed,
                    4 => 24 + completed,
                    _ => unreachable!(),
                };
                let expected = size_of::<RuntimeStackAttempt>()
                    + (3 + nested_payloads) * MAX_XSTATE
                    + 3 * 8192;
                assert_eq!(actual_owners(&attempt), expected);
                assert_eq!(
                    census.used().source_fact_bytes - used.source_fact_bytes,
                    expected
                );
                assert_eq!(census.charged(), charged);
                assert_eq!(census.current_observation(attempt.origin).unwrap(), &before);
                assert_eq!(census.used().origins, used.origins);
                assert_eq!(census.used().witnesses, used.witnesses);
                assert!(attempt.census.is_none());
                assert!(attempt.call.is_none());
                assert!(attempt.settlement_failure.is_none());
                assert!(attempt.operand.operand().is_err());
                assert!(attempt.native.progress().effects().is_empty());
                let pointers = root_pointers(&attempt);
                let settled = census.used();
                let first = attempt.failure;
                assert!(attempt.allocate_and_settle(&mut census).is_err());
                assert_eq!(root_pointers(&attempt), pointers);
                assert_eq!(attempt.failure, first);
                assert_eq!(census.used(), settled);
            }
        }
    }
}

#[test]
fn runtime_stack_nested_census_and_call_failures_settle_each_real_prefix() {
    for is_call in [false, true] {
        let targets = if is_call {
            &[StackAllocationTarget::Census, StackAllocationTarget::Call][..]
        } else {
            &[StackAllocationTarget::Census][..]
        };
        for &target in targets {
            let count = if target == StackAllocationTarget::Census {
                17
            } else {
                1
            };
            for ordinal in 0..count {
                for unwind in [false, true] {
                    let (mut census, mut attempt) = attempt(is_call);
                    let used = census.used();
                    let charged = census.charged();
                    let before = census.current_observation(attempt.origin).unwrap().clone();
                    attempt.configure_allocation(StackAllocationFault {
                        target,
                        ordinal,
                        unwind,
                    });
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        attempt.allocate_and_settle(&mut census)
                    }));
                    if unwind {
                        let sentinel = if target == StackAllocationTarget::Census {
                            0x5354_434e_u32
                        } else {
                            0x5343_414c_u32
                        };
                        assert_eq!(*result.unwrap_err().downcast::<u32>().unwrap(), sentinel);
                        assert_eq!(attempt.failure, Some(Failure::Unwound));
                    } else {
                        assert!(result.unwrap().is_err());
                        assert!(attempt.failure.is_some());
                    }
                    let completed = ordinal + usize::from(unwind);
                    // Root: two states, one map and three source windows.
                    // Native: fifteen core payloads and nine word payloads.
                    // A: three payloads. Each state/map payload has fixed MAX size.
                    let common = size_of::<RuntimeStackAttempt>()
                        + 29 * MAX_XSTATE
                        + MAP_BYTES
                        + 3 * 8192
                        + size_of::<PreparedStackCensus>();
                    let evidence = PreparedStackCensus::test_evidence_bytes();
                    let expected = if target == StackAllocationTarget::Census {
                        common
                            + completed.min(16) * MAX_XSTATE
                            + usize::from(completed == 17) * evidence
                    } else {
                        common
                            + 16 * MAX_XSTATE
                            + evidence
                            + size_of::<PreparedCallRecord>()
                            + completed * MAX_XSTATE
                    };
                    assert_eq!(actual_owners(&attempt), expected);
                    let mut expected_used = used;
                    expected_used.source_fact_bytes += expected;
                    assert_eq!(census.used(), expected_used);
                    assert_eq!(census.charged(), charged);
                    assert_eq!(census.current_observation(attempt.origin).unwrap(), &before);
                    assert!(attempt.census.is_some());
                    assert_eq!(
                        attempt.call.is_some(),
                        target == StackAllocationTarget::Call
                    );
                    assert!(!attempt.allocated);
                    assert!(attempt.settlement_failure.is_none());
                    assert!(attempt.operand.operand().is_err());
                    assert!(attempt.native.progress().effects().is_empty());
                    let pointers = root_pointers(&attempt);
                    let first = attempt.failure;
                    assert!(attempt.allocate_and_settle(&mut census).is_err());
                    assert_eq!(attempt.failure, first);
                    assert_eq!(root_pointers(&attempt), pointers);
                    assert_eq!(actual_owners(&attempt), expected);
                    assert_eq!(census.used(), expected_used);
                }
            }
        }
    }
}

#[test]
fn runtime_stack_closed_fault_configuration_rejects_reuse_and_out_of_bounds() {
    let targets = [
        (StackAllocationTarget::Profile, 3),
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
        for unwind in [false, true] {
            for ordinal in 0..bound {
                let reserved = RuntimeStackState::startup_reservation(32).unwrap();
                let mut state = RuntimeStackState::empty(32, reserved);
                let fault = StackAllocationFault {
                    target,
                    ordinal,
                    unwind,
                };
                state.configure_allocation(fault);
                assert_eq!(state.allocation_config, Some(fault));
                assert_eq!(
                    state.allocation_config_used,
                    target == StackAllocationTarget::Profile
                );
                assert_eq!(state.startup_payload_bytes().unwrap(), 0);
                assert!(state.profile.identity().is_err());
                assert!(
                    catch_unwind(AssertUnwindSafe(|| state.configure_allocation(fault))).is_err()
                );
                assert_eq!(state.allocation_config, Some(fault));
                assert_eq!(state.startup_payload_bytes().unwrap(), 0);
            }
            for ordinal in [bound, usize::MAX] {
                let fault = StackAllocationFault {
                    target,
                    ordinal,
                    unwind,
                };
                assert!(catch_unwind(|| fault.pair()).is_err());
            }
        }
    }
    let invalid_word = StackAllocationFault {
        target: StackAllocationTarget::Word(3),
        ordinal: 0,
        unwind: false,
    };
    assert!(catch_unwind(|| invalid_word.pair()).is_err());
    for target in [StackAllocationTarget::Root, StackAllocationTarget::Call] {
        let (_census, mut ret) = attempt(false);
        let fault = StackAllocationFault {
            target,
            ordinal: if target == StackAllocationTarget::Root {
                10
            } else {
                0
            },
            unwind: false,
        };
        assert!(catch_unwind(AssertUnwindSafe(|| ret.configure_allocation(fault))).is_err());
        assert_eq!(actual_owners(&ret), size_of::<RuntimeStackAttempt>());
        assert!(ret.nested_fault.is_none());
        assert!(ret.native.progress().effects().is_empty());
    }
}
