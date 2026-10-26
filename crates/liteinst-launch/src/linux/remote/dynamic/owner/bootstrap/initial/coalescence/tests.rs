//! Pure storage/failure controls. No Owner, held stop, syscall, completed native
//! proof or census authority is constructed by these supplied-data fixtures.
use super::*;
use crate::linux::{EntryEvidence, FirstImage};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Duration;

fn original() -> Vec<u8> {
    concat!(
        "00400000-00401000 r--p 00000000 08:02 17    /main\n",
        "00401000-00402000 r-xp 00001000 08:02 17    /main\n",
        "00600000-00601000 rw-p 00000000 00:00 0\n",
        "00700000-00701000 r-xp 00000000 00:00 0  [vdso]\n",
    )
    .as_bytes()
    .to_vec()
}
fn prepared(raw: &[u8]) -> PreparedInitialCoalescence {
    let entry = EntryEvidence {
        first_image: FirstImage::Executable,
        executable_entry: 0x401000,
        interpreter_base: 0,
        initial_instruction: 0x401000,
        interpreter: None,
    };
    let plan = InitialMapPlan::select(raw, &entry, (8, 2, 17))
        .unwrap()
        .unwrap();
    PreparedInitialCoalescence::installed(plan, raw, Instant::now() + Duration::from_secs(1))
        .unwrap()
}

#[test]
fn coalescence_exact_layout_helpers_refuse_overflow_and_preserve_empty_ownership() {
    let mut values = storage::vector::<u64>(5).unwrap();
    assert_eq!(values.len(), 0);
    assert_eq!(values.capacity(), 5);
    values.extend([11, 22, 33, 44, 55]);
    assert_eq!(values, [11, 22, 33, 44, 55]);
    assert_eq!(values.capacity(), 5);
    let empty = storage::vector::<u64>(0).unwrap();
    assert_eq!((empty.len(), empty.capacity()), (0, 0));
    let mut text = storage::string(7).unwrap();
    assert_eq!((text.len(), text.capacity()), (0, 7));
    text.push_str("abcdefg");
    assert_eq!((text.as_str(), text.capacity()), ("abcdefg", 7));
    assert!(storage::vector::<()>(1).is_err());
    assert!(storage::vector::<u64>(usize::MAX).is_err());
    assert!(add(usize::MAX, 1).is_err());
    assert!(mul(usize::MAX, 2).is_err());
}

#[test]
fn coalescence_prepared_storage_has_exact_payloads_and_no_native_completion() {
    let raw = original();
    let mut p = prepared(&raw);
    assert_eq!(p.allocated_bytes().unwrap(), 0);
    assert_eq!(p.stage, InitialCoalescenceStage::Installed);
    p.allocate_payloads(&raw).unwrap();
    assert_eq!(p.stage, InitialCoalescenceStage::Allocated);
    assert_eq!(p.original_bytes.len(), PAIR_BYTES);
    assert_eq!(p.original_bytes.capacity(), PAIR_BYTES);
    assert_eq!(p.final_bytes.len(), PAIR_BYTES);
    assert_eq!(p.final_bytes.capacity(), PAIR_BYTES);
    assert!(
        p.original_bytes
            .iter()
            .chain(&p.final_bytes)
            .all(|byte| *byte == 0)
    );
    assert!(p.maps.iter().all(|map| {
        let map = map.as_ref().unwrap();
        map.bytes().is_empty() && !map.complete && map.request.is_none()
    }));
    for state in &p.states {
        assert_eq!(state.state.xstate.len(), MAX_XSTATE);
        assert_eq!(state.state.xstate.capacity(), MAX_XSTATE);
        assert!(state.state.xstate.iter().all(|byte| *byte == 0));
        assert!(!state.complete);
        assert!(
            state.registers_request.is_none()
                && state.xstate_request.is_none()
                && state.mask_request.is_none()
        );
    }
    assert_eq!((p.pool.len(), p.pool.capacity()), (4, 4));
    assert_eq!((p.output.len(), p.output.capacity()), (0, 5));
    assert_eq!(
        (
            p.retired_descriptors.len(),
            p.retired_descriptors.capacity()
        ),
        (0, 0)
    );
    let expected = 336 * 1024
        + 4 * size_of::<Option<MemoryMapping>>()
        + 5 * size_of::<MemoryMapping>()
        + 4 * 4
        + 2 * "/main".len()
        + "[vdso]".len();
    assert_eq!(p.allocated_bytes().unwrap(), expected);
    assert_eq!(p.successful_payload_bytes, expected);
    assert_eq!(
        p.reserved_payload_bytes,
        expected + PreparedInitialCoalescence::temporary_bytes()
    );
    p.validate_allocations(None).unwrap();
    assert_eq!(p.read_progress, [SourceReadProgress::default(); 2]);
    assert!(p.projection.is_none() && p.final_stop.is_none() && p.call.wait.is_none());
    assert!(!p.call.complete && !p.output_transferred);
    assert!(p.allocate_payloads(&raw).is_err());
    assert_eq!(p.allocated_bytes().unwrap(), expected);
}

#[test]
fn coalescence_each_partial_allocation_refusal_or_unwind_retains_prefix_and_cannot_restart() {
    let raw = original();
    let mut complete = prepared(&raw);
    complete.allocate_payloads(&raw).unwrap();
    let steps = complete.allocation_steps;
    // Two byte vectors, three maps, two state vectors, two descriptor vectors,
    // four permission strings and three path strings are distinct allocations.
    assert_eq!(steps, 16);
    for unwind in [false, true] {
        for step in 1..=steps {
            let mut p = prepared(&raw);
            p.allocation_fault = Some((step, unwind));
            let result = catch_unwind(AssertUnwindSafe(|| p.allocate_payloads(&raw)));
            if unwind {
                assert!(result.is_err(), "step {step}");
                p.fail(None);
                assert_eq!(p.first_failure, Some(InitialBootstrapFailureKind::Unwound));
            } else {
                let error = result.unwrap().unwrap_err();
                assert!(matches!(
                    error,
                    LaunchError::Invalid("injected coalescence allocation refusal")
                ));
                p.fail(Some(&error));
                assert_eq!(
                    p.first_failure,
                    Some(InitialBootstrapFailureKind::Invalid(
                        "injected coalescence allocation refusal"
                    ))
                );
            }
            assert_eq!(p.allocation_steps, step);
            assert_eq!(p.stage, InitialCoalescenceStage::Allocating);
            assert_eq!(p.allocated_bytes().unwrap(), p.successful_payload_bytes);
            assert!(p.successful_payload_bytes > 0);
            assert!(p.successful_payload_bytes <= complete.successful_payload_bytes);
            p.validate_allocations(None).unwrap();
            let first = p.first_failure;
            p.fail(Some(&LaunchError::Timeout("later failure")));
            assert_eq!(p.first_failure, first);
            let bytes = p.allocated_bytes().unwrap();
            let original_pointer = p.original_bytes.as_ptr();
            let final_pointer = p.final_bytes.as_ptr();
            assert!(p.allocate_payloads(&raw).is_err());
            assert_eq!(p.allocated_bytes().unwrap(), bytes);
            assert_eq!(p.original_bytes.as_ptr(), original_pointer);
            assert_eq!(p.final_bytes.as_ptr(), final_pointer);
            assert_eq!(p.read_progress, [SourceReadProgress::default(); 2]);
            assert!(p.projection.is_none() && p.call.wait.is_none() && p.final_stop.is_none());
        }
    }
}

#[test]
fn coalescence_allocation_identity_and_accounting_corruption_are_refused() {
    let raw = original();
    let replacement = raw.clone();
    let mut p = prepared(&raw);
    assert!(p.allocate_payloads(&replacement).is_err());
    assert!(p.allocate_payloads(&raw[..raw.len() - 1]).is_err());
    assert_eq!(p.allocated_bytes().unwrap(), 0);
    p.allocate_payloads(&raw).unwrap();
    p.validate_allocations(None).unwrap();
    p.successful_payload_bytes += 1;
    assert!(p.validate_allocations(None).is_err());
    p.successful_payload_bytes -= 1;
    p.reserved_payload_bytes -= 1;
    assert!(p.validate_allocations(None).is_err());
    p.reserved_payload_bytes += 1;
    p.validate_allocations(None).unwrap();
    assert!(p.validate_allocations(Some(&Vec::new())).is_err());
    p.output_transferred = true;
    assert!(p.validate_allocations(None).is_err());
    p.output_transferred = false;
    p.borrowed_island_payload = 4;
    assert!(p.validate_allocations(None).is_err());
}

fn supplied_call() -> CoalescenceCallObservation {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    info.si_signo = libc::SIGTRAP;
    info.si_code = libc::SI_KERNEL;
    let mut signal = SignalObservation::default();
    assert_eq!(size_of::<libc::siginfo_t>(), signal.bytes.len());
    // SAFETY: the entire local object was zero-initialized; the fixed output
    // has exactly its size and the objects are disjoint. This is supplied data.
    unsafe {
        std::ptr::copy_nonoverlapping(
            (&raw const info).cast::<u8>(),
            signal.bytes.as_mut_ptr(),
            signal.bytes.len(),
        );
    }
    signal.request = Some(Request {
        result: 0,
        errno: None,
    });
    CoalescenceCallObservation {
        wait: Some((17, (libc::SIGTRAP << 8) | 0x7f)),
        queries_started: true,
        signal,
        registers: Some(RegisterSnapshot::from(unsafe {
            std::mem::zeroed::<libc::user_regs_struct>()
        })),
        requests: [Some(Request {
            result: 0,
            errno: None,
        }); 3],
        mask: 0x1234,
        returned_length: 512,
        result: Some(0),
        complete: true,
    }
}

#[test]
fn coalescence_supplied_call_facts_require_wait_queries_result_mask_and_completion() {
    // This checks a descriptive predicate only. No call record constructs a
    // producer, native checkpoint, completed borrow or original-execution right.
    supplied_call().validate(17, 0x1234).unwrap();
    for mutation in 0..20 {
        let mut call = supplied_call();
        match mutation {
            0 => call.wait = None,
            1 => call.wait.as_mut().unwrap().0 += 1,
            2 => call.wait.as_mut().unwrap().1 = 0,
            3 => call.wait.as_mut().unwrap().1 = (libc::SIGUSR1 << 8) | 0x7f,
            4 => call.wait.as_mut().unwrap().1 |= 1 << 16,
            5 => call.queries_started = false,
            6 => call.complete = false,
            7 => call.result = None,
            8 => call.result = Some((-i64::from(libc::EPERM)) as u64),
            9 => call.registers = None,
            10 => call.registers.as_mut().unwrap().rax = 1,
            11 => call.returned_length = 511,
            12 => call.returned_length = MAX_XSTATE,
            13 => call.mask ^= 1,
            14 => call.signal.request = None,
            15 => call.signal.request.as_mut().unwrap().errno = Some(libc::EIO),
            16 => call.signal.request.as_mut().unwrap().result = 1,
            17 => call.signal.bytes[..4].copy_from_slice(&libc::SIGUSR1.to_ne_bytes()),
            18 => call.signal.bytes[8..12].copy_from_slice(&libc::SI_USER.to_ne_bytes()),
            _ => call.requests[1].as_mut().unwrap().result = -1,
        }
        assert!(call.validate(17, 0x1234).is_err(), "mutation {mutation}");
    }
    assert!(supplied_call().validate(18, 0x1234).is_err());
    assert!(supplied_call().validate(17, 0x1235).is_err());
}

#[test]
fn coalescence_every_supplied_state_query_must_succeed_independently() {
    for index in 0..3 {
        for mutation in 0..3 {
            let mut call = supplied_call();
            match mutation {
                0 => call.requests[index] = None,
                1 => call.requests[index].as_mut().unwrap().result = -1,
                _ => call.requests[index].as_mut().unwrap().errno = Some(libc::EIO),
            }
            assert!(
                call.validate(17, 0x1234).is_err(),
                "query {index}, mutation {mutation}"
            );
        }
    }
}

#[test]
fn coalescence_incomplete_or_wrong_operation_read_progress_never_finishes_original_capture() {
    let raw = original();
    for mutation in 0..6 {
        let mut p = prepared(&raw);
        p.allocate_payloads(&raw).unwrap();
        let (_, bytes, progress) = p.original_capture_storage().unwrap();
        assert_eq!(bytes.len(), PAIR_BYTES);
        // Descriptive negative input only. It does not call a native reader.
        progress.started = true;
        progress.attempted = true;
        progress.requested_bytes = PAIR_BYTES;
        progress.copied_bytes = PAIR_BYTES;
        progress.complete = true;
        progress.last_request = Some(admission::SourceReadRequest {
            operation: SourceReadOperation::PeekMemory,
            address: 0x401ff8,
            count: 8,
            result: 0,
            errno: None,
        });
        match mutation {
            0 => progress.complete = false,
            1 => progress.copied_bytes -= 1,
            2 => progress.requested_bytes -= 1,
            3 => progress.last_request.as_mut().unwrap().operation = SourceReadOperation::ReadMaps,
            4 => progress.last_request.as_mut().unwrap().address -= 8,
            _ => progress.last_request.as_mut().unwrap().errno = Some(libc::EFAULT),
        }
        assert!(p.original_captured().is_err());
        assert_eq!(p.stage, InitialCoalescenceStage::OriginalRead);
        assert!(p.original_capture_storage().is_err());
        assert!(p.projection.is_none() && p.call.wait.is_none());
    }
}
