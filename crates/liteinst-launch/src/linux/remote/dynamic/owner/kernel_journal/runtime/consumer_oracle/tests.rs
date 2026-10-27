//! Supplied diagnostic-record and allocation models only. No native owner,
//! completion seal, source permission or physical cleanup receipt is created.
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind, panic_any};

fn modeled_state(length: usize) -> RuntimeKernelStateRecord {
    RuntimeKernelStateRecord {
        slot: RuntimeKernelStateSlot::Unexpected,
        captured: true,
        finalized: false,
        complete: false,
        raw_ordinal: Some(3),
        stop: None,
        registers: [0x31; 216],
        registers_request: Some(RuntimeKernelRequest {
            result: 0,
            errno: None,
        }),
        initialized_xstate: vec![0x57; length],
        xstate_request: Some(RuntimeKernelRequest {
            result: -1,
            errno: Some(libc::EIO),
        }),
        requested_pointer: 0x1000,
        returned_pointer: 0x2000,
        requested_length: MAX_XSTATE,
        returned_length: 513,
        mask: [0x17; 8],
        mask_request: Some(RuntimeKernelRequest {
            result: -1,
            errno: Some(libc::ESRCH),
        }),
    }
}

#[test]
fn consumer_journal_retains_exact_allocation_error_and_unwind_prefixes() {
    let expected = |ordinal: usize| {
        size_of::<PreparedKernelObservation>()
            + if ordinal == 0 {
                0
            } else {
                ATTEMPTS * size_of::<AttemptCopy>() + (ordinal - 1) * MAX_XSTATE
            }
    };
    for ordinal in 0..=ATTEMPTS * STATE_COUNT {
        let mut value = PreparedKernelObservation::empty();
        let error = value
            .allocate_with(|next| {
                if next == ordinal {
                    Err(invalid("supplied allocation boundary refusal"))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert!(matches!(
            error,
            LaunchError::Invalid("supplied allocation boundary refusal")
        ));
        assert_eq!(value.allocated_bytes().unwrap(), expected(ordinal));
        assert!(!value.partial_view().progress.allocation_complete);
        assert!(!value.partial_view().progress.capture_started);
        assert!(value.partial_view().header.is_none());
        assert!(value.allocate_payloads().is_err());
        assert_eq!(value.allocated_bytes().unwrap(), expected(ordinal));

        let mut value = PreparedKernelObservation::empty();
        let panic = catch_unwind(AssertUnwindSafe(|| {
            value
                .allocate_with(|next| {
                    if next == ordinal {
                        panic_any(0x4a4f_5552_u32);
                    }
                    Ok(())
                })
                .unwrap();
        }))
        .unwrap_err();
        assert_eq!(panic.downcast_ref::<u32>(), Some(&0x4a4f_5552));
        value.mark_aborted();
        assert_eq!(value.allocated_bytes().unwrap(), expected(ordinal));
        assert_eq!(
            value.partial_view().progress.first_failure.unwrap().kind,
            KernelFailureKind::CaughtPanic
        );
        assert!(!value.partial_view().progress.allocation_complete);
    }
    let mut value = PreparedKernelObservation::empty();
    value.allocate_payloads().unwrap();
    assert_eq!(
        value.allocated_bytes().unwrap(),
        PreparedKernelObservation::reservation_bytes().unwrap()
    );
    let view = value.partial_view();
    assert_eq!(view.allocation, view.installed.unwrap());
    assert_eq!((view.allocation.length, view.allocation.capacity), (3, 3));
    for index in 0..ATTEMPTS {
        let attempt = view.attempt(index).unwrap();
        assert!(attempt.binding.is_none() && attempt.header.is_none());
        assert_eq!(
            (
                attempt.raw_slots_copied,
                attempt.fact_slots_copied,
                attempt.state_slots_copied
            ),
            (0, 0, 0)
        );
        for slot in 0..STATE_COUNT {
            let state = attempt.state(slot).unwrap();
            assert_eq!(state.allocation, state.installed.unwrap());
            assert_eq!(
                (state.allocation.length, state.allocation.capacity),
                (MAX_XSTATE, MAX_XSTATE)
            );
            assert!(
                state.source.is_none() && state.header.is_none() && state.copied_prefix.is_empty()
            );
            assert!(state.initialized.iter().all(|byte| *byte == 0));
        }
    }
    assert!(PreparedKernelObservation::temporary_bytes().unwrap() > size_of::<AttemptCopy>());
}

#[test]
fn consumer_journal_preserves_full_failed_state_and_detects_changes() {
    let source = modeled_state(MAX_XSTATE);
    let mut copied = StateCopy::empty();
    copied.allocate().unwrap();
    copied.capture(&source).unwrap();
    assert!(!copied.view().header.unwrap().complete);
    assert!(copied.view().complete);
    assert_eq!(copied.view().copied_prefix, source.initialized_xstate);
    copied.require_retained(&source).unwrap();
    type Mutation = fn(&mut RuntimeKernelStateRecord);
    let mutations: [Mutation; 17] = [
        |s| s.slot = RuntimeKernelStateSlot::Closed,
        |s| s.captured = false,
        |s| s.finalized = true,
        |s| s.complete = true,
        |s| s.raw_ordinal = Some(4),
        |s| s.registers[215] ^= 1,
        |s| s.registers_request = None,
        |s| s.xstate_request = None,
        |s| s.requested_pointer += 1,
        |s| s.returned_pointer += 1,
        |s| s.requested_length -= 1,
        |s| s.returned_length += 1,
        |s| s.mask[7] ^= 1,
        |s| s.mask_request = None,
        |s| s.initialized_xstate[0] ^= 1,
        |s| s.initialized_xstate[MAX_XSTATE - 1] ^= 1,
        |s| s.initialized_xstate.truncate(MAX_XSTATE - 1),
    ];
    for mutate in mutations {
        // A new source allocation already differs; first make a separate copy
        // from that exact allocation, then corrupt only its named field.
        let mut model = source.clone();
        let mut baseline = StateCopy::empty();
        baseline.allocate().unwrap();
        baseline.capture(&model).unwrap();
        baseline.require_retained(&model).unwrap();
        mutate(&mut model);
        assert!(baseline.require_retained(&model).is_err());
    }
    let same_bytes_new_allocation = source.clone();
    assert_eq!(
        source.initialized_xstate,
        same_bytes_new_allocation.initialized_xstate
    );
    assert!(copied.require_retained(&same_bytes_new_allocation).is_err());
    copied.bytes[MAX_XSTATE - 1] ^= 1;
    assert!(copied.require_retained(&source).is_err());
}

#[test]
fn consumer_journal_failed_copy_keeps_initialized_prefix_without_completion() {
    for length in [MAX_XSTATE - 1, MAX_XSTATE + 1] {
        let source = modeled_state(length);
        let mut copied = StateCopy::empty();
        copied.allocate().unwrap();
        assert!(copied.capture(&source).is_err());
        let view = copied.view();
        assert!(!view.complete);
        assert_eq!(view.source.unwrap().length, length);
        assert_eq!(
            view.copied_prefix,
            &source.initialized_xstate[..length.min(MAX_XSTATE)]
        );
        assert_eq!(view.header.unwrap(), &JournalStateHeader::from(&source));
        assert!(
            view.initialized[view.copied_prefix.len()..]
                .iter()
                .all(|byte| *byte == 0)
        );
        copied.require_retained(&source).unwrap();
        assert!(copied.capture(&source).is_err());
    }
}

#[test]
fn consumer_journal_empty_model_archive_does_not_claim_native_completion() {
    for status in [
        KernelWriterStatus::Cleaned,
        KernelWriterStatus::FailedCleanup,
    ] {
        // These are host-only journal flags supplied by a pure model, not an
        // actual Owner::cleanup result or an application/broker physical receipt.
        let mut writer = KernelJournalWriter::new(7);
        let mut value = PreparedKernelObservation::empty();
        value.allocate_payloads().unwrap();
        value.capture(&writer).unwrap();
        let counts = value.counts().unwrap();
        assert_eq!(
            (counts.attempts, counts.raw_waits, counts.complete_states),
            (0, 0, 0)
        );
        assert!(counts.per_attempt.iter().all(Option::is_none));
        assert!(value.partial_view().attempt(0).unwrap().binding.is_none());
        writer.close(
            KernelWriterStatus::Closing,
            Some(KernelFailureKind::Cancelled),
        );
        writer.close(status, None);
        assert_eq!(
            value.require_retained(&writer).unwrap(),
            JournalWriterTransition {
                before: KernelWriterStatus::Active,
                after: status,
            }
        );
        assert_eq!(value.counts().unwrap(), counts);
        assert!(value.partial_view().progress.first_failure.is_none());
        assert!(value.require_retained(&writer).is_err());
    }
    let writer = KernelJournalWriter::new(9);
    let mut value = PreparedKernelObservation::empty();
    value.allocate_payloads().unwrap();
    value.capture(&writer).unwrap();
    assert!(value.require_retained(&writer).is_err());
}

#[test]
fn consumer_journal_first_failure_and_poisoned_prefix_remain_visible() {
    let writer = KernelJournalWriter::new(11);
    let mut value = PreparedKernelObservation::empty();
    assert!(value.capture(&writer).is_err());
    let first = value.partial_view().progress.first_failure.unwrap();
    value.mark_aborted();
    assert_eq!(value.partial_view().progress.first_failure, Some(first));
    assert!(value.partial_view().header.is_none());
    assert!(!value.partial_view().progress.capture_complete);
    assert!(value.counts().is_err());

    let mut value = PreparedKernelObservation::empty();
    value.allocate_payloads().unwrap();
    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _guard = writer.archive.lock().unwrap();
        panic_any(0x504f_4953_u32);
    }))
    .unwrap_err();
    assert_eq!(panic.downcast_ref::<u32>(), Some(&0x504f_4953));
    assert!(value.capture(&writer).is_err());
    assert!(value.partial_view().header.unwrap().lock_poisoned);
    assert!(!value.partial_view().progress.capture_complete);
    assert_eq!(value.partial_view().progress.headers_copied, 0);
    let first = value.partial_view().progress.first_failure;
    value.mark_aborted();
    assert_eq!(value.partial_view().progress.first_failure, first);
    assert!(value.counts().is_err());
}
