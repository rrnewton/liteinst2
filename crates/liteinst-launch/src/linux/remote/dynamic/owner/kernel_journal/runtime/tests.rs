//! Data-only archive models. No native seal, live stop or census receipt is made.
use super::observation::registers_bytes;
use super::storage::{check_shape, empty_attempt, prepare_owned};
use super::*;
use liteinst_admission::{Generation, MappingId};
use liteinst2::contracts::SourceIdentity;

fn binding() -> Binding {
    let old = super::super::tests::binding();
    Binding {
        pending: RuntimePendingToken {
            stop: old.pending.stop,
            task: old.pending.task,
            generation: Generation(0),
            mapping: MappingId(17),
            window: 2,
            pc: old.before.registers.rip,
            invocation: old.pending.invocation,
        },
        original: old.original_stop,
        source: CodeIdentity {
            source: SourceIdentity([0x39; 32]),
            mapping: 17,
            generation: 0,
        },
        window: 2,
        origin: (83, 4),
        execution: (83, 1),
        registers: old.before.registers,
        original_mask: old.before.mask,
        original_xstate_len: old.before.xstate.len(),
        number: libc::SYS_getpid as u64,
        arguments: [17, 0x700000, 0, 0, 0, 0],
        until: old.until,
    }
}
fn prepared(writer: &KernelJournalWriter, binding: Binding) -> PreparedRuntimeJournal {
    let shape = writer.runtime_shape().unwrap();
    prepare_owned(Arc::clone(&writer.archive), shape, binding).unwrap()
}
fn request() -> Request {
    Request {
        result: 0,
        errno: None,
    }
}
fn raw_state<'a>(
    state: &'a TaskStateSnapshot,
    registers: &'a [u8; 216],
    initialized: &'a [u8],
    mask: &'a [u8; 8],
) -> RuntimeStateReadView<'a> {
    RuntimeStateReadView {
        registers,
        registers_request: Some(request()),
        xstate_initialized: initialized,
        xstate_request: Some(request()),
        requested_pointer: 0x1000,
        returned_pointer: 0x1000,
        requested_length: MAX_XSTATE,
        returned_length: state.xstate.len(),
        mask,
        mask_request: Some(request()),
        complete: true,
        state: Some(state),
    }
}

#[test]
fn runtime_journal_detached_preparation_charges_full_replacement_without_refund() {
    let mut writer = KernelJournalWriter::new(83);
    let first = prepared(&writer, binding());
    let first_charge = first.retained_bytes();
    assert_eq!(
        first_charge,
        size_of::<PreparedRuntimeJournal>()
            + size_of::<RuntimeAttempt>()
            + 8 * MAX_XSTATE
            + size_of::<RuntimeArchive>()
    );
    assert_eq!(first.allocation_peak_bytes().unwrap(), first_charge);
    assert!(writer.reader().snapshot().runtime_attempts.is_empty());
    for state in &first.attempt.states {
        assert_eq!(state.initialized_xstate.capacity(), MAX_XSTATE);
        assert!(!state.captured);
        assert!(state.initialized_xstate.iter().all(|byte| *byte == 0));
    }
    let (handle, _sink) = writer.attach_runtime(first).unwrap();
    let old = writer.reader().snapshot().runtime_attempts;
    // End only the private model's active marker; no production finish/receipt.
    writer.lock().runtime.active = None;
    let mut next = binding();
    next.pending.invocation = 2;
    next.execution.1 = 2;
    let second = prepared(&writer, next);
    let second_charge = second.retained_bytes();
    assert_eq!(
        second_charge,
        size_of::<PreparedRuntimeJournal>() + 2 * size_of::<RuntimeAttempt>() + 8 * MAX_XSTATE
    );
    assert_eq!(
        second.allocation_peak_bytes().unwrap(),
        second_charge + size_of::<RuntimeAttempt>()
    );
    writer.attach_runtime(second).unwrap();
    let snapshot = writer.reader().snapshot();
    assert_eq!(snapshot.runtime_attempts[0], old[0]);
    assert_eq!(snapshot.runtime_attempts[0].retained_bytes, first_charge);
    assert_eq!(snapshot.runtime_attempts[1].retained_bytes, second_charge);
    assert!(snapshot.attempts.is_empty());
    assert_eq!(handle.id().invocation, 1);
}

#[test]
fn runtime_journal_detached_drop_and_stale_foreign_attach_leave_archive_exact() {
    let mut writer = KernelJournalWriter::new(83);
    let before = writer.reader().snapshot();
    drop(prepared(&writer, binding()));
    assert_eq!(writer.reader().snapshot(), before);
    assert_eq!(writer.lock().runtime.attempts.capacity(), 0);
    let stale = prepared(&writer, binding());
    let current = prepared(&writer, binding());
    writer.attach_runtime(current).unwrap();
    let attached = writer.reader().snapshot();
    assert!(writer.attach_runtime(stale).is_err());
    assert_eq!(writer.reader().snapshot(), attached);
    let other = KernelJournalWriter::new(83);
    let foreign = prepared(&other, binding());
    assert!(writer.attach_runtime(foreign).is_err());
    assert_eq!(writer.reader().snapshot(), attached);
}

#[test]
fn runtime_journal_shape_checks_actual_capacity_overflow_and_mixed_stream_order() {
    assert!(RuntimeJournalShape::new(2, 1, 0).is_err());
    assert!(RuntimeJournalShape::new(0, 0, u64::MAX).is_err());
    assert!(RuntimeJournalShape::new(usize::MAX, usize::MAX, 0).is_err());
    let mut writer = KernelJournalWriter::new(83);
    let shape = writer.runtime_shape().unwrap();
    assert_eq!(
        shape.reservation_bytes(),
        size_of::<PreparedRuntimeJournal>()
            + size_of::<RuntimeAttempt>()
            + 8 * MAX_XSTATE
            + size_of::<RuntimeArchive>()
    );
    assert_eq!(
        shape.allocation_peak_bytes().unwrap(),
        shape.reservation_bytes()
    );
    let value = prepared(&writer, binding());
    writer.attach_runtime(value).unwrap();
    assert!(writer.runtime_shape().is_err());
    assert!(writer.prepare(super::super::tests::binding()).is_err());
    let mut archive = writer.lock();
    archive.runtime.active = None;
    assert!(!archive.runtime.allows_legacy(KernelAttemptId {
        session: 83,
        invocation: 1
    }));
    assert!(archive.runtime.allows_legacy(KernelAttemptId {
        session: 83,
        invocation: 2
    }));
    assert!(
        check_shape(
            &archive,
            None,
            &shape,
            KernelAttemptId {
                session: 83,
                invocation: 2
            }
        )
        .is_err()
    );
}

#[test]
fn runtime_journal_failed_getregs_preserves_independent_max_substrate_and_errno() {
    let writer = KernelJournalWriter::new(83);
    let mut value = prepared(&writer, binding());
    let state = super::super::tests::binding().before;
    let mut registers = registers_bytes(&state.registers);
    registers[0] = 0x91;
    let mut initialized = vec![0; MAX_XSTATE];
    initialized[..state.xstate.len()].copy_from_slice(&state.xstate);
    initialized[MAX_XSTATE - 1] = 0x73;
    let mask = state.mask.to_ne_bytes();
    let mut raw = raw_state(&state, &registers, &initialized, &mask);
    raw.registers_request = Some(Request {
        result: -1,
        errno: Some(libc::EFAULT),
    });
    raw.complete = false;
    raw.state = None;
    let slot = &mut value.attempt.states[RuntimeKernelStateSlot::Unexpected.index()];
    slot.copy(raw, Some(3), None, true).unwrap();
    assert!(slot.captured && slot.finalized && !slot.complete);
    assert_eq!(slot.registers, registers);
    assert_eq!(slot.initialized_xstate, initialized);
    assert_eq!(
        slot.registers_request,
        Some(RuntimeKernelRequest {
            result: -1,
            errno: Some(libc::EFAULT)
        })
    );
    assert_eq!(slot.xstate_request, Some(request().into()));
    assert_eq!(slot.mask_request, Some(request().into()));
    assert_eq!(slot.mask, mask);
    assert_eq!(slot.returned_length, state.xstate.len());
    let old = slot.clone();
    assert!(slot.copy(raw, Some(3), None, true).is_err());
    assert_eq!(*slot, old);
}

#[test]
fn runtime_journal_complete_claim_refuses_pointer_length_and_state_corruption() {
    let state = super::super::tests::binding().before;
    let registers = registers_bytes(&state.registers);
    let mask = state.mask.to_ne_bytes();
    let mut initialized = vec![0; MAX_XSTATE];
    initialized[..state.xstate.len()].copy_from_slice(&state.xstate);
    for choice in 0..6 {
        let writer = KernelJournalWriter::new(83);
        let mut value = prepared(&writer, binding());
        let mut raw = raw_state(&state, &registers, &initialized, &mask);
        match choice {
            0 => raw.returned_pointer += 1,
            1 => raw.requested_length -= 1,
            2 => raw.returned_length = MAX_XSTATE,
            3 => raw.registers_request = None,
            4 => {
                raw.mask_request = Some(Request {
                    result: -1,
                    errno: Some(libc::EPERM),
                })
            }
            5 => raw.state = None,
            _ => unreachable!(),
        }
        let slot = &mut value.attempt.states[RuntimeKernelStateSlot::Original.index()];
        assert!(slot.copy(raw, None, None, true).is_err());
        assert!(slot.captured && !slot.complete);
        assert_eq!(slot.initialized_xstate, initialized);
        assert_eq!(slot.registers, registers);
        assert_eq!(slot.requested_length, raw.requested_length);
        assert_eq!(slot.returned_pointer, raw.returned_pointer);
    }
    let writer = KernelJournalWriter::new(83);
    let mut value = prepared(&writer, binding());
    let slot = &mut value.attempt.states[RuntimeKernelStateSlot::Original.index()];
    slot.copy(
        raw_state(&state, &registers, &initialized, &mask),
        None,
        None,
        true,
    )
    .unwrap();
    assert!(slot.equals(&state));
    let mut changed = state.clone();
    changed.xstate[0] ^= 1;
    assert!(!slot.equals(&changed));
    changed = state.clone();
    changed.registers.eflags ^= 1;
    assert!(!slot.equals(&changed));
    changed = state.clone();
    changed.mask ^= 1;
    assert!(!slot.equals(&changed));
}

#[test]
fn runtime_journal_partial_wait_and_first_error_survive_cleanup_and_owner_drop() {
    let mut writer = KernelJournalWriter::new(83);
    let value = prepared(&writer, binding());
    let reader = writer.reader();
    let (handle, mut sink) = writer.attach_runtime(value).unwrap();
    {
        let mut archive = writer.lock();
        let attempt = &mut archive.runtime.attempts[handle.index];
        let custody = RuntimeWaitCustody {
            session: 83,
            expected_tid: 100,
            retained_pin: Some(7),
            process_pin: Some(true),
            owned: false,
            stopped_status: None,
            tracer_terminal: Some(0),
            lost_wait: false,
            missing_pin: false,
        };
        attempt.raw[0] = Some(RuntimeKernelRawRecord::new(0, 100, 0, custody));
        attempt.raw_count = 1;
        attempt
            .append(RuntimeKernelFact::Wait { ordinal: 0 })
            .unwrap();
    }
    sink.fail(
        RuntimeKernelJournalStage::Raw,
        KernelFailureKind::NativeIo(Some(libc::EIO)),
    );
    writer.fail_active(KernelFailureKind::CaughtPanic);
    writer.close(
        KernelWriterStatus::Cleaned,
        Some(KernelFailureKind::Cancelled),
    );
    drop(sink);
    drop(writer);
    let saved = reader.snapshot();
    assert_eq!(saved.writer, KernelWriterStatus::Cleaned);
    let attempt = &saved.runtime_attempts[0];
    assert_eq!(
        attempt.failure,
        Some(RuntimeKernelJournalFailure {
            stage: RuntimeKernelJournalStage::Raw,
            kind: KernelFailureKind::NativeIo(Some(libc::EIO))
        })
    );
    let raw = attempt.raw[0].as_ref().unwrap();
    assert_eq!(raw.status, 0);
    assert!(!raw.queries_started && !raw.finalized);
    assert_eq!(raw.registers_request, None);
    assert_eq!(raw.xstate_request, None);
    assert_eq!(raw.mask_request, None);
    assert_eq!(raw.custody.tracer_terminal, Some(0));
    assert!(attempt.states.iter().all(|state| !state.captured));
}

#[test]
fn runtime_journal_exact_fact_capacity_keeps_prefix_and_separate_first_failure() {
    let mut attempt = empty_attempt(binding());
    for ordinal in 0..FACT_COUNT {
        attempt.append(RuntimeKernelFact::Wait { ordinal }).unwrap();
    }
    let old = attempt.facts().copied().collect::<Vec<_>>();
    assert!(
        attempt
            .append(RuntimeKernelFact::Wait {
                ordinal: FACT_COUNT
            })
            .is_err()
    );
    assert_eq!(attempt.facts().copied().collect::<Vec<_>>(), old);
    assert_eq!(attempt.failure.unwrap().kind, KernelFailureKind::Capacity);
    attempt.fail(KernelFailureKind::Cancelled);
    assert_eq!(attempt.failure.unwrap().kind, KernelFailureKind::Capacity);
    assert_eq!(attempt.fact_count, 32);
}

#[test]
fn runtime_journal_unwind_marks_only_incomplete_runtime_attempt() {
    let mut writer = KernelJournalWriter::new(83);
    let value = prepared(&writer, binding());
    writer.attach_runtime(value).unwrap();
    let reader = writer.reader();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _scope = writer.panic_scope();
        panic!("model unwind");
    }));
    assert!(result.is_err());
    assert_eq!(
        reader.snapshot().runtime_attempts[0].failure.unwrap().kind,
        KernelFailureKind::CaughtPanic
    );
    {
        let mut archive = writer.lock();
        let attempt = &mut archive.runtime.attempts[0];
        attempt.failure = None;
        attempt.completed = true;
        archive.runtime.active = None;
    }
    let before = reader.snapshot();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _scope = writer.panic_scope();
        panic!("later model unwind");
    }));
    assert!(result.is_err());
    assert_eq!(reader.snapshot(), before);
}

#[test]
fn runtime_journal_exact_layout_preserves_initialized_ownership_and_checked_bounds() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Counted(Arc<AtomicUsize>);
    impl Drop for Counted {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut values = super::storage::exact_vec::<Counted>(3).unwrap();
    assert_eq!(values.capacity(), 3);
    assert!(values.is_empty());
    values.push(Counted(Arc::clone(&dropped)));
    values.push(Counted(Arc::clone(&dropped)));
    assert_eq!(values.capacity(), 3);
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    drop(values);
    assert_eq!(dropped.load(Ordering::SeqCst), 2);
    assert!(super::storage::exact_vec::<u64>(usize::MAX).is_err());
    assert!(super::storage::exact_vec::<()>(1).is_err());
    assert_eq!(super::storage::exact_vec::<u8>(0).unwrap().capacity(), 0);
}

#[test]
fn runtime_journal_terminal_and_unheld_headers_never_imply_query_permission() {
    let status = (libc::SIGTRAP << 8) | 0x7f;
    let custody = RuntimeWaitCustody {
        session: 83,
        expected_tid: 100,
        retained_pin: Some(7),
        process_pin: Some(true),
        owned: true,
        stopped_status: Some(status),
        tracer_terminal: None,
        lost_wait: false,
        missing_pin: false,
    };
    let mut held = RuntimeKernelRawRecord::new(0, 100, status, custody);
    held.queries_started = true;
    held.registers_request = Some(request().into());
    held.validate_custody(true).unwrap();
    for choice in 0..6 {
        let mut changed = held.clone();
        match choice {
            0 => changed.status = 0,
            1 => changed.custody.owned = false,
            2 => changed.custody.stopped_status = None,
            3 => changed.custody.retained_pin = None,
            4 => changed.custody.lost_wait = true,
            5 => changed.custody.missing_pin = true,
            _ => unreachable!(),
        }
        assert!(changed.validate_custody(true).is_err());
    }
    let mut terminal = RuntimeKernelRawRecord::new(
        5,
        100,
        7 << 8,
        RuntimeWaitCustody {
            owned: false,
            stopped_status: None,
            tracer_terminal: Some(7 << 8),
            ..custody
        },
    );
    terminal.validate_custody(false).unwrap();
    assert!(terminal.validate_custody(true).is_err());
    terminal.registers_request = Some(RuntimeKernelRequest {
        result: -1,
        errno: Some(libc::ESRCH),
    });
    assert!(terminal.validate_custody(false).is_err());
    assert_eq!(terminal.registers_request.unwrap().errno, Some(libc::ESRCH));
    assert_eq!(terminal.custody.tracer_terminal, Some(7 << 8));
}

fn commit_view<'a>(
    binding: &'a Binding,
    outcome: RuntimeKernelCommitOutcome<'a>,
) -> RuntimeKernelCommitView<'a> {
    RuntimeKernelCommitView {
        attempt: binding.id(),
        pending: &binding.pending,
        source: binding.source,
        window: binding.window,
        origin: binding.origin,
        execution: binding.execution,
        task: binding.pending.task,
        number: binding.number,
        arguments: binding.arguments,
        until: binding.until,
        outcome,
    }
}

#[test]
fn runtime_journal_return_commit_comparison_binds_every_identity_and_exact_stop() {
    let b = binding();
    let mut attempt = empty_attempt(b.clone());
    let mut stop = b.pending.stop.clone();
    stop.sequence += 9;
    attempt
        .append(RuntimeKernelFact::Returned {
            stop: (&stop).into(),
        })
        .unwrap();
    let expected = RuntimeKernelFact::ReturnCommitted {
        current: (b.origin.0, b.origin.1 + 1),
        stop: (&stop).into(),
    };
    let view = commit_view(
        &b,
        RuntimeKernelCommitOutcome::Returned {
            current: (b.origin.0, b.origin.1 + 1),
            stop: &stop,
        },
    );
    assert_eq!(attempt.committed_fact(&view, true).unwrap(), expected);
    assert!(attempt.committed_fact(&view, false).is_err());
    let before = attempt.snapshot();
    for choice in 0..14 {
        let mut pending = b.pending.clone();
        pending.invocation += 1;
        let mut wrong_stop = stop.clone();
        wrong_stop.sequence += 1;
        let mut view = commit_view(
            &b,
            RuntimeKernelCommitOutcome::Returned {
                current: (b.origin.0, b.origin.1 + 1),
                stop: &stop,
            },
        );
        match choice {
            0 => view.attempt.invocation += 1,
            1 => view.pending = &pending,
            2 => view.source.source.0[0] ^= 1,
            3 => view.source.mapping += 1,
            4 => view.source.generation += 1,
            5 => view.window += 1,
            6 => view.origin.1 += 1,
            7 => view.execution.1 += 1,
            8 => view.task.generation += 1,
            9 => view.number = libc::SYS_gettid as u64,
            10 => view.arguments[5] ^= 1,
            11 => view.until += Duration::from_nanos(1),
            12 => {
                view.outcome = RuntimeKernelCommitOutcome::Returned {
                    current: b.origin,
                    stop: &stop,
                }
            }
            13 => {
                view.outcome = RuntimeKernelCommitOutcome::Returned {
                    current: (b.origin.0, b.origin.1 + 1),
                    stop: &wrong_stop,
                }
            }
            _ => unreachable!(),
        }
        assert!(attempt.committed_fact(&view, true).is_err());
        assert_eq!(attempt.snapshot(), before);
    }
    attempt.fail(KernelFailureKind::Cancelled);
    assert!(attempt.committed_fact(&view, true).is_err());
    // No private census receipt was constructed and no production finish ran.
    assert!(!attempt.completed);
}

#[test]
fn runtime_journal_terminal_commit_comparison_requires_real_tag_and_no_successor() {
    let mut b = binding();
    b.number = libc::SYS_exit as u64;
    b.registers.rax = b.number;
    let mut attempt = empty_attempt(b.clone());
    let sequence = b.pending.stop.sequence + 6;
    let status = 7 << 8;
    attempt
        .append(RuntimeKernelFact::Terminal {
            ordinal: 5,
            sequence,
            status,
            physical_status: status,
            pin_revents: libc::POLLHUP,
        })
        .unwrap();
    let event = DynamicEvent {
        tid: b.pending.stop.tid,
        task: Some(b.pending.task),
        stop: None,
        kind: DynamicEventKind::TaskTerminal {
            status: crate::lifecycle::ExitStatus::Code(7),
        },
    };
    let outcome = || RuntimeKernelCommitOutcome::Terminal {
        event: &event,
        sequence,
        wait_status: status,
        physical_status: status,
        pin_revents: libc::POLLHUP,
    };
    let view = commit_view(&b, outcome());
    assert_eq!(
        attempt.committed_fact(&view, false).unwrap(),
        RuntimeKernelFact::TerminalCommitted { sequence, status }
    );
    assert!(attempt.committed_fact(&view, true).is_err());
    let before = attempt.snapshot();
    for choice in 0..8 {
        let mut changed = event.clone();
        let mut seq = sequence;
        let mut wait = status;
        let mut physical = status;
        let mut pin = libc::POLLHUP;
        match choice {
            0 => changed.stop = Some(b.pending.stop.clone()),
            1 => changed.tid += 1,
            2 => changed.task.as_mut().unwrap().generation += 1,
            3 => seq += 1,
            4 => wait = 0,
            5 => physical = 0,
            6 => pin = 0,
            7 => {
                changed.kind = DynamicEventKind::SyscallExit {
                    result: 0,
                    is_error: false,
                }
            }
            _ => unreachable!(),
        }
        let view = commit_view(
            &b,
            RuntimeKernelCommitOutcome::Terminal {
                event: &changed,
                sequence: seq,
                wait_status: wait,
                physical_status: physical,
                pin_revents: pin,
            },
        );
        assert!(attempt.committed_fact(&view, false).is_err());
        assert_eq!(attempt.snapshot(), before);
    }
    assert!(attempt.states.iter().all(|slot| !slot.captured));
    assert!(!attempt.completed); // Descriptive model data cannot mint a receipt.
}
