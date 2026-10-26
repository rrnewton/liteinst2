//! Synthetic journal transactions only. These tests manufacture model input,
//! not native stops, ptrace ownership, syscall results or cleanup evidence.
use super::*;

pub(in crate::linux::remote::dynamic::owner) mod native;
use crate::lifecycle::{
    CreationEvent, CreationEventKind, CreationRequest, HoldReason, LifecycleRegistry, Limits,
};
use crate::selected::{SyscallAliases, decode};
use std::panic::{AssertUnwindSafe, catch_unwind};

const SESSION: u64 = 83;
const PC: u64 = 0x401000;

fn registry() -> LifecycleRegistry {
    LifecycleRegistry::new_after_exec_syscall_exit(
        Limits {
            tasks: 2,
            processes: 1,
            address_spaces: 1,
            obligations: 8,
        },
        100,
        PC,
    )
    .unwrap()
}
fn identity(registry: &LifecycleRegistry, task: crate::lifecycle::TaskId) -> DynamicTask {
    let record = registry.task(task).unwrap();
    DynamicTask {
        task,
        process: record.process,
        address_space: record.address_space,
        generation: 0,
    }
}
pub(in crate::linux::remote::dynamic::owner) fn binding() -> KernelAttemptBinding {
    binding_from(&registry(), libc::SYS_getpid as u64)
}
fn binding_from(registry: &LifecycleRegistry, number: u64) -> KernelAttemptBinding {
    let task = identity(registry, registry.root_task());
    // All members are initialized scalar integers, not an observed native state.
    let mut raw: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    raw.rax = number;
    raw.rip = PC;
    raw.rsp = 0x600000;
    raw.orig_rax = u64::MAX;
    raw.cs = 0x33;
    raw.ss = 0x2b;
    raw.eflags = 0x202;
    raw.rdi = if number == libc::SYS_clone as u64 {
        0x10f00
    } else {
        17
    };
    raw.rsi = 0x700000;
    let registers = raw.into();
    let token = DynamicStop {
        session: SESSION,
        sequence: 7,
        tid: 100,
        task: Some(task.task),
    };
    KernelAttemptBinding {
        pending: PendingToken {
            stop: token.clone(),
            task,
            epoch: 0,
            plan: 9,
            invocation: 1,
        },
        original_stop: AdmissionStop {
            token,
            identity: task,
            phase: trusted::AdmissionPhase::Restored,
            signal: None,
        },
        input: SelectedInput::new(
            decode(PC, &[0x0f, 0x05], &SyscallAliases::default()).unwrap(),
            registers,
        )
        .unwrap(),
        before: TaskStateSnapshot {
            registers,
            xstate: vec![0x5a; 832],
            mask: 0x200,
        },
        until: Instant::now() + Duration::from_secs(3),
    }
}
fn attached(binding: KernelAttemptBinding) -> (KernelJournalWriter, KernelAttemptHandle) {
    let mut writer = KernelJournalWriter::new(SESSION);
    let prepared = writer.prepare(binding).unwrap();
    // This model harness tests archive transactions. Actual census debiting is
    // exercised separately by completion/journal_tests.rs, before native work.
    let handle = writer.attach(prepared).unwrap();
    (writer, handle)
}
fn event(task: DynamicTask, tid: i32, sequence: u64, kind: DynamicEventKind) -> DynamicEvent {
    DynamicEvent {
        tid,
        task: Some(task),
        kind,
        stop: Some(DynamicStop {
            session: SESSION,
            sequence,
            tid,
            task: Some(task.task),
        }),
    }
}
fn put_state(
    writer: &mut KernelJournalWriter,
    handle: KernelAttemptHandle,
    slot: KernelStateSlot,
    state: &TaskStateSnapshot,
) {
    let mut archive = writer.lock();
    let attempt = KernelJournalWriter::attempt_mut(&mut archive, handle).unwrap();
    let stored = &mut attempt.states[slot.index()];
    assert_eq!(stored.status, KernelCaptureStatus::Unused);
    stored.bytes.as_mut().unwrap()[..state.xstate.len()].copy_from_slice(&state.xstate);
    stored.length = state.xstate.len();
    stored.registers = Some(state.registers);
    stored.mask = state.mask;
    stored.status = KernelCaptureStatus::Complete;
}
fn raw(
    writer: &mut KernelJournalWriter,
    handle: KernelAttemptHandle,
    slot: KernelStateSlot,
    tid: i32,
    state: &TaskStateSnapshot,
    info: Option<KernelSyscallInfo>,
    message: Option<u64>,
) {
    let record = {
        let mut archive = writer.lock();
        let attempt = KernelJournalWriter::attempt_mut(&mut archive, handle).unwrap();
        let record = attempt.raw_count;
        attempt.raw_count += 1;
        attempt.raw_slots[slot.index()] = Some(record);
        let task = (tid == 100).then_some(attempt.binding.original_stop.identity);
        let status = match slot {
            KernelStateSlot::Creation => {
                (libc::PTRACE_EVENT_CLONE << 16) | (libc::SIGTRAP << 8) | 0x7f
            }
            KernelStateSlot::Newborn => {
                (libc::PTRACE_EVENT_STOP << 16) | (libc::SIGTRAP << 8) | 0x7f
            }
            _ => 0x857f,
        };
        attempt
            .append(KernelJournalFact::RawStop {
                record,
                tid,
                status,
                pin: KernelPinKind::Thread,
                task,
            })
            .unwrap();
        record
    };
    if let Some(info) = info {
        writer
            .append(handle, KernelJournalFact::SyscallInfo { record, info })
            .unwrap();
    }
    if let Some(value) = message {
        writer
            .append(handle, KernelJournalFact::EventMessage { record, value })
            .unwrap();
    }
    put_state(writer, handle, slot, state);
    writer
        .append(handle, KernelJournalFact::StateCaptured { record, slot })
        .unwrap();
}
fn info(state: &TaskStateSnapshot, entry: bool, args: [u64; 6]) -> KernelSyscallInfo {
    let mut bytes = [0_u8; 88];
    bytes[0] = if entry { 1 } else { 2 };
    bytes[4..8].copy_from_slice(&0xc000_003e_u32.to_ne_bytes());
    bytes[8..16].copy_from_slice(&state.registers.rip.to_ne_bytes());
    bytes[16..24].copy_from_slice(&state.registers.rsp.to_ne_bytes());
    bytes[24..32].copy_from_slice(
        &(if entry {
            state.registers.orig_rax
        } else {
            state.registers.rax
        })
        .to_ne_bytes(),
    );
    if entry {
        for (i, arg) in args.into_iter().enumerate() {
            bytes[32 + i * 8..40 + i * 8].copy_from_slice(&arg.to_ne_bytes());
        }
    } else {
        bytes[32] = u8::from((-4095..=-1).contains(&(state.registers.rax as i64)));
    }
    KernelSyscallInfo {
        returned_bytes: if entry { 80 } else { 33 },
        initialized: bytes,
    }
}
fn model_entry(
    writer: &mut KernelJournalWriter,
    handle: KernelAttemptHandle,
) -> (DynamicEvent, TaskStateSnapshot) {
    let (original, mut state, input) = {
        let archive = writer.lock();
        let a = &archive.attempts[0];
        (
            a.binding.original_stop.clone(),
            a.binding.before.clone(),
            a.binding.input.clone(),
        )
    };
    let until = writer.lock().attempts[0].binding.until;
    writer
        .check_invocation(handle, &original, &input, &state, until)
        .unwrap();
    writer
        .release_attempt(handle, KernelReleasePhase::Original, &original.token)
        .unwrap();
    writer
        .release_succeeded(handle, KernelReleasePhase::Original, &original.token)
        .unwrap();
    state.registers.rip += 2;
    state.registers.orig_rax = input.registers().rax;
    state.registers.rax = (-38_i64) as u64;
    state.registers.rcx = PC + 2;
    state.registers.r11 = state.registers.eflags;
    let args = arguments(input.registers());
    raw(
        writer,
        handle,
        KernelStateSlot::Entry,
        100,
        &state,
        Some(info(&state, true, args)),
        None,
    );
    let event = event(
        original.identity,
        100,
        8,
        DynamicEventKind::SyscallEntry {
            number: input.registers().rax,
            arguments: args,
        },
    );
    (event, state)
}

#[test]
fn original_release_binding_checks_exact_input_state_stop_and_absolute_deadline() {
    let input = binding();
    let saved = input.clone();
    let (writer, handle) = attached(input);
    let before = writer.reader().snapshot();
    assert!(
        writer
            .check_invocation(
                handle,
                &saved.original_stop,
                &saved.input,
                &saved.before,
                saved.until + Duration::from_nanos(1)
            )
            .is_err()
    );
    let mut stop = saved.original_stop.clone();
    stop.token.sequence -= 1;
    assert!(
        writer
            .check_invocation(handle, &stop, &saved.input, &saved.before, saved.until)
            .is_err()
    );
    let mut state = saved.before.clone();
    state.registers.rax ^= 1;
    let changed = SelectedInput::new(saved.input.instruction().clone(), state.registers).unwrap();
    assert!(
        writer
            .check_invocation(handle, &saved.original_stop, &changed, &state, saved.until)
            .is_err()
    );
    state = saved.before.clone();
    state.mask ^= 1;
    assert!(
        writer
            .check_invocation(
                handle,
                &saved.original_stop,
                &saved.input,
                &state,
                saved.until
            )
            .is_err()
    );
    assert_eq!(writer.reader().snapshot(), before);
    writer
        .check_invocation(
            handle,
            &saved.original_stop,
            &saved.input,
            &saved.before,
            saved.until,
        )
        .unwrap();
    assert_eq!(writer.reader().snapshot(), before);
}

#[test]
fn prepare_is_unpublished_and_refuses_mismatched_binding_without_archive_changes() {
    let mut writer = KernelJournalWriter::new(SESSION);
    let before = writer.reader().snapshot();
    let prepared = writer.prepare(binding()).unwrap();
    assert!(prepared.retained_bytes() >= 8 * MAX_XSTATE);
    assert_eq!(writer.reader().snapshot(), before);
    drop(prepared);
    for fault in 0..5 {
        let mut input = binding();
        match fault {
            0 => input.pending.stop.sequence += 1,
            1 => input.pending.epoch += 1,
            2 => input.before.registers.rax += 1,
            3 => input.before.xstate.truncate(511),
            _ => input.pending.invocation = 0,
        }
        assert!(writer.prepare(input).is_err());
        assert_eq!(writer.reader().snapshot(), before);
    }
    let mut foreign = KernelJournalWriter::new(SESSION);
    let prepared = writer.prepare(binding()).unwrap();
    let unused_foreign = foreign.prepare(binding()).unwrap();
    assert!(foreign.attach(prepared).is_err());
    assert_eq!(foreign.reader().snapshot(), before);
    assert_eq!(writer.reader().snapshot(), before);
    drop(unused_foreign);
}

#[test]
fn validation_failure_retains_raw_prefix_and_cannot_authorize_entry_release() {
    let (mut writer, handle) = attached(binding());
    let (mut entry, state) = model_entry(&mut writer, handle);
    let before = writer.reader().snapshot();
    entry.kind = DynamicEventKind::SyscallEntry {
        number: 999,
        arguments: [0; 6],
    };
    assert!(writer.validated_entry(handle, &entry, &state).is_err());
    assert_eq!(writer.reader().snapshot(), before);
    assert!(
        writer
            .release_attempt(
                handle,
                KernelReleasePhase::Entry,
                entry.stop_token().unwrap()
            )
            .is_err()
    );
    assert_eq!(writer.reader().snapshot(), before);
    writer.fail_active(KernelFailureKind::InvalidState);
    let after = writer.reader().snapshot();
    assert_eq!(after.attempts[0].facts, before.attempts[0].facts);
    assert_eq!(after.attempts[0].states, before.attempts[0].states);
    assert_eq!(
        after.attempts[0].failure.unwrap().kind,
        KernelFailureKind::InvalidState
    );
}

#[test]
fn foreign_handles_partial_captures_and_overflow_never_replace_committed_prefix() {
    let (mut writer, handle) = attached(binding());
    let (entry, state) = model_entry(&mut writer, handle);
    writer.validated_entry(handle, &entry, &state).unwrap();
    let before = writer.reader().snapshot();
    let mut foreign = handle;
    foreign.id.session += 1;
    assert!(writer.validated_entry(foreign, &entry, &state).is_err());
    assert_eq!(writer.reader().snapshot(), before);
    {
        let mut archive = writer.lock();
        let a = &mut archive.attempts[0];
        a.states[KernelStateSlot::Exit.index()].status = KernelCaptureStatus::InProgress;
        a.states[KernelStateSlot::Exit.index()]
            .bytes
            .as_mut()
            .unwrap()[0] = 99;
    }
    assert_eq!(writer.reader().snapshot().attempts[0].states[4].state, None);
    writer.lock().attempts[0].states[4].status =
        KernelCaptureStatus::Failed(KernelFailureKind::NativeIo(Some(libc::EIO)));
    assert_eq!(writer.reader().snapshot().attempts[0].states[4].state, None);
    let fact = KernelJournalFact::RawStop {
        record: 31,
        tid: 100,
        status: 0,
        pin: KernelPinKind::Process,
        task: entry.task,
    };
    while writer.lock().attempts[0].length < FACTS {
        writer.append(handle, fact).unwrap();
    }
    let full = writer.reader().snapshot();
    assert!(writer.append(handle, fact).is_err());
    let after = writer.reader().snapshot();
    assert_eq!(after.attempts[0].facts, full.attempts[0].facts);
    assert_eq!(after.attempts[0].facts.len(), 32);
    assert_eq!(
        after.attempts[0].failure.unwrap().kind,
        KernelFailureKind::Capacity
    );
    assert!(writer.append(handle, fact).is_err());
}

#[test]
fn caught_unwind_survives_taken_local_and_writer_drop_without_fabricating_cleanup() {
    let (writer, _) = attached(binding());
    let reader = writer.reader();
    let result = catch_unwind(AssertUnwindSafe(|| {
        let _scope = writer.panic_scope();
        let _taken_local = Box::new([17; 4]);
        std::panic::panic_any("journal model panic");
    }));
    assert_eq!(
        result.unwrap_err().downcast_ref::<&str>(),
        Some(&"journal model panic")
    );
    drop(writer);
    let snapshot = reader.snapshot();
    assert_eq!(snapshot.writer, KernelWriterStatus::Active);
    assert_eq!(
        snapshot.attempts[0].failure.unwrap().kind,
        KernelFailureKind::CaughtPanic
    );
    assert!(snapshot.attempts[0].facts.is_empty());
}

#[test]
fn poisoned_append_lock_preserves_prefix_and_marks_inspection_incomplete() {
    let (mut writer, handle) = attached(binding());
    let reader = writer.reader();
    let _ = model_entry(&mut writer, handle);
    let before = reader.snapshot();
    let result = catch_unwind(AssertUnwindSafe(|| {
        let _lock = writer.lock();
        std::panic::panic_any("journal lock panic");
    }));
    assert_eq!(
        result.unwrap_err().downcast_ref::<&str>(),
        Some(&"journal lock panic")
    );
    assert!(reader.snapshot().archive_poisoned);
    assert_eq!(
        reader.snapshot().attempts[0].facts,
        before.attempts[0].facts
    );
    assert!(
        writer
            .append(
                handle,
                KernelJournalFact::AdmissionComplete {
                    task: binding().pending.task
                }
            )
            .is_err()
    );
    writer.close(
        KernelWriterStatus::FailedCleanup,
        Some(KernelFailureKind::ArchivePoisoned),
    );
    assert_eq!(reader.snapshot().writer, KernelWriterStatus::FailedCleanup);
    assert_eq!(
        reader.snapshot().attempts[0].facts,
        before.attempts[0].facts
    );
}

#[test]
fn child_first_clone_prefix_preserves_order_and_longest_success_fits_exactly() {
    let mut registry = registry();
    let parent_id = registry.root_task();
    let parent = identity(&registry, parent_id);
    let (mut writer, handle) = attached(binding_from(&registry, libc::SYS_clone as u64));
    let (entry, entry_state) = model_entry(&mut writer, handle);
    writer
        .validated_entry(handle, &entry, &entry_state)
        .unwrap();
    writer
        .release_attempt(
            handle,
            KernelReleasePhase::Entry,
            entry.stop_token().unwrap(),
        )
        .unwrap();
    writer
        .release_succeeded(
            handle,
            KernelReleasePhase::Entry,
            entry.stop_token().unwrap(),
        )
        .unwrap();
    registry.resume(parent_id, 0).unwrap();
    registry
        .observe_stop(parent_id, 1, PC + 2, HoldReason::SyscallEntry)
        .unwrap();
    let ticket = registry
        .prepare_creation(parent_id, CreationRequest::Clone { flags: 0x10f00 })
        .unwrap();
    registry.resume(parent_id, 1).unwrap();
    let child_id = registry
        .observe_creation(
            ticket,
            2,
            CreationEvent {
                kind: CreationEventKind::Clone,
                child_tid: 101,
                child_tgid: 100,
                parent_visible_tid: 101,
                parent_pc: PC + 2,
            },
        )
        .unwrap();
    let child = identity(&registry, child_id);
    let mut child_state = entry_state.clone();
    child_state.registers.rax = 0;
    child_state.registers.rsp = 0x700000;
    raw(
        &mut writer,
        handle,
        KernelStateSlot::Newborn,
        101,
        &child_state,
        None,
        None,
    );
    raw(
        &mut writer,
        handle,
        KernelStateSlot::Creation,
        100,
        &entry_state,
        None,
        Some(101),
    );
    let created = event(parent, 100, 9, DynamicEventKind::Created { child });
    let newborn = event(child, 101, 1, DynamicEventKind::Newborn { parent });
    writer
        .validated_creation(handle, &created, &newborn)
        .unwrap();
    let snapshot = writer.reader().snapshot();
    let raw_order: Vec<_> = snapshot.attempts[0]
        .facts
        .iter()
        .filter_map(|fact| match fact {
            KernelJournalFact::RawStop { tid, task, .. } => Some((*tid, *task)),
            _ => None,
        })
        .collect();
    assert_eq!(
        raw_order,
        vec![(100, Some(parent)), (101, None), (100, Some(parent))]
    );
    writer
        .release_attempt(
            handle,
            KernelReleasePhase::Creation,
            created.stop_token().unwrap(),
        )
        .unwrap();
    writer
        .release_succeeded(
            handle,
            KernelReleasePhase::Creation,
            created.stop_token().unwrap(),
        )
        .unwrap();
    let mut exit_state = entry_state;
    exit_state.registers.rax = 101;
    raw(
        &mut writer,
        handle,
        KernelStateSlot::Exit,
        100,
        &exit_state,
        Some(info(&exit_state, false, [0; 6])),
        None,
    );
    let exit = event(
        parent,
        100,
        10,
        DynamicEventKind::SyscallExit {
            result: 101,
            is_error: false,
        },
    );
    writer.validated_exit(handle, &exit, &exit_state).unwrap();
    let parent_bridge = AdmissionStop {
        token: DynamicStop {
            session: SESSION,
            sequence: 12,
            tid: 100,
            task: Some(parent.task),
        },
        identity: parent,
        phase: trusted::AdmissionPhase::Restored,
        signal: None,
    };
    let child_bridge = AdmissionStop {
        token: DynamicStop {
            session: SESSION,
            sequence: 3,
            tid: 101,
            task: Some(child.task),
        },
        identity: child,
        phase: trusted::AdmissionPhase::Restored,
        signal: None,
    };
    writer.bridge_begin(handle, parent, false).unwrap();
    put_state(
        &mut writer,
        handle,
        KernelStateSlot::ParentBridge,
        &exit_state,
    );
    writer
        .bridge_committed(handle, KernelStateSlot::ParentBridge, &parent_bridge)
        .unwrap();
    writer.bridge_begin(handle, child, true).unwrap();
    put_state(
        &mut writer,
        handle,
        KernelStateSlot::NewbornBridge,
        &child_state,
    );
    writer
        .bridge_committed(handle, KernelStateSlot::NewbornBridge, &child_bridge)
        .unwrap();
    writer
        .transport_complete(handle, &parent_bridge, Some(&child_bridge))
        .unwrap();
    let before_finish = writer.reader().snapshot();
    assert!(writer.finish_admission(handle, parent).is_err());
    assert_eq!(writer.reader().snapshot(), before_finish);
    writer
        .finish_admission(
            handle,
            DynamicTask {
                generation: 1,
                ..parent
            },
        )
        .unwrap();
    let completed = writer.reader().snapshot();
    assert_eq!(completed.attempts[0].facts.len(), LONGEST_SUCCESS);
    assert_eq!(completed.attempts[0].facts.len(), 26);
    assert_eq!(
        completed.attempts[0]
            .states
            .iter()
            .filter(|state| state.status == KernelCaptureStatus::Complete)
            .count(),
        7
    );
    assert!(completed.attempts[0].failure.is_none());
    assert!(
        writer
            .finish_admission(
                handle,
                DynamicTask {
                    generation: 2,
                    ..parent
                }
            )
            .is_err()
    );
    assert_eq!(writer.reader().snapshot(), completed);
}

#[test]
fn full_state_validation_does_not_accept_register_xstate_or_mask_corruption() {
    let (mut writer, handle) = attached(binding());
    let (entry, state) = model_entry(&mut writer, handle);
    let before = writer.reader().snapshot();
    for field in 0..3 {
        let mut corrupted = state.clone();
        match field {
            0 => corrupted.registers.r15 ^= 1,
            1 => corrupted.xstate[511] ^= 1,
            _ => corrupted.mask ^= 1,
        }
        assert!(writer.validated_entry(handle, &entry, &corrupted).is_err());
        assert_eq!(writer.reader().snapshot(), before);
    }
    writer.validated_entry(handle, &entry, &state).unwrap();
    let validated = writer.reader().snapshot();
    assert!(writer.validated_entry(handle, &entry, &state).is_err());
    assert_eq!(writer.reader().snapshot(), validated);
}

#[test]
fn first_failure_is_preserved_across_closing_and_failed_cleanup() {
    let (mut writer, handle) = attached(binding());
    let reader = writer.reader();
    let _ = model_entry(&mut writer, handle);
    let before = reader.snapshot();
    writer.fail_active(KernelFailureKind::Timeout);
    writer.close(
        KernelWriterStatus::Closing,
        Some(KernelFailureKind::Cancelled),
    );
    writer.close(
        KernelWriterStatus::FailedCleanup,
        Some(KernelFailureKind::NativeIo(Some(libc::ECHILD))),
    );
    let after = reader.snapshot();
    assert_eq!(
        after.attempts[0].failure.unwrap().kind,
        KernelFailureKind::Timeout
    );
    assert_eq!(after.attempts[0].facts, before.attempts[0].facts);
    assert_eq!(after.writer, KernelWriterStatus::FailedCleanup);
    assert!(!after.attempts[0].facts.iter().any(|fact| matches!(
        fact,
        KernelJournalFact::TransportComplete { .. } | KernelJournalFact::AdmissionComplete { .. }
    )));
}
