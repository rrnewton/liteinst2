//! Force only lifecycle processing order. The two genuine wait deliveries are
//! journaled immediately in their actual collection order, while both tasks
//! remain held. No test changes production capture order or invents child EXIT.
use super::super::super::kernel_journal::tests::native::{
    self, APP_MASK, CHILD_SP, FLAGS, Fixture, Frame, TIMEOUT, assert_echild, duplicate,
    physically_gone, raw, spawn_masked,
};
use super::super::super::kernel_journal::{
    self, KernelAttemptSnapshot, KernelCaptureStatus, KernelCapturedState, KernelJournalFact,
    KernelJournalStage, KernelPinKind, KernelProgressSnapshot, KernelReleasePhase, KernelStateSlot,
    KernelWriterStatus,
};
use super::*;
use crate::lifecycle::{HoldReason, TaskState};
use std::sync::mpsc::sync_channel;

static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
enum DispatchOrder {
    ParentFirst,
    NewbornFirst,
}

fn attempt(snapshot: &KernelProgressSnapshot) -> &KernelAttemptSnapshot {
    assert!(!snapshot.archive_poisoned);
    assert_eq!(snapshot.attempts.len(), 1);
    &snapshot.attempts[0]
}

fn captured(snapshot: &KernelProgressSnapshot, slot: KernelStateSlot) -> &KernelCapturedState {
    let rows = attempt(snapshot)
        .states
        .iter()
        .filter(|row| row.slot == slot)
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, KernelCaptureStatus::Complete);
    rows[0].state.as_ref().expect("complete initialized state")
}

fn raw_rows(
    snapshot: &KernelProgressSnapshot,
) -> Vec<(u8, i32, i32, KernelPinKind, Option<DynamicTask>)> {
    attempt(snapshot)
        .facts
        .iter()
        .filter_map(|fact| match fact {
            KernelJournalFact::RawStop {
                record,
                tid,
                status,
                pin,
                task,
            } => Some((*record, *tid, *status, *pin, *task)),
            _ => None,
        })
        .collect()
}

fn assert_incomplete(snapshot: &KernelProgressSnapshot) {
    assert!(!attempt(snapshot).facts.iter().any(|fact| matches!(
        fact,
        KernelJournalFact::ValidatedExit { .. }
            | KernelJournalFact::BridgeBegin { .. }
            | KernelJournalFact::BridgeComplete { .. }
            | KernelJournalFact::TransportComplete { .. }
            | KernelJournalFact::AdmissionComplete { .. }
            | KernelJournalFact::ReleaseAttempt {
                phase: KernelReleasePhase::Creation,
                ..
            }
            | KernelJournalFact::ReleaseSucceeded {
                phase: KernelReleasePhase::Creation,
                ..
            }
    )));
    for slot in [
        KernelStateSlot::Exit,
        KernelStateSlot::ParentBridge,
        KernelStateSlot::NewbornBridge,
        KernelStateSlot::Unexpected,
    ] {
        let row = attempt(snapshot)
            .states
            .iter()
            .find(|row| row.slot == slot)
            .unwrap();
        assert_eq!(row.status, KernelCaptureStatus::Unused);
        assert!(row.state.is_none());
    }
}

fn frame_matches(actual: &Frame, expected: &Frame) {
    // Complete GPRs (including orig_rax/RFLAGS), XSTATE, mask, initialized
    // stack/data and full source bytes. These phases contain no PID result,
    // so there is no normalization or substituted architectural field.
    assert_eq!(actual, expected);
    let mut bad = actual.clone();
    bad.state.registers.r11 ^= 1;
    assert_ne!(&bad, expected);
    let mut bad = actual.clone();
    bad.state.xstate[0] ^= 1;
    assert_ne!(&bad, expected);
    let mut bad = actual.clone();
    bad.state.signal_mask ^= 1;
    assert_ne!(&bad, expected);
    let mut bad = actual.clone();
    bad.storage[0] ^= 1;
    assert_ne!(&bad, expected);
    let mut bad = actual.clone();
    bad.source[0] ^= 1;
    assert_ne!(&bad, expected);
}

fn dispatch_body(
    owner: &mut Owner,
    fixture: &Fixture,
    oracle: &raw::Oracle,
    order: DispatchOrder,
    inherited_mask: u64,
    retained: &mut Option<AdmissionOwner>,
    window: &mut Option<routes::OriginalWindow>,
) {
    let options = DynamicAdmissionOptions {
        lifecycle: DynamicLifecycleOptions::thread_only(),
        ..DynamicAdmissionOptions::default()
    };
    let (_, reader) = native::launch_owner(owner, fixture, options, inherited_mask);
    let until = Instant::now() + TIMEOUT;
    let AdmissionReply::Provider(provider) = owner
        .execute_admission(AdmissionRequest::Advance, until)
        .unwrap()
    else {
        panic!("actual selected clone provider input");
    };
    assert_eq!(
        provider.input.instruction().logical_pc(),
        fixture.selected_pc
    );
    assert_eq!(provider.input.instruction().bytes(), [0x0f, 0x05]);
    assert_eq!(provider.input.registers().rax, libc::SYS_clone as u64);
    assert_eq!(provider.input.registers().eflags, FLAGS);
    *retained = Some(
        owner
            .admission
            .take()
            .expect("actual initialized admission"),
    );
    let admission = retained.as_mut().unwrap();
    admission
        .authenticate_pending(owner, &provider.token, until)
        .unwrap();
    admission
        .check_native_policy(owner, &provider.input)
        .unwrap();
    let pending = admission.pending.as_ref().unwrap();
    let prepared = owner
        .kernel_journal
        .prepare(KernelAttemptBinding {
            pending: pending.token.clone(),
            original_stop: pending.stop.clone(),
            input: pending.input.clone(),
            before: TaskStateSnapshot {
                registers: pending.before.registers,
                xstate: pending.before.xstate.clone(),
                mask: pending.before.signal_mask,
            },
            until,
        })
        .unwrap();
    let bytes = prepared.retained_bytes();
    let reservation = admission
        .reserve_transition_with_prefix(owner, 2, true, 1, bytes)
        .unwrap();
    admission
        .check_completion_budget(owner, reservation, 2, true, 1)
        .unwrap();
    admission
        .census
        .account_external(
            reservation,
            BudgetCharge {
                source_fact_bytes: bytes,
                ..BudgetCharge::default()
            },
        )
        .unwrap();
    let handle = owner.kernel_journal.attach(prepared).unwrap();
    let pending = admission.pending.take().unwrap();
    let task = pending.token.task.task;
    {
        let mut held = HeldMmStop::acquire(
            owner,
            &mut admission.native,
            &mut admission.island,
            task,
            until,
        )
        .unwrap();
        *window = Some(
            routes::restore_original(
                &mut held,
                &admission.domain,
                fixture.selected_pc,
                pending.input.instruction().bytes(),
                until,
            )
            .unwrap(),
        );
    }
    admission
        .refresh_all_same_pc(owner, reservation, task, until)
        .unwrap();
    let before = admission.observe_current(owner, task).unwrap();
    assert_eq!(before.registers, *pending.input.registers());
    assert_eq!(before.xstate, pending.before.xstate);
    assert_eq!(before.signal_mask, pending.before.signal_mask);
    assert_eq!(before.phase, StopPhase::UserCheckpoint);
    admission
        .check_completion_budget(owner, reservation, 2, true, 1)
        .unwrap();
    let current = admission.native.admission_current(task).unwrap();
    let full_before = TaskStateSnapshot::read(current.token.tid).unwrap();
    assert_eq!(full_before.registers, before.registers);
    assert_eq!(full_before.xstate, before.xstate);
    assert_eq!(full_before.mask, APP_MASK);
    assert_eq!(
        admission
            .native
            .admission_interrupt_credit(current.token.tid)
            .unwrap(),
        0
    );
    let members = admission.native.check_admission_mm(owner, task).unwrap();
    assert_eq!(members.tids, BTreeSet::from([owner.pid]));
    assert!(admission.native.admission_events_empty());
    admission.island.verify(owner.pid).unwrap();
    frame_matches(&raw::frame(owner.pid), &oracle.original);
    owner
        .kernel_journal
        .check_invocation(handle, &current, &pending.input, &full_before, until)
        .unwrap();
    owner
        .kernel_journal
        .release_attempt(handle, KernelReleasePhase::Original, &current.token)
        .unwrap();
    owner
        .time_left(until, "kernel journal dispatch original release")
        .unwrap();
    // SAFETY: real admission authenticated the exact policy, full mm and source;
    // the restored original window remains in the outer harness until cleanup.
    unsafe {
        admission
            .native
            .begin_admission_original(owner, &current, libc::PTRACE_SYSCALL)
            .unwrap();
    }
    owner
        .kernel_journal
        .release_succeeded(handle, KernelReleasePhase::Original, &current.token)
        .unwrap();
    let (parent, entry_status) = owner
        .wait_raw(until, "kernel journal dispatch ENTRY")
        .unwrap();
    owner
        .capture_kernel_raw(handle, parent, entry_status)
        .unwrap();
    assert_eq!(parent, owner.pid);
    assert_eq!(entry_status, ((libc::SIGTRAP | 0x80) << 8) | 0x7f);
    let entry = admission
        .native
        .observe_admission_other(owner, parent, entry_status)
        .unwrap()
        .unwrap();
    assert_eq!(
        entry.kind,
        DynamicEventKind::SyscallEntry {
            number: libc::SYS_clone as u64,
            arguments: [0x10f00, CHILD_SP, 0, 0, 0, pending.input.registers().r9],
        }
    );
    let entry_frame = raw::frame(parent);
    frame_matches(&entry_frame, &oracle.entry);
    let entry_state = TaskStateSnapshot::read(parent).unwrap();
    owner
        .kernel_journal
        .validated_entry(handle, &entry, &entry_state)
        .unwrap();
    let entry_token = entry.stop_token().unwrap();
    owner
        .kernel_journal
        .release_attempt(handle, KernelReleasePhase::Entry, entry_token)
        .unwrap();
    owner
        .time_left(until, "kernel journal dispatch ENTRY release")
        .unwrap();
    // SAFETY: this is the single original clone invocation. Its exact native
    // lifecycle policy remains enforced by the production resume implementation.
    unsafe {
        admission
            .native
            .resume_admission_event(owner, entry_token, DynamicResume::Continue)
            .unwrap();
    }
    owner
        .kernel_journal
        .release_succeeded(handle, KernelReleasePhase::Entry, entry_token)
        .unwrap();

    // Actual collection order is immutable evidence. Capture each delivered,
    // already-pinned wait before any test classification or lifecycle dispatch.
    let mut observed = Vec::with_capacity(2);
    for _ in 0..2 {
        let row = owner
            .wait_raw(until, "kernel journal dispatch pair")
            .unwrap();
        owner.capture_kernel_raw(handle, row.0, row.1).unwrap();
        observed.push(row);
    }
    assert_ne!(observed[0].0, observed[1].0);
    let parent_row = *observed.iter().find(|(tid, _)| *tid == parent).unwrap();
    let child_row = *observed.iter().find(|(tid, _)| *tid != parent).unwrap();
    let child = child_row.0;
    assert_eq!(
        parent_row.1,
        (libc::PTRACE_EVENT_CLONE << 16) | (libc::SIGTRAP << 8) | 0x7f
    );
    assert_eq!(
        child_row.1,
        (libc::PTRACE_EVENT_STOP << 16) | (libc::SIGTRAP << 8) | 0x7f
    );
    assert_eq!(owner.owned, BTreeSet::from([parent, child]));
    assert_eq!(owner.stopped.get(&parent), Some(&parent_row.1));
    assert_eq!(owner.stopped.get(&child), Some(&child_row.1));
    assert_eq!(
        owner.pin_kinds.get(&child),
        Some(&super::super::super::PinKind::Thread)
    );
    let retained_pins = [
        duplicate(&owner.handles[&parent]),
        duplicate(&owner.handles[&child]),
    ];
    assert!(retained_pins.iter().all(|pin| !physically_gone(pin)));
    let parent_frame = raw::frame(parent);
    let child_frame = raw::frame(child);
    frame_matches(&parent_frame, oracle.creation.as_ref().unwrap());
    frame_matches(&child_frame, oracle.newborn.as_ref().unwrap());
    assert_eq!(child_frame.state.registers.rax, 0);
    assert_eq!(child_frame.state.registers.rsp, CHILD_SP);
    let collected = reader.snapshot();
    let expected_rows = std::iter::once((
        0,
        parent,
        entry_status,
        KernelPinKind::Process,
        Some(current.identity),
    ))
    .chain(observed.iter().enumerate().map(|(index, &(tid, status))| {
        (
            (index + 1) as u8,
            tid,
            status,
            if tid == parent {
                KernelPinKind::Process
            } else {
                KernelPinKind::Thread
            },
            (tid == parent).then_some(current.identity),
        )
    }))
    .collect::<Vec<_>>();
    assert_eq!(raw_rows(&collected), expected_rows);
    let syscall_rows = attempt(&collected)
        .facts
        .iter()
        .filter_map(|fact| match fact {
            KernelJournalFact::SyscallInfo { record, info } => {
                Some((*record, info.returned_bytes, info.initialized))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        syscall_rows,
        vec![(0, oracle.entry_info.0, oracle.entry_info.1)]
    );
    let payloads = attempt(&collected)
        .facts
        .iter()
        .filter_map(|fact| match fact {
            KernelJournalFact::EventMessage { record, value } => Some((*record, *value)),
            _ => None,
        })
        .collect::<Vec<_>>();
    let parent_record = expected_rows
        .iter()
        .find(|(_, tid, status, _, _)| *tid == parent && *status == parent_row.1)
        .unwrap()
        .0;
    assert_eq!(payloads, vec![(parent_record, child as u64)]);
    assert_eq!(
        captured(&collected, KernelStateSlot::Original),
        &oracle.original.state
    );
    assert_eq!(
        captured(&collected, KernelStateSlot::Entry),
        &oracle.entry.state
    );
    assert_eq!(
        captured(&collected, KernelStateSlot::Creation),
        &parent_frame.state
    );
    assert_eq!(
        captured(&collected, KernelStateSlot::Newborn),
        &child_frame.state
    );
    assert!(attempt(&collected).failure.is_none());
    assert_incomplete(&collected);
    assert_eq!(admission.native.admission_snapshot().tasks().count(), 1);

    let dispatch = match order {
        DispatchOrder::ParentFirst => [parent_row, child_row],
        DispatchOrder::NewbornFirst => [child_row, parent_row],
    };
    assert!(
        admission
            .native
            .observe_admission_other(owner, dispatch[0].0, dispatch[0].1)
            .unwrap()
            .is_none()
    );
    assert_eq!(admission.native.admission_snapshot().tasks().count(), 1);
    assert_eq!(
        reader.snapshot(),
        collected,
        "dispatch does not rewrite raw collection history"
    );
    let created = admission
        .native
        .observe_admission_other(owner, dispatch[1].0, dispatch[1].1)
        .unwrap()
        .unwrap();
    let born = admission
        .native
        .take_admission_event()
        .expect("joined real newborn event");
    assert!(admission.native.admission_events_empty());
    let newborn = born.task.unwrap();
    assert_eq!(created.kind, DynamicEventKind::Created { child: newborn });
    assert_eq!(created.task, Some(current.identity));
    assert_eq!(created.tid, parent);
    assert_eq!(
        born.kind,
        DynamicEventKind::Newborn {
            parent: current.identity
        }
    );
    assert_eq!(born.tid, child);
    assert_ne!(newborn.task, current.identity.task);
    assert_eq!(newborn.process, current.identity.process);
    assert_eq!(newborn.address_space, current.identity.address_space);
    assert_eq!(newborn.generation, current.identity.generation);
    let registry = admission.native.admission_snapshot();
    assert_eq!(registry.tasks().count(), 2);
    assert_eq!(registry.address_spaces().count(), 1);
    let child_record = registry
        .tasks()
        .find(|record| record.id == newborn.task)
        .unwrap();
    assert!(matches!(
        child_record.state,
        TaskState::Held {
            reason: HoldReason::NewbornReturnReady,
            ..
        }
    ));
    assert_eq!(raw::frame(parent), parent_frame);
    assert_eq!(raw::frame(child), child_frame);
    assert_eq!(reader.snapshot(), collected);
    owner
        .kernel_journal
        .validated_creation(handle, &created, &born)
        .unwrap();
    let joined = reader.snapshot();
    assert_eq!(raw_rows(&joined), expected_rows);
    assert_eq!(attempt(&joined).states, attempt(&collected).states);
    assert_eq!(
        &attempt(&joined).facts[..attempt(&collected).facts.len()],
        attempt(&collected).facts.as_slice()
    );
    assert_eq!(
        attempt(&joined).facts.len(),
        attempt(&collected).facts.len() + 1
    );
    assert!(
        matches!(attempt(&joined).facts.last(), Some(KernelJournalFact::ValidatedCreation { parent: p, newborn: c, .. }) if p.tid == parent && c.tid == child && c.task == Some(newborn.task))
    );
    assert_incomplete(&joined);

    // A duplicate dispatch is not another wait/capture. The actual production
    // lifecycle rejects it; the outer transport would fail this invocation.
    let held_statuses = owner.stopped.clone();
    let owned = owner.owned.clone();
    let rejected = admission
        .native
        .observe_admission_other(owner, parent, parent_row.1);
    assert!(matches!(
        &rejected,
        Err(LaunchError::Invalid(
            "creation event differs from entry intent"
        ))
    ));
    assert_eq!(admission.native.admission_snapshot(), registry);
    assert_eq!(reader.snapshot(), joined);
    assert_eq!(owner.stopped, held_statuses);
    assert_eq!(owner.owned, owned);
    assert_eq!(raw::frame(parent), parent_frame);
    assert_eq!(raw::frame(child), child_frame);
    assert!(retained_pins.iter().all(|pin| !physically_gone(pin)));
    let error = rejected.unwrap_err();
    owner
        .kernel_journal
        .fail_active(kernel_journal::failure_kind(&error));
    owner.closing = true;
    owner.cancel.store(true, Ordering::Release);
    let failed = reader.snapshot();
    assert_eq!(attempt(&failed).facts, attempt(&joined).facts);
    assert_eq!(attempt(&failed).states, attempt(&joined).states);
    assert_eq!(
        attempt(&failed).failure,
        Some(kernel_journal::KernelJournalFailure {
            stage: KernelJournalStage::CreationValidation,
            kind: KernelFailureKind::InvalidState,
        })
    );
    assert_incomplete(&failed);
    assert!(admission.completion_history.is_empty());
}

fn run(order: DispatchOrder) {
    let fixture = Fixture::new(libc::SYS_clone);
    let oracle = raw::original(Arc::clone(&fixture));
    let (send, receive) = sync_channel(1);
    let worker = spawn_masked(move || {
        let blocked = launch::BlockedSignals::new().unwrap();
        let mut owner = Owner::new(
            NEXT_SESSION.fetch_add(1, Ordering::Relaxed),
            Arc::new(AtomicBool::new(false)),
        );
        let reader = owner.kernel_journal.reader();
        // These objects outlive any assertion unwind and the entire physical
        // cleanup; no restored original window is abandoned to execution.
        let mut retained = None;
        let mut window = None;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _unwind = owner.kernel_journal.panic_scope();
            dispatch_body(
                &mut owner,
                &fixture,
                &oracle,
                order,
                APP_MASK,
                &mut retained,
                &mut window,
            );
        }));
        let pins = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner
                .handles
                .iter()
                .map(|(&tid, pin)| (tid, duplicate(pin)))
                .collect::<Vec<_>>()
        }));
        let before_cleanup = reader.snapshot();
        // Never move wait ownership to the caller or kill the real-parent
        // reaper on a caller deadline. This thread retains cleanup on failure.
        let cleanup = owner.cleanup();
        drop(window);
        drop(retained);
        let restore = blocked.restore();
        let _ = send.send((result, pins, before_cleanup, reader, cleanup, restore));
    });
    let (result, pins, before_cleanup, reader, cleanup, restore) = receive
        .recv_timeout(3 * TIMEOUT)
        .expect("forced dispatch caller deadline; original owner retains physical cleanup");
    worker.join().unwrap();
    restore.unwrap();
    let pins = match pins {
        Ok(pins) => pins,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    let mut actual = cleanup.unwrap().reaped;
    let mut expected = pins.iter().map(|(tid, _)| *tid).collect::<Vec<_>>();
    actual.sort_unstable();
    expected.sort_unstable();
    assert_eq!(actual, expected);
    for (_, pin) in &pins {
        assert!(physically_gone(pin));
        assert_echild(pin);
    }
    assert_eq!(reader.snapshot().writer, KernelWriterStatus::Cleaned);
    assert_eq!(reader.snapshot().attempts, before_cleanup.attempts);
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
    assert_eq!(pins.len(), 2);
    assert_incomplete(&reader.snapshot());
}

#[test]
fn collected_clone_prefix_survives_parent_first_dispatch_and_rejection() {
    run(DispatchOrder::ParentFirst);
}

#[test]
fn collected_clone_prefix_survives_newborn_first_dispatch_and_rejection() {
    run(DispatchOrder::NewbornFirst);
}
