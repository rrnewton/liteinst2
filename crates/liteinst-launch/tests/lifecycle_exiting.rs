//! Ledger phase and exclusion tests, not native event or physical-reap evidence.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use liteinst_admission::entries::ResumeKind;
use liteinst_launch::lifecycle::*;

const PC: u64 = 0x401000;

fn registry() -> LifecycleRegistry {
    LifecycleRegistry::new_after_exec_syscall_exit(Limits::default(), 100, PC).unwrap()
}

fn sequence(r: &LifecycleRegistry, task: TaskId) -> u64 {
    r.task(task).unwrap().sequence + 1
}

fn resume(r: &mut LifecycleRegistry, task: TaskId) {
    r.resume(task, r.task(task).unwrap().sequence).unwrap();
}

fn unchanged<T: std::fmt::Debug>(
    r: &mut LifecycleRegistry,
    error: LifecycleError,
    action: impl FnOnce(&mut LifecycleRegistry) -> Result<T, LifecycleError>,
) {
    let before = r.snapshot();
    assert_eq!(action(r).unwrap_err(), error);
    assert_eq!(r.snapshot(), before);
}

#[test]
fn preexit_retains_identity_and_obligations_until_independent_terminal_status() {
    let mut r = registry();
    let task = r.root_task();
    let identity = r.task(task).unwrap().clone();
    let saved = r
        .record_obligation(
            task,
            ObligationKind::SavedResume {
                pc: PC + 64,
                kind: ResumeKind::SignalFrame,
            },
        )
        .unwrap();
    let obligations = r.obligations().cloned().collect::<Vec<_>>();
    resume(&mut r, task);
    r.observe_exit_event(task, 1, ExitStatus::Code(5)).unwrap();
    let record = r.task(task).unwrap();
    assert_eq!(record.id, identity.id);
    assert_eq!(record.tid, identity.tid);
    assert_eq!(record.process, identity.process);
    assert_eq!(record.address_space, identity.address_space);
    assert_eq!(record.origin, identity.origin);
    assert_eq!(record.sequence, 1);
    assert_eq!(
        record.state,
        TaskState::Exiting {
            event_status: ExitStatus::Code(5)
        }
    );
    assert_eq!(r.task_for_tid(100), Some(task));
    assert_eq!(r.obligations().cloned().collect::<Vec<_>>(), obligations);
    assert_eq!(obligations[0].id, saved);

    // A later group-fatal signal may change the actual terminal status. The
    // event payload is evidence of that event, not an immutable exit forecast.
    r.observe_exit(task, 2, ExitStatus::Signal(9)).unwrap();
    let record = r.task(task).unwrap();
    assert_eq!(record.sequence, 2);
    assert_eq!(
        record.state,
        TaskState::Terminal(TerminalReason::Exit(ExitStatus::Signal(9)))
    );
    assert_eq!(record.process, identity.process);
    assert_eq!(record.address_space, identity.address_space);
    assert_eq!(r.task_for_tid(100), None);
    assert_eq!(r.snapshot().tasks().count(), 1);
    assert_eq!(r.obligations().cloned().collect::<Vec<_>>(), obligations);
}

#[test]
fn preexit_rejects_wrong_phase_foreign_stale_duplicate_and_invalid_status_atomically() {
    let mut r = registry();
    let task = r.root_task();
    let foreign = registry().root_task();
    unchanged(&mut r, LifecycleError::WrongState, |r| {
        r.observe_exit_event(task, 1, ExitStatus::Code(0))
    });
    resume(&mut r, task);
    unchanged(&mut r, LifecycleError::UnknownIdentity, |r| {
        r.observe_exit_event(foreign, 1, ExitStatus::Code(0))
    });
    for wrong in [0, 2, u64::MAX] {
        unchanged(&mut r, LifecycleError::Stale, |r| {
            r.observe_exit_event(task, wrong, ExitStatus::Code(0))
        });
    }
    for signal in [0, 65, u8::MAX] {
        unchanged(&mut r, LifecycleError::EventMismatch, |r| {
            r.observe_exit_event(task, 1, ExitStatus::Signal(signal))
        });
    }
    r.observe_exit_event(task, 1, ExitStatus::Code(17)).unwrap();
    unchanged(&mut r, LifecycleError::Stale, |r| {
        r.observe_exit_event(task, 1, ExitStatus::Code(17))
    });
    unchanged(&mut r, LifecycleError::WrongState, |r| {
        r.observe_exit_event(task, 2, ExitStatus::Code(17))
    });
    unchanged(&mut r, LifecycleError::EventMismatch, |r| {
        r.observe_exit(task, 2, ExitStatus::Signal(0))
    });
    r.observe_exit(task, 2, ExitStatus::Code(23)).unwrap();
    unchanged(&mut r, LifecycleError::WrongState, |r| {
        r.observe_exit_event(task, 3, ExitStatus::Code(23))
    });
    unchanged(&mut r, LifecycleError::WrongState, |r| {
        r.observe_exit(task, 3, ExitStatus::Code(23))
    });
}

#[test]
fn exiting_member_blocks_release_and_exclusion_while_held_sibling_stays_controllable() {
    let mut r = registry();
    let parent = r.root_task();
    let mm = r.task(parent).unwrap().address_space;
    resume(&mut r, parent);
    r.observe_stop(parent, 1, PC + 2, HoldReason::SyscallEntry)
        .unwrap();
    let ticket = r
        .prepare_creation(parent, CreationRequest::Clone { flags: 0x10f00 })
        .unwrap();
    resume(&mut r, parent);
    let child = r
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
    r.observe_newborn_return_ready(child, 1, PC + 2).unwrap();
    resume(&mut r, parent);
    r.observe_creation_exit(ticket, 3, PC + 2, 101).unwrap();
    let held = r.exclusion_candidate(mm, 0).unwrap();
    assert_eq!(held.tasks, [parent, child]);
    resume(&mut r, parent);
    r.observe_exit_event(parent, 4, ExitStatus::Code(5))
        .unwrap();
    assert_eq!(r.exclusion_candidate(mm, 0), Err(LifecycleError::NotHeld));
    unchanged(&mut r, LifecycleError::Stale, |r| {
        r.begin_invalidation(&held)
    });
    unchanged(&mut r, LifecycleError::WrongState, |r| r.resume(parent, 4));
    unchanged(&mut r, LifecycleError::WrongState, |r| {
        r.observe_stop(parent, 5, PC, HoldReason::Interrupt)
    });
    unchanged(&mut r, LifecycleError::WrongState, |r| {
        r.prepare_exec(parent)
    });
    unchanged(&mut r, LifecycleError::WrongState, |r| {
        r.prepare_creation(parent, CreationRequest::Fork)
    });
    unchanged(&mut r, LifecycleError::NotHeld, |r| {
        r.record_obligation(
            parent,
            ObligationKind::SavedResume {
                pc: PC,
                kind: ResumeKind::SignalFrame,
            },
        )
    });

    // The exiting member is never treated as held, but another held task is
    // still individually controllable so it can make progress toward exit.
    resume(&mut r, child);
    r.observe_stop(child, 2, PC + 8, HoldReason::Interrupt)
        .unwrap();
    assert_eq!(r.exclusion_candidate(mm, 0), Err(LifecycleError::NotHeld));
    resume(&mut r, child);
    r.observe_exit_event(child, 3, ExitStatus::Code(7)).unwrap();
    r.observe_exit(child, sequence(&r, child), ExitStatus::Code(7))
        .unwrap();
    // A leader still awaiting its actual terminal is not an empty or held mm.
    assert_eq!(r.task_for_tid(100), Some(parent));
    assert_eq!(r.task_for_tid(101), None);
    assert_eq!(r.exclusion_candidate(mm, 0), Err(LifecycleError::NotHeld));
    r.observe_exit(parent, 5, ExitStatus::Code(7)).unwrap();
    assert_eq!(
        r.exclusion_candidate(mm, 0),
        Err(LifecycleError::NoLiveTasks)
    );
}
