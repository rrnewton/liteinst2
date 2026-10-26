//! Pure event-ledger regressions. These inputs are authenticated by a caller;
//! this suite does not establish native exclusion, signal provenance, or reaping.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use liteinst_admission::entries::ResumeKind;
use liteinst_launch::lifecycle::*;

const PC: u64 = 0x400000;
const THREAD_FLAGS: u64 = 0x50f00;

fn next(r: &LifecycleRegistry, task: TaskId) -> u64 {
    r.task(task).unwrap().sequence + 1
}

fn resume(r: &mut LifecycleRegistry, task: TaskId) {
    r.resume(task, r.task(task).unwrap().sequence).unwrap();
}

fn enter(r: &mut LifecycleRegistry, task: TaskId) {
    resume(r, task);
    r.observe_stop(task, next(r, task), PC + 2, HoldReason::SyscallEntry)
        .unwrap();
}

fn unchanged<T: std::fmt::Debug>(
    r: &mut LifecycleRegistry,
    expected: LifecycleError,
    action: impl FnOnce(&mut LifecycleRegistry) -> Result<T, LifecycleError>,
) {
    let before = r.snapshot();
    assert_eq!(action(r).unwrap_err(), expected);
    assert_eq!(r.snapshot(), before, "refusal changed the event ledger");
}

fn create(r: &mut LifecycleRegistry, parent: TaskId, thread: bool) -> TaskId {
    enter(r, parent);
    let request = if thread {
        CreationRequest::Clone {
            flags: THREAD_FLAGS,
        }
    } else {
        CreationRequest::Fork
    };
    let ticket = r.prepare_creation(parent, request).unwrap();
    resume(r, parent);
    let child = r
        .observe_creation(
            ticket,
            next(r, parent),
            CreationEvent {
                kind: if thread {
                    CreationEventKind::Clone
                } else {
                    CreationEventKind::Fork
                },
                child_tid: 101,
                child_tgid: if thread { 100 } else { 101 },
                parent_visible_tid: 101,
                parent_pc: PC + 2,
            },
        )
        .unwrap();
    r.observe_newborn_stop(child, 1, PC + 2).unwrap();
    resume(r, child);
    r.observe_stop(child, 2, PC + 2, HoldReason::SyscallExit)
        .unwrap();
    resume(r, parent);
    r.observe_creation_exit(ticket, next(r, parent), PC + 2, 101)
        .unwrap();
    child
}

fn initial(r: &LifecycleRegistry, origin: TaskOrigin, reason: HoldReason) {
    let root = r.root_task();
    let task = r.task(root).unwrap();
    assert_eq!(task.id, root);
    assert_eq!(task.tid, 100);
    assert_eq!(task.sequence, 0);
    assert_eq!(task.origin, origin);
    assert_eq!(task.state, TaskState::Held { pc: PC, reason });
    assert_eq!(r.task_for_tid(100), Some(root));
    let mm = r.address_space(task.address_space).unwrap();
    assert_eq!(mm.id, task.address_space);
    assert_eq!(mm.generation, 0);
    assert!(!mm.poisoned);
    assert_eq!(mm.origin, AddressSpaceOrigin::Initial);
    let snapshot = r.snapshot();
    assert_eq!(snapshot.tasks().collect::<Vec<_>>(), [task]);
    assert_eq!(snapshot.address_spaces().collect::<Vec<_>>(), [mm]);
    assert_eq!(r.obligations().count(), 0);
    let candidate = r.exclusion_candidate(mm.id, 0).unwrap();
    assert_eq!(candidate.tasks, [root]);
    assert_eq!(candidate.address_space, mm.id);
    assert_eq!(candidate.generation, 0);
    assert!(candidate.obligations.is_empty());
}

#[test]
fn initial_exec_exit_and_first_user_constructors_keep_distinct_origins() {
    let first_user = LifecycleRegistry::new(Limits::default(), 100, PC).unwrap();
    let syscall_exit =
        LifecycleRegistry::new_after_exec_syscall_exit(Limits::default(), 100, PC).unwrap();
    initial(&first_user, TaskOrigin::Initial, HoldReason::Exec);
    initial(
        &syscall_exit,
        TaskOrigin::InitialExecSyscallExit,
        HoldReason::ExecSyscallExit,
    );
    let first = first_user.task(first_user.root_task()).unwrap();
    let exit = syscall_exit.task(syscall_exit.root_task()).unwrap();
    assert_ne!(first.id, exit.id);
    assert_ne!(first.process, exit.process);
    assert_ne!(first.address_space, exit.address_space);
    assert_eq!(
        first_user.task(exit.id),
        Err(LifecycleError::UnknownIdentity)
    );
    assert_eq!(
        syscall_exit.address_space(first.address_space),
        Err(LifecycleError::UnknownIdentity)
    );
}

#[test]
fn exec_exit_starts_a_closed_syscall_phase_and_preserves_interrupt_ordering() {
    let mut r = LifecycleRegistry::new_after_exec_syscall_exit(Limits::default(), 100, PC).unwrap();
    let task = r.root_task();
    let identity = r.task(task).unwrap().clone();
    resume(&mut r, task);
    unchanged(&mut r, LifecycleError::EventMismatch, |r| {
        r.observe_stop(task, 1, PC, HoldReason::SyscallExit)
    });
    r.observe_stop(task, 1, PC + 2, HoldReason::SyscallEntry)
        .unwrap();
    resume(&mut r, task);
    r.observe_stop(task, 2, PC + 2, HoldReason::Interrupt)
        .unwrap();
    resume(&mut r, task);
    unchanged(&mut r, LifecycleError::EventMismatch, |r| {
        r.observe_stop(task, 3, PC + 2, HoldReason::SyscallEntry)
    });
    r.observe_stop(task, 3, PC + 2, HoldReason::SyscallExit)
        .unwrap();
    resume(&mut r, task);
    unchanged(&mut r, LifecycleError::Stale, |r| {
        r.observe_stop(task, 3, PC + 4, HoldReason::SyscallEntry)
    });
    unchanged(&mut r, LifecycleError::EventMismatch, |r| {
        r.observe_stop(task, 4, PC + 2, HoldReason::SyscallExit)
    });
    r.observe_stop(task, 4, PC + 4, HoldReason::SyscallEntry)
        .unwrap();
    let after = r.task(task).unwrap();
    assert_eq!(after.id, identity.id);
    assert_eq!(after.process, identity.process);
    assert_eq!(after.address_space, identity.address_space);
    assert_eq!(after.origin, TaskOrigin::InitialExecSyscallExit);
    assert_eq!(after.sequence, 4);
    assert_eq!(r.address_space(after.address_space).unwrap().generation, 0);
}

#[test]
fn neither_exec_origin_can_be_fabricated_as_an_ordinary_stop() {
    for at_syscall_exit in [false, true] {
        let mut r = if at_syscall_exit {
            LifecycleRegistry::new_after_exec_syscall_exit(Limits::default(), 100, PC)
        } else {
            LifecycleRegistry::new(Limits::default(), 100, PC)
        }
        .unwrap();
        let task = r.root_task();
        resume(&mut r, task);
        for reason in [HoldReason::Exec, HoldReason::ExecSyscallExit] {
            unchanged(&mut r, LifecycleError::EventMismatch, |r| {
                r.observe_stop(task, 1, PC, reason)
            });
        }
        r.observe_stop(task, 1, PC, HoldReason::Interrupt).unwrap();
        assert_eq!(r.task(task).unwrap().sequence, 1);
    }
}

#[test]
fn invalid_constructor_limits_and_tids_cannot_create_a_registry() {
    for at_syscall_exit in [false, true] {
        let construct = |limits, tid| {
            if at_syscall_exit {
                LifecycleRegistry::new_after_exec_syscall_exit(limits, tid, PC)
            } else {
                LifecycleRegistry::new(limits, tid, PC)
            }
        };
        for (field, upper) in [(0, 65_536), (1, 65_536), (2, 65_536), (3, 1_048_576)] {
            for invalid in [0, upper + 1] {
                let mut limits = Limits::default();
                match field {
                    0 => limits.tasks = invalid,
                    1 => limits.processes = invalid,
                    2 => limits.address_spaces = invalid,
                    3 => limits.obligations = invalid,
                    _ => unreachable!(),
                }
                assert_eq!(
                    construct(limits, 100).err(),
                    Some(LifecycleError::InvalidLimits)
                );
            }
        }
        for tid in [0, -1, i32::MIN] {
            assert_eq!(
                construct(Limits::default(), tid).err(),
                Some(LifecycleError::InvalidTid)
            );
        }
        let r = construct(
            Limits {
                tasks: 1,
                processes: 1,
                address_spaces: 1,
                obligations: 1,
            },
            100,
        )
        .unwrap();
        initial(
            &r,
            if at_syscall_exit {
                TaskOrigin::InitialExecSyscallExit
            } else {
                TaskOrigin::Initial
            },
            if at_syscall_exit {
                HoldReason::ExecSyscallExit
            } else {
                HoldReason::Exec
            },
        );
    }
}

#[test]
fn unknown_other_thread_signal_survives_exec_without_becoming_classified() {
    let mut r = LifecycleRegistry::new_after_exec_syscall_exit(Limits::default(), 100, PC).unwrap();
    let leader = r.root_task();
    let sibling = create(&mut r, leader, true);
    let old_mm = r.task(leader).unwrap().address_space;
    let old_process = r.task(leader).unwrap().process;
    let unknown_kind = ObligationKind::PendingSignal {
        signal: 10,
        code: -6,
        scope: SignalScope::Unknown,
    };
    let unknown = r.record_obligation(leader, unknown_kind).unwrap();
    let other_task = r
        .record_obligation(
            leader,
            ObligationKind::PendingSignal {
                signal: 12,
                code: -6,
                scope: SignalScope::Task,
            },
        )
        .unwrap();
    let execing_task = r
        .record_obligation(
            sibling,
            ObligationKind::PendingSignal {
                signal: 13,
                code: -6,
                scope: SignalScope::Task,
            },
        )
        .unwrap();
    let originals = r.obligations().cloned().collect::<Vec<_>>();
    enter(&mut r, sibling);
    let ticket = r.prepare_exec(sibling).unwrap();
    resume(&mut r, sibling);
    let transition = r
        .observe_exec(ticket, next(&r, sibling), 101, 100, PC)
        .unwrap();
    assert_eq!(transition.superseded, [leader, sibling]);
    assert_eq!(r.task(transition.task).unwrap().process, old_process);
    assert_ne!(transition.address_space, old_mm);
    let inherited = r
        .obligations()
        .filter(|record| record.address_space == transition.address_space)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(inherited.len(), 2);
    let copied_unknown = inherited
        .iter()
        .find(|record| record.inherited_from == Some(unknown))
        .unwrap();
    assert_ne!(copied_unknown.id, unknown);
    assert_eq!(copied_unknown.task, transition.task);
    assert_eq!(copied_unknown.kind, unknown_kind);
    assert_eq!(
        inherited
            .iter()
            .filter(|record| record.inherited_from == Some(execing_task))
            .count(),
        1
    );
    assert!(
        !inherited
            .iter()
            .any(|record| record.inherited_from == Some(other_task))
    );
    assert_eq!(
        r.obligations()
            .filter(|record| record.address_space == old_mm)
            .cloned()
            .collect::<Vec<_>>(),
        originals
    );
    assert_eq!(r.obligations().count(), 5);
}

#[test]
fn fork_does_not_copy_unknown_signal_queues_but_retains_saved_resume_provenance() {
    let mut r = LifecycleRegistry::new_after_exec_syscall_exit(Limits::default(), 100, PC).unwrap();
    let parent = r.root_task();
    let parent_mm = r.task(parent).unwrap().address_space;
    let signal = r
        .record_obligation(
            parent,
            ObligationKind::PendingSignal {
                signal: 10,
                code: -1,
                scope: SignalScope::Unknown,
            },
        )
        .unwrap();
    let saved_kind = ObligationKind::SavedResume {
        pc: PC + 64,
        kind: ResumeKind::SignalFrame,
    };
    let saved = r.record_obligation(parent, saved_kind).unwrap();
    let originals = r.obligations().cloned().collect::<Vec<_>>();
    let child = create(&mut r, parent, false);
    let child_mm = r.task(child).unwrap().address_space;
    let inherited = r
        .obligations()
        .filter(|record| record.address_space == child_mm)
        .collect::<Vec<_>>();
    assert_eq!(inherited.len(), 1);
    assert_eq!(inherited[0].kind, saved_kind);
    assert_eq!(inherited[0].inherited_from, Some(saved));
    assert_ne!(inherited[0].id, saved);
    assert_eq!(inherited[0].task, child);
    assert!(
        !r.obligations()
            .any(|record| record.inherited_from == Some(signal))
    );
    assert_eq!(
        r.obligations()
            .filter(|record| record.address_space == parent_mm)
            .cloned()
            .collect::<Vec<_>>(),
        originals
    );
}

#[test]
fn terminal_tasks_processes_and_mms_still_consume_lifetime_limits() {
    for bounded_record in 0..3 {
        let mut limits = Limits::default();
        match bounded_record {
            0 => limits.tasks = 2,
            1 => limits.processes = 2,
            2 => limits.address_spaces = 2,
            _ => unreachable!(),
        }
        let mut r = LifecycleRegistry::new_after_exec_syscall_exit(limits, 100, PC).unwrap();
        let parent = r.root_task();
        let child = create(&mut r, parent, false);
        r.observe_exit(child, 3, ExitStatus::Code(23)).unwrap();
        assert_eq!(r.task_for_tid(101), None);
        assert_eq!(
            r.task(child).unwrap().state,
            TaskState::Terminal(TerminalReason::Exit(ExitStatus::Code(23)))
        );
        enter(&mut r, parent);
        let ticket = r.prepare_creation(parent, CreationRequest::Fork).unwrap();
        resume(&mut r, parent);
        unchanged(&mut r, LifecycleError::Exhausted, |r| {
            r.observe_creation(
                ticket,
                next(r, parent),
                CreationEvent {
                    kind: CreationEventKind::Fork,
                    child_tid: 101,
                    child_tgid: 101,
                    parent_visible_tid: 101,
                    parent_pc: PC + 2,
                },
            )
        });
        assert_eq!(r.task_for_tid(101), None);
        assert_eq!(r.snapshot().tasks().count(), 2);
        assert_eq!(r.snapshot().address_spaces().count(), 2);
    }
}

// The two dedicated newborn methods describe different authenticated kernel
// phases. A late automatic stop must not invent a second syscall-exit event.
fn newborn_before_observation() -> (LifecycleRegistry, TaskId, TaskId, CreationTicket) {
    let mut r = LifecycleRegistry::new_after_exec_syscall_exit(Limits::default(), 100, PC).unwrap();
    let parent = r.root_task();
    enter(&mut r, parent);
    let ticket = r.prepare_creation(parent, CreationRequest::Fork).unwrap();
    resume(&mut r, parent);
    let child = r
        .observe_creation(
            ticket,
            next(&r, parent),
            CreationEvent {
                kind: CreationEventKind::Fork,
                child_tid: 101,
                child_tgid: 101,
                parent_visible_tid: 101,
                parent_pc: PC + 2,
            },
        )
        .unwrap();
    assert_eq!(r.task(child).unwrap().state, TaskState::Newborn);
    (r, parent, child, ticket)
}

#[test]
fn newborn_return_ready_has_its_own_phase_and_preserves_creation_identity() {
    let (mut r, parent, child, ticket) = newborn_before_observation();
    let before = r.task(child).unwrap().clone();
    assert_eq!(before.sequence, 0);
    assert_eq!(
        before.origin,
        TaskOrigin::Created {
            parent,
            request: CreationRequest::Fork
        }
    );
    r.observe_newborn_return_ready(child, 1, PC + 2).unwrap();
    let after = r.task(child).unwrap();
    assert_eq!(after.id, before.id);
    assert_eq!(after.tid, before.tid);
    assert_eq!(after.process, before.process);
    assert_eq!(after.address_space, before.address_space);
    assert_eq!(after.origin, before.origin);
    assert_eq!(after.sequence, 1);
    assert_eq!(
        after.state,
        TaskState::Held {
            pc: PC + 2,
            reason: HoldReason::NewbornReturnReady
        }
    );
    let mm = r.address_space(after.address_space).unwrap();
    assert_eq!(mm.generation, 0);
    assert_eq!(
        mm.origin,
        AddressSpaceOrigin::Fork {
            parent: r.task(parent).unwrap().address_space,
            generation: 0
        }
    );
    assert_eq!(r.task_for_tid(101), Some(child));
    assert_eq!(r.snapshot().tasks().count(), 2);
    assert_eq!(r.snapshot().address_spaces().count(), 2);

    // The child phase does not consume or synthesize its parent's real exit.
    resume(&mut r, parent);
    r.observe_creation_exit(ticket, next(&r, parent), PC + 2, 101)
        .unwrap();
    assert_eq!(
        r.task(parent).unwrap().state,
        TaskState::Held {
            pc: PC + 2,
            reason: HoldReason::SyscallExit
        }
    );
    assert_eq!(
        r.task(child).unwrap().state,
        TaskState::Held {
            pc: PC + 2,
            reason: HoldReason::NewbornReturnReady
        }
    );
}

#[test]
fn late_newborn_rejects_fabricated_exit_and_accepts_the_next_real_syscall_entry() {
    let (mut r, _, child, _) = newborn_before_observation();
    r.observe_newborn_return_ready(child, 1, PC + 2).unwrap();
    let origin = r.task(child).unwrap().origin;
    resume(&mut r, child);
    unchanged(&mut r, LifecycleError::EventMismatch, |r| {
        r.observe_stop(child, 2, PC + 2, HoldReason::SyscallExit)
    });
    unchanged(&mut r, LifecycleError::Stale, |r| {
        r.observe_stop(child, 3, PC + 4, HoldReason::SyscallEntry)
    });
    r.observe_stop(child, 2, PC + 4, HoldReason::SyscallEntry)
        .unwrap();
    resume(&mut r, child);
    unchanged(&mut r, LifecycleError::EventMismatch, |r| {
        r.observe_stop(child, 3, PC + 4, HoldReason::SyscallEntry)
    });
    r.observe_stop(child, 3, PC + 4, HoldReason::SyscallExit)
        .unwrap();
    assert_eq!(r.task(child).unwrap().sequence, 3);
    assert_eq!(r.task(child).unwrap().origin, origin);
    assert_eq!(
        r.task(child).unwrap().state,
        TaskState::Held {
            pc: PC + 4,
            reason: HoldReason::SyscallExit
        }
    );

    // Preserve the existing, explicitly earlier newborn phase and its required
    // EXIT. Supporting a later stop must not silently reinterpret this API.
    let (mut earlier, _, early_child, _) = newborn_before_observation();
    earlier
        .observe_newborn_stop(early_child, 1, PC + 2)
        .unwrap();
    assert_eq!(
        earlier.task(early_child).unwrap().state,
        TaskState::Held {
            pc: PC + 2,
            reason: HoldReason::Newborn
        }
    );
    resume(&mut earlier, early_child);
    unchanged(&mut earlier, LifecycleError::EventMismatch, |r| {
        r.observe_stop(early_child, 2, PC + 4, HoldReason::SyscallEntry)
    });
    earlier
        .observe_stop(early_child, 2, PC + 2, HoldReason::SyscallExit)
        .unwrap();
    resume(&mut earlier, early_child);
    earlier
        .observe_stop(early_child, 3, PC + 4, HoldReason::SyscallEntry)
        .unwrap();
}

#[test]
fn newborn_return_ready_rejects_stale_foreign_and_duplicate_transitions_atomically() {
    let (mut r, parent, child, _) = newborn_before_observation();
    for sequence in [0, 2, u64::MAX] {
        unchanged(&mut r, LifecycleError::Stale, |r| {
            r.observe_newborn_return_ready(child, sequence, PC + 2)
        });
    }
    unchanged(&mut r, LifecycleError::WrongState, |r| {
        r.observe_newborn_return_ready(parent, next(r, parent), PC + 2)
    });
    let (_, _, foreign, _) = newborn_before_observation();
    unchanged(&mut r, LifecycleError::UnknownIdentity, |r| {
        r.observe_newborn_return_ready(foreign, 1, PC + 2)
    });
    r.observe_newborn_return_ready(child, 1, PC + 2).unwrap();
    unchanged(&mut r, LifecycleError::WrongState, |r| {
        r.observe_newborn_return_ready(child, 2, PC + 2)
    });
    unchanged(&mut r, LifecycleError::WrongState, |r| {
        r.observe_newborn_stop(child, 2, PC + 2)
    });

    let (mut earlier, _, child, _) = newborn_before_observation();
    earlier.observe_newborn_stop(child, 1, PC + 2).unwrap();
    unchanged(&mut earlier, LifecycleError::WrongState, |r| {
        r.observe_newborn_return_ready(child, 2, PC + 2)
    });
}

#[test]
fn ordinary_stop_cannot_fabricate_newborn_return_ready() {
    let (mut r, parent, child, ticket) = newborn_before_observation();
    r.observe_newborn_return_ready(child, 1, PC + 2).unwrap();
    resume(&mut r, child);
    unchanged(&mut r, LifecycleError::EventMismatch, |r| {
        r.observe_stop(child, 2, PC + 2, HoldReason::NewbornReturnReady)
    });
    r.observe_stop(child, 2, PC + 2, HoldReason::Interrupt)
        .unwrap();
    assert_eq!(r.task(child).unwrap().sequence, 2);

    resume(&mut r, parent);
    r.observe_creation_exit(ticket, next(&r, parent), PC + 2, 101)
        .unwrap();
    resume(&mut r, parent);
    unchanged(&mut r, LifecycleError::EventMismatch, |r| {
        r.observe_stop(
            parent,
            next(r, parent),
            PC + 2,
            HoldReason::NewbornReturnReady,
        )
    });
    r.observe_stop(parent, next(&r, parent), PC + 4, HoldReason::SyscallEntry)
        .unwrap();
}
