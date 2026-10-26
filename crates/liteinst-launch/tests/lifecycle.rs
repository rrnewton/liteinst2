//! Pure lifecycle invariants; none of these tests claims native exclusion.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use liteinst_admission::entries::ResumeKind;
use liteinst_launch::lifecycle::*;

const PC: u64 = 0x400000;
const THREAD_FLAGS: u64 = 0x50f00;

fn registry() -> LifecycleRegistry {
    LifecycleRegistry::new(Limits::default(), 100, PC).unwrap()
}

fn sequence(registry: &LifecycleRegistry, task: TaskId) -> u64 {
    registry.task(task).unwrap().sequence + 1
}

fn resume(registry: &mut LifecycleRegistry, task: TaskId) {
    let previous = registry.task(task).unwrap().sequence;
    registry.resume(task, previous).unwrap();
}

fn enter_syscall(registry: &mut LifecycleRegistry, task: TaskId) {
    resume(registry, task);
    registry
        .observe_stop(task, sequence(registry, task), PC, HoldReason::SyscallEntry)
        .unwrap();
}

fn child_return(registry: &mut LifecycleRegistry, task: TaskId) {
    registry.observe_newborn_stop(task, 1, PC + 2).unwrap();
    resume(registry, task);
    registry
        .observe_stop(task, 2, PC + 2, HoldReason::SyscallExit)
        .unwrap();
}

fn creation(
    registry: &mut LifecycleRegistry,
    parent: TaskId,
    request: CreationRequest,
    kind: CreationEventKind,
    child_tid: i32,
    child_tgid: i32,
) -> (CreationTicket, TaskId) {
    enter_syscall(registry, parent);
    let ticket = registry.prepare_creation(parent, request).unwrap();
    resume(registry, parent);
    let child = registry
        .observe_creation(
            ticket,
            sequence(registry, parent),
            CreationEvent {
                kind,
                child_tid,
                child_tgid,
                parent_visible_tid: child_tid,
                parent_pc: PC + 2,
            },
        )
        .unwrap();
    (ticket, child)
}

fn creation_return(
    registry: &mut LifecycleRegistry,
    parent: TaskId,
    ticket: CreationTicket,
    child_tid: i32,
) {
    resume(registry, parent);
    registry
        .observe_creation_exit(
            ticket,
            sequence(registry, parent),
            PC + 2,
            i64::from(child_tid),
        )
        .unwrap();
}

fn unchanged<T: std::fmt::Debug>(
    registry: &mut LifecycleRegistry,
    expected: LifecycleError,
    action: impl FnOnce(&mut LifecycleRegistry) -> Result<T, LifecycleError>,
) {
    let before = registry.snapshot();
    assert_eq!(action(registry).unwrap_err(), expected);
    assert_eq!(
        registry.snapshot(),
        before,
        "refusal mutated registry state"
    );
}

#[test]
fn thread_creation_requires_newborn_stop_and_collective_hold() {
    let mut r = registry();
    let parent = r.root_task();
    let mm = r.task(parent).unwrap().address_space;
    let before = r.exclusion_candidate(mm, 0).unwrap();
    let (ticket, child) = creation(
        &mut r,
        parent,
        CreationRequest::Clone {
            flags: THREAD_FLAGS,
        },
        CreationEventKind::Clone,
        101,
        100,
    );
    assert_eq!(r.task(child).unwrap().address_space, mm);
    assert_eq!(
        r.task(child).unwrap().process,
        r.task(parent).unwrap().process
    );
    assert_eq!(r.task(child).unwrap().state, TaskState::Newborn);
    assert_eq!(
        r.exclusion_candidate(mm, 0).unwrap_err(),
        LifecycleError::NotHeld
    );
    assert_eq!(r.validate_candidate(&before), Err(LifecycleError::Stale));
    unchanged(&mut r, LifecycleError::WrongState, |r| r.resume(child, 0));
    child_return(&mut r, child);
    creation_return(&mut r, parent, ticket, 101);
    assert_eq!(r.exclusion_candidate(mm, 0).unwrap().tasks, [parent, child]);
    assert_eq!(
        r.task(child).unwrap().origin,
        TaskOrigin::Created {
            parent,
            request: CreationRequest::Clone {
                flags: THREAD_FLAGS
            }
        }
    );
    resume(&mut r, child);
    assert_eq!(
        r.exclusion_candidate(mm, 0).unwrap_err(),
        LifecycleError::NotHeld
    );
    r.observe_stop(child, 3, PC + 2, HoldReason::Interrupt)
        .unwrap();
    assert_eq!(r.exclusion_candidate(mm, 0).unwrap().tasks.len(), 2);
}

#[test]
fn clone_vm_without_clone_thread_still_joins_the_same_mm_exclusion() {
    let mut r = registry();
    let parent = r.root_task();
    let mm = r.task(parent).unwrap().address_space;
    let (ticket, child) = creation(
        &mut r,
        parent,
        CreationRequest::Clone3 {
            flags: 0x100,
            exit_signal: 0,
        },
        CreationEventKind::Clone,
        101,
        101,
    );
    assert_ne!(
        r.task(child).unwrap().process,
        r.task(parent).unwrap().process
    );
    assert_eq!(r.task(child).unwrap().address_space, mm);
    child_return(&mut r, child);
    creation_return(&mut r, parent, ticket, 101);
    assert_eq!(r.exclusion_candidate(mm, 0).unwrap().tasks, [parent, child]);
}

#[test]
fn fork_copies_saved_resumes_and_source_generation_but_not_pending_signals() {
    let mut r = registry();
    let parent = r.root_task();
    let mm = r.task(parent).unwrap().address_space;
    let obligation = r
        .record_obligation(
            parent,
            ObligationKind::SavedResume {
                pc: PC + 4096,
                kind: ResumeKind::SignalFrame,
            },
        )
        .unwrap();
    r.record_obligation(
        parent,
        ObligationKind::PendingSignal {
            signal: 10,
            code: 0,
            scope: SignalScope::Process,
        },
    )
    .unwrap();
    let candidate = r.exclusion_candidate(mm, 0).unwrap();
    let invalidation = r.begin_invalidation(&candidate).unwrap();
    r.finish_invalidation(&invalidation).unwrap();
    let (ticket, child) = creation(
        &mut r,
        parent,
        CreationRequest::Fork,
        CreationEventKind::Fork,
        101,
        101,
    );
    let child_mm = r.task(child).unwrap().address_space;
    assert_ne!(child_mm, mm);
    assert_ne!(
        r.task(child).unwrap().process,
        r.task(parent).unwrap().process
    );
    assert_eq!(
        r.address_space(child_mm).unwrap().origin,
        AddressSpaceOrigin::Fork {
            parent: mm,
            generation: 1
        }
    );
    let copied: Vec<_> = r
        .obligations()
        .filter(|o| o.address_space == child_mm)
        .collect();
    assert_eq!(copied.len(), 1);
    assert_eq!(copied[0].inherited_from, Some(obligation));
    assert_eq!(
        copied[0].kind,
        ObligationKind::SavedResume {
            pc: PC + 4096,
            kind: ResumeKind::SignalFrame
        }
    );
    assert_eq!(r.obligations().filter(|o| o.address_space == mm).count(), 2);
    child_return(&mut r, child);
    creation_return(&mut r, parent, ticket, 101);
    assert_eq!(r.exclusion_candidate(child_mm, 0).unwrap().tasks, [child]);
}

#[test]
fn vfork_parent_stays_held_until_child_exec_and_exact_done_event() {
    let mut r = registry();
    let parent = r.root_task();
    let mm = r.task(parent).unwrap().address_space;
    let (ticket, child) = creation(
        &mut r,
        parent,
        CreationRequest::Vfork,
        CreationEventKind::Vfork,
        101,
        101,
    );
    child_return(&mut r, child);
    assert_eq!(r.task(child).unwrap().address_space, mm);
    let parent_sequence = r.task(parent).unwrap().sequence;
    unchanged(&mut r, LifecycleError::VforkBlocked, |r| {
        r.resume(parent, parent_sequence)
    });
    enter_syscall(&mut r, child);
    let exec = r.prepare_exec(child).unwrap();
    resume(&mut r, child);
    let transition = r
        .observe_exec(exec, sequence(&r, child), 101, 101, PC + 8192)
        .unwrap();
    assert_ne!(transition.address_space, mm);
    assert_eq!(transition.superseded, [child]);
    resume(&mut r, parent);
    unchanged(&mut r, LifecycleError::EventMismatch, |r| {
        r.observe_creation_exit(ticket, sequence(r, parent), PC + 2, 101)
    });
    r.observe_vfork_done(ticket, sequence(&r, parent), child, PC + 2)
        .unwrap();
    creation_return(&mut r, parent, ticket, 101);
    assert_eq!(r.exclusion_candidate(mm, 0).unwrap().tasks, [parent]);
}

#[test]
fn nonleader_exec_mints_new_identity_and_preserves_the_right_signal_queues() {
    let mut r = registry();
    let parent = r.root_task();
    let old_mm = r.task(parent).unwrap().address_space;
    let old_process = r.task(parent).unwrap().process;
    let (ticket, child) = creation(
        &mut r,
        parent,
        CreationRequest::Clone {
            flags: THREAD_FLAGS,
        },
        CreationEventKind::Clone,
        101,
        100,
    );
    child_return(&mut r, child);
    creation_return(&mut r, parent, ticket, 101);
    r.record_obligation(
        parent,
        ObligationKind::PendingSignal {
            signal: 10,
            code: 0,
            scope: SignalScope::Process,
        },
    )
    .unwrap();
    r.record_obligation(
        parent,
        ObligationKind::PendingSignal {
            signal: 12,
            code: 0,
            scope: SignalScope::Task,
        },
    )
    .unwrap();
    r.record_obligation(
        child,
        ObligationKind::PendingSignal {
            signal: 13,
            code: 0,
            scope: SignalScope::Task,
        },
    )
    .unwrap();
    r.record_obligation(
        child,
        ObligationKind::SavedResume {
            pc: PC + 64,
            kind: ResumeKind::NonlocalJump,
        },
    )
    .unwrap();
    enter_syscall(&mut r, child);
    let exec = r.prepare_exec(child).unwrap();
    resume(&mut r, child);
    unchanged(&mut r, LifecycleError::EventMismatch, |r| {
        r.observe_exec(exec, sequence(r, child), 100, 100, PC)
    });
    let transition = r
        .observe_exec(exec, sequence(&r, child), 101, 100, PC)
        .unwrap();
    assert_ne!(transition.task, parent);
    assert_ne!(transition.task, child);
    assert_ne!(transition.address_space, old_mm);
    assert_eq!(transition.superseded, [parent, child]);
    assert_eq!(r.task_for_tid(100), Some(transition.task));
    assert_eq!(r.task_for_tid(101), None);
    assert_eq!(r.task(transition.task).unwrap().process, old_process);
    assert_eq!(
        r.task(child).unwrap().state,
        TaskState::Terminal(TerminalReason::ExecReplaced)
    );
    assert_eq!(
        r.obligations()
            .filter(|o| o.address_space == old_mm)
            .count(),
        4
    );
    let new_signals: Vec<_> = r
        .obligations()
        .filter(|o| o.address_space == transition.address_space)
        .map(|o| o.kind)
        .collect();
    assert_eq!(
        new_signals,
        [
            ObligationKind::PendingSignal {
                signal: 10,
                code: 0,
                scope: SignalScope::Process
            },
            ObligationKind::PendingSignal {
                signal: 13,
                code: 0,
                scope: SignalScope::Task
            }
        ]
    );

    // A second exec copies only the current queues, not all historical copies.
    let task = transition.task;
    resume(&mut r, task);
    r.observe_stop(task, 1, PC, HoldReason::SyscallExit)
        .unwrap();
    enter_syscall(&mut r, task);
    let exec = r.prepare_exec(task).unwrap();
    resume(&mut r, task);
    let again = r
        .observe_exec(exec, sequence(&r, task), 100, 100, PC)
        .unwrap();
    assert_eq!(
        r.obligations()
            .filter(|o| o.address_space == again.address_space)
            .count(),
        2
    );
    assert_eq!(r.obligations().count(), 8);
}

#[test]
fn failed_exec_retains_the_original_mm_and_saved_contexts() {
    let mut r = registry();
    let task = r.root_task();
    let mm = r.task(task).unwrap().address_space;
    r.record_obligation(
        task,
        ObligationKind::SavedResume {
            pc: PC + 8,
            kind: ResumeKind::SyscallReturn,
        },
    )
    .unwrap();
    enter_syscall(&mut r, task);
    let ticket = r.prepare_exec(task).unwrap();
    resume(&mut r, task);
    unchanged(&mut r, LifecycleError::EventMismatch, |r| {
        r.observe_exec_failure(ticket, sequence(r, task), PC, 0)
    });
    r.observe_exec_failure(ticket, sequence(&r, task), PC, -2)
        .unwrap();
    assert_eq!(r.task(task).unwrap().address_space, mm);
    assert_eq!(r.task_for_tid(100), Some(task));
    assert_eq!(r.obligations().count(), 1);
}

#[test]
fn signals_are_retained_atomically_and_generic_signal_relabeling_refuses() {
    let mut r = registry();
    let task = r.root_task();
    let mm = r.task(task).unwrap().address_space;
    resume(&mut r, task);
    unchanged(&mut r, LifecycleError::EventMismatch, |r| {
        r.observe_stop(task, 1, PC, HoldReason::Signal)
    });
    unchanged(&mut r, LifecycleError::InvalidObligation, |r| {
        r.observe_signal(
            task,
            1,
            SignalEvent {
                pc: PC,
                signal: 0,
                code: 0,
                scope: SignalScope::Task,
            },
        )
    });
    let signal = r
        .observe_signal(
            task,
            1,
            SignalEvent {
                pc: PC,
                signal: 10,
                code: -6,
                scope: SignalScope::Task,
            },
        )
        .unwrap();
    r.record_obligation(
        task,
        ObligationKind::SavedResume {
            pc: PC,
            kind: ResumeKind::SignalFrame,
        },
    )
    .unwrap();
    let candidate = r.exclusion_candidate(mm, 0).unwrap();
    assert_eq!(candidate.obligations.len(), 2);
    assert!(
        candidate
            .obligations
            .iter()
            .any(|record| record.id == signal)
    );
    resume(&mut r, task);
    r.observe_stop(task, 2, PC, HoldReason::Interrupt).unwrap();
    assert_eq!(r.exclusion_candidate(mm, 0).unwrap().obligations.len(), 2);
}

#[test]
fn tid_reuse_never_reanimates_an_old_task_or_process_identity() {
    let mut r = registry();
    let parent = r.root_task();
    let (ticket, old) = creation(
        &mut r,
        parent,
        CreationRequest::Fork,
        CreationEventKind::Fork,
        101,
        101,
    );
    child_return(&mut r, old);
    creation_return(&mut r, parent, ticket, 101);
    let old_process = r.task(old).unwrap().process;
    r.observe_exit(old, 3, ExitStatus::Code(0)).unwrap();
    unchanged(&mut r, LifecycleError::WrongState, |r| {
        r.observe_exit(old, 4, ExitStatus::Code(0))
    });
    let (_, new) = creation(
        &mut r,
        parent,
        CreationRequest::Fork,
        CreationEventKind::Fork,
        101,
        101,
    );
    assert_ne!(new, old);
    assert_ne!(r.task(new).unwrap().process, old_process);
    assert_eq!(r.task_for_tid(101), Some(new));
    unchanged(&mut r, LifecycleError::WrongState, |r| r.resume(old, 3));
    assert_eq!(r.task_for_tid(101), Some(new));
}

#[test]
fn creation_event_kind_sequence_and_parent_return_are_exact() {
    let mut r = registry();
    let parent = r.root_task();
    enter_syscall(&mut r, parent);
    let ticket = r.prepare_creation(parent, CreationRequest::Fork).unwrap();
    resume(&mut r, parent);
    let mut event = CreationEvent {
        kind: CreationEventKind::Clone,
        child_tid: 101,
        child_tgid: 101,
        parent_visible_tid: 7,
        parent_pc: PC,
    };
    unchanged(&mut r, LifecycleError::EventMismatch, |r| {
        r.observe_creation(ticket, 2, event)
    });
    event.kind = CreationEventKind::Fork;
    unchanged(&mut r, LifecycleError::Stale, |r| {
        r.observe_creation(ticket, 3, event)
    });
    let child = r.observe_creation(ticket, 2, event).unwrap();
    unchanged(&mut r, LifecycleError::WrongState, |r| {
        r.observe_creation(ticket, 3, event)
    });
    child_return(&mut r, child);
    resume(&mut r, parent);
    unchanged(&mut r, LifecycleError::EventMismatch, |r| {
        r.observe_creation_exit(ticket, 3, PC, 101)
    });
    r.observe_creation_exit(ticket, 3, PC, 7).unwrap();
}

#[test]
fn failed_creation_has_no_child_and_cannot_be_promoted_to_success() {
    let mut r = registry();
    let parent = r.root_task();
    enter_syscall(&mut r, parent);
    let ticket = r.prepare_creation(parent, CreationRequest::Fork).unwrap();
    resume(&mut r, parent);
    unchanged(&mut r, LifecycleError::EventMismatch, |r| {
        r.observe_creation_exit(ticket, 2, PC, 101)
    });
    r.observe_creation_exit(ticket, 2, PC, -11).unwrap();
    assert_eq!(r.task_for_tid(101), None);
    assert_eq!(
        r.exclusion_candidate(r.task(parent).unwrap().address_space, 0)
            .unwrap()
            .tasks,
        [parent]
    );
}

#[test]
fn unknown_flags_foreign_ids_and_out_of_order_syscalls_refuse_unchanged() {
    let mut r = registry();
    let other = registry();
    let task = r.root_task();
    unchanged(&mut r, LifecycleError::UnknownIdentity, |r| {
        r.resume(other.root_task(), 0)
    });
    resume(&mut r, task);
    unchanged(&mut r, LifecycleError::EventMismatch, |r| {
        r.observe_stop(task, 1, PC, HoldReason::SyscallExit)
    });
    r.observe_stop(task, 1, PC, HoldReason::SyscallEntry)
        .unwrap();
    for flags in [1 << 63, 0x800000, 0x10000, 0x800, 0x100000900] {
        unchanged(&mut r, LifecycleError::UnsupportedClone, |r| {
            r.prepare_creation(task, CreationRequest::Clone { flags })
        });
    }
    resume(&mut r, task);
    unchanged(&mut r, LifecycleError::EventMismatch, |r| {
        r.observe_stop(task, 2, PC, HoldReason::SyscallEntry)
    });
    unchanged(&mut r, LifecycleError::Stale, |r| {
        r.observe_stop(task, 1, PC, HoldReason::Interrupt)
    });
    r.observe_stop(task, 2, PC, HoldReason::SyscallExit)
        .unwrap();
}

#[test]
fn invalidation_advances_generation_blocks_resume_and_keeps_all_obligations() {
    let mut r = registry();
    let task = r.root_task();
    let mm = r.task(task).unwrap().address_space;
    r.record_obligation(
        task,
        ObligationKind::SavedResume {
            pc: PC + 8,
            kind: ResumeKind::NonlocalJump,
        },
    )
    .unwrap();
    let candidate = r.exclusion_candidate(mm, 0).unwrap();
    let ticket = r.begin_invalidation(&candidate).unwrap();
    assert_eq!(ticket.previous_generation, 0);
    assert_eq!(ticket.generation, 1);
    unchanged(&mut r, LifecycleError::Invalidating, |r| r.resume(task, 0));
    unchanged(&mut r, LifecycleError::Stale, |r| {
        r.begin_invalidation(&candidate)
    });
    r.finish_invalidation(&ticket).unwrap();
    unchanged(&mut r, LifecycleError::Stale, |r| {
        r.finish_invalidation(&ticket)
    });
    assert_eq!(
        r.exclusion_candidate(mm, 0).unwrap_err(),
        LifecycleError::Stale
    );
    assert_eq!(
        r.exclusion_candidate(mm, 1).unwrap().obligations,
        candidate.obligations
    );
}

#[test]
fn candidate_tampering_and_any_intervening_event_invalidate_it() {
    let mut r = registry();
    let task = r.root_task();
    let mm = r.task(task).unwrap().address_space;
    let candidate = r.exclusion_candidate(mm, 0).unwrap();
    let mut tampered = candidate.clone();
    tampered.tasks.clear();
    assert_eq!(r.validate_candidate(&tampered), Err(LifecycleError::Stale));
    r.record_obligation(
        task,
        ObligationKind::SavedResume {
            pc: PC + 4,
            kind: ResumeKind::ParkedThread,
        },
    )
    .unwrap();
    unchanged(&mut r, LifecycleError::Stale, |r| {
        r.begin_invalidation(&candidate)
    });
}

#[test]
fn poison_is_terminal_for_release_but_preserves_exit_and_context_accounting() {
    let mut r = registry();
    let task = r.root_task();
    let mm = r.task(task).unwrap().address_space;
    r.record_obligation(
        task,
        ObligationKind::SavedResume {
            pc: PC + 8,
            kind: ResumeKind::SyscallReturn,
        },
    )
    .unwrap();
    let ticket = r
        .begin_invalidation(&r.exclusion_candidate(mm, 0).unwrap())
        .unwrap();
    r.poison(mm).unwrap();
    unchanged(&mut r, LifecycleError::Poisoned, |r| {
        r.finish_invalidation(&ticket)
    });
    unchanged(&mut r, LifecycleError::Poisoned, |r| r.resume(task, 0));
    assert_eq!(
        r.exclusion_candidate(mm, 1).unwrap_err(),
        LifecycleError::Poisoned
    );
    r.observe_exit(task, 1, ExitStatus::Signal(9)).unwrap();
    assert_eq!(r.obligations().count(), 1);
}

#[test]
fn storage_exhaustion_rolls_back_ids_membership_and_inherited_obligations() {
    for limits in [
        Limits {
            tasks: 1,
            ..Limits::default()
        },
        Limits {
            processes: 1,
            ..Limits::default()
        },
        Limits {
            address_spaces: 1,
            ..Limits::default()
        },
        Limits {
            obligations: 1,
            ..Limits::default()
        },
    ] {
        let mut r = LifecycleRegistry::new(limits, 100, PC).unwrap();
        let task = r.root_task();
        r.record_obligation(
            task,
            ObligationKind::SavedResume {
                pc: PC + 2,
                kind: ResumeKind::SignalFrame,
            },
        )
        .unwrap();
        enter_syscall(&mut r, task);
        let ticket = r.prepare_creation(task, CreationRequest::Fork).unwrap();
        resume(&mut r, task);
        unchanged(&mut r, LifecycleError::Exhausted, |r| {
            r.observe_creation(
                ticket,
                2,
                CreationEvent {
                    kind: CreationEventKind::Fork,
                    child_tid: 101,
                    child_tgid: 101,
                    parent_visible_tid: 101,
                    parent_pc: PC,
                },
            )
        });
    }
}

#[test]
fn invalid_limits_signal_bounds_and_newborn_replay_are_rejected() {
    assert!(matches!(
        LifecycleRegistry::new(
            Limits {
                tasks: 0,
                ..Limits::default()
            },
            100,
            PC
        ),
        Err(LifecycleError::InvalidLimits)
    ));
    assert!(matches!(
        LifecycleRegistry::new(
            Limits {
                obligations: usize::MAX,
                ..Limits::default()
            },
            100,
            PC
        ),
        Err(LifecycleError::InvalidLimits)
    ));
    assert!(matches!(
        LifecycleRegistry::new(Limits::default(), 0, PC),
        Err(LifecycleError::InvalidTid)
    ));
    let mut r = registry();
    let parent = r.root_task();
    unchanged(&mut r, LifecycleError::InvalidObligation, |r| {
        r.record_obligation(
            parent,
            ObligationKind::PendingSignal {
                signal: 65,
                code: 0,
                scope: SignalScope::Task,
            },
        )
    });
    let (_, child) = creation(
        &mut r,
        parent,
        CreationRequest::Fork,
        CreationEventKind::Fork,
        101,
        101,
    );
    r.observe_newborn_stop(child, 1, PC).unwrap();
    unchanged(&mut r, LifecycleError::WrongState, |r| {
        r.observe_newborn_stop(child, 1, PC)
    });
    unchanged(&mut r, LifecycleError::EventMismatch, |r| {
        r.observe_exit(child, 2, ExitStatus::Signal(0))
    });
}
