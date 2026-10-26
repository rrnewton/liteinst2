//! Authenticated-fact ledger tests, not native exec or exclusion evidence.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
use liteinst_admission::entries::ResumeKind;
use liteinst_launch::lifecycle::*;

const PC: u64 = 0x401000;

fn sequence(r: &LifecycleRegistry, task: TaskId) -> u64 {
    r.task(task).unwrap().sequence + 1
}
fn resume(r: &mut LifecycleRegistry, task: TaskId) {
    r.resume(task, r.task(task).unwrap().sequence).unwrap();
}
fn entry(r: &mut LifecycleRegistry, task: TaskId) {
    resume(r, task);
    r.observe_stop(task, sequence(r, task), PC + 2, HoldReason::SyscallEntry)
        .unwrap();
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
fn pending(r: &mut LifecycleRegistry, task: TaskId) -> ExecTicket {
    entry(r, task);
    let ticket = r.prepare_exec(task).unwrap();
    resume(r, task);
    ticket
}
fn replace(r: &mut LifecycleRegistry, task: TaskId) -> TaskId {
    let tid = r.task(task).unwrap().tid;
    let ticket = pending(r, task);
    let fresh = r
        .observe_exec_event(ticket, sequence(r, task), tid, tid, PC)
        .unwrap()
        .task;
    resume(r, fresh);
    r.observe_stop(fresh, 1, PC, HoldReason::SyscallExit)
        .unwrap();
    fresh
}
fn create(r: &mut LifecycleRegistry, parent: TaskId, tid: i32, thread: bool) -> TaskId {
    entry(r, parent);
    let request = if thread {
        CreationRequest::Clone { flags: 0x50f00 }
    } else {
        CreationRequest::Fork
    };
    let ticket = r.prepare_creation(parent, request).unwrap();
    let parent_tid = r.task(parent).unwrap().tid;
    resume(r, parent);
    let child = r
        .observe_creation(
            ticket,
            sequence(r, parent),
            CreationEvent {
                kind: if thread {
                    CreationEventKind::Clone
                } else {
                    CreationEventKind::Fork
                },
                child_tid: tid,
                child_tgid: if thread { parent_tid } else { tid },
                parent_visible_tid: tid,
                parent_pc: PC + 2,
            },
        )
        .unwrap();
    r.observe_newborn_return_ready(child, 1, PC + 2).unwrap();
    resume(r, parent);
    r.observe_creation_exit(ticket, sequence(r, parent), PC + 2, i64::from(tid))
        .unwrap();
    child
}

#[test]
fn exec_event_and_legacy_exec_keep_distinct_reasons_and_actual_exit_obligation() {
    for legacy in [false, true] {
        let mut r =
            LifecycleRegistry::new_after_exec_syscall_exit(Limits::default(), 100, PC).unwrap();
        let old = r.root_task();
        let old_record = r.task(old).unwrap().clone();
        let ticket = pending(&mut r, old);
        let transition = if legacy {
            r.observe_exec(ticket, sequence(&r, old), 100, 100, PC)
        } else {
            r.observe_exec_event(ticket, sequence(&r, old), 100, 100, PC)
        }
        .unwrap();
        let task = transition.task;
        assert_eq!(transition.superseded, [old]);
        assert_ne!(task, old);
        assert_ne!(transition.address_space, old_record.address_space);
        let record = r.task(task).unwrap();
        assert_eq!(record.process, old_record.process);
        assert_eq!(record.tid, 100);
        assert_eq!(record.sequence, 0);
        assert_eq!(record.origin, TaskOrigin::Exec { previous: old });
        assert_eq!(
            record.state,
            TaskState::Held {
                pc: PC,
                reason: if legacy {
                    HoldReason::Exec
                } else {
                    HoldReason::ExecEvent
                }
            }
        );
        assert_eq!(
            r.task(old).unwrap().state,
            TaskState::Terminal(TerminalReason::ExecReplaced)
        );
        assert_eq!(r.task_for_tid(100), Some(task));
        assert_eq!(
            r.address_space(transition.address_space)
                .unwrap()
                .generation,
            0
        );
        assert_eq!(
            r.address_space(transition.address_space).unwrap().origin,
            AddressSpaceOrigin::Exec {
                previous: old_record.address_space
            }
        );
        resume(&mut r, task);
        unchanged(&mut r, LifecycleError::EventMismatch, |r| {
            r.observe_stop(task, 1, PC, HoldReason::SyscallEntry)
        });
        r.observe_stop(task, 1, PC, HoldReason::Interrupt).unwrap();
        resume(&mut r, task);
        unchanged(&mut r, LifecycleError::EventMismatch, |r| {
            r.observe_stop(task, 2, PC, HoldReason::SyscallEntry)
        });
        r.observe_stop(task, 2, PC, HoldReason::SyscallExit)
            .unwrap();
        resume(&mut r, task);
        unchanged(&mut r, LifecycleError::EventMismatch, |r| {
            r.observe_stop(task, 3, PC, HoldReason::SyscallExit)
        });
        r.observe_stop(task, 3, PC + 2, HoldReason::SyscallEntry)
            .unwrap();
    }
    // The original constructor is a distinct, already user-ready fact.
    let mut first = LifecycleRegistry::new(Limits::default(), 100, PC).unwrap();
    let task = first.root_task();
    entry(&mut first, task);
}

#[test]
fn exec_event_rejects_stale_foreign_wrong_tid_and_duplicate_facts_atomically() {
    let mut r = LifecycleRegistry::new_after_exec_syscall_exit(Limits::default(), 100, PC).unwrap();
    let old = r.root_task();
    let ticket = pending(&mut r, old);
    let n = sequence(&r, old);
    for bad in [0, n + 1, u64::MAX] {
        unchanged(&mut r, LifecycleError::Stale, |r| {
            r.observe_exec_event(ticket, bad, 100, 100, PC)
        });
    }
    for (former, current) in [(101, 100), (100, 101), (0, 100), (100, 0)] {
        unchanged(&mut r, LifecycleError::EventMismatch, |r| {
            r.observe_exec_event(ticket, n, former, current, PC)
        });
    }
    let mut foreign =
        LifecycleRegistry::new_after_exec_syscall_exit(Limits::default(), 100, PC).unwrap();
    let task = foreign.root_task();
    let foreign_ticket = pending(&mut foreign, task);
    unchanged(&mut r, LifecycleError::UnknownIdentity, |r| {
        r.observe_exec_event(foreign_ticket, n, 100, 100, PC)
    });
    let fresh = r.observe_exec_event(ticket, n, 100, 100, PC).unwrap().task;
    unchanged(&mut r, LifecycleError::WrongState, |r| {
        r.observe_exec_event(ticket, n + 1, 100, 100, PC)
    });
    assert_eq!(r.task_for_tid(100), Some(fresh));
}

#[test]
fn generic_stops_cannot_fabricate_any_exec_phase() {
    let mut r = LifecycleRegistry::new_after_exec_syscall_exit(Limits::default(), 100, PC).unwrap();
    let task = r.root_task();
    resume(&mut r, task);
    for reason in [
        HoldReason::Exec,
        HoldReason::ExecEvent,
        HoldReason::ExecSyscallExit,
    ] {
        unchanged(&mut r, LifecycleError::EventMismatch, |r| {
            r.observe_stop(task, 1, PC, reason)
        });
    }
    r.observe_stop(task, 1, PC, HoldReason::Interrupt).unwrap();
}

#[test]
fn physical_process_budget_is_distinct_from_retained_exec_and_fork_incarnations() {
    for exec_first in [true, false] {
        for exhausted_field in [0, 1] {
            let limits = Limits {
                tasks: if exhausted_field == 0 { 3 } else { 4 },
                processes: 2,
                address_spaces: if exhausted_field == 1 { 3 } else { 4 },
                obligations: 16,
            };
            let mut r = LifecycleRegistry::new_after_exec_syscall_exit(limits, 100, PC).unwrap();
            let root = r.root_task();
            let (parent, child) = if exec_first {
                let fresh = replace(&mut r, root);
                let child = create(&mut r, fresh, 101, false);
                (fresh, child)
            } else {
                let child = create(&mut r, root, 101, false);
                (root, replace(&mut r, child))
            };
            assert_eq!(r.snapshot().tasks().count(), 3);
            assert_eq!(r.snapshot().address_spaces().count(), 3);
            assert_ne!(
                r.task(parent).unwrap().process,
                r.task(child).unwrap().process
            );
            r.observe_exit(child, sequence(&r, child), ExitStatus::Code(23))
                .unwrap();
            let tid = r.task(parent).unwrap().tid;
            let ticket = pending(&mut r, parent);
            unchanged(&mut r, LifecycleError::Exhausted, |r| {
                r.observe_exec_event(ticket, sequence(r, parent), tid, tid, PC)
            });
            assert_eq!(r.snapshot().tasks().count(), 3);
            assert_eq!(r.snapshot().address_spaces().count(), 3);
        }
    }
}

#[test]
fn exec_event_preserves_signal_provenance_and_old_mm_saved_returns() {
    let mut r = LifecycleRegistry::new_after_exec_syscall_exit(Limits::default(), 100, PC).unwrap();
    let leader = r.root_task();
    let thread = create(&mut r, leader, 101, true);
    let old_mm = r.task(leader).unwrap().address_space;
    let process = r.task(leader).unwrap().process;
    let unknown_kind = ObligationKind::PendingSignal {
        signal: 10,
        code: -1,
        scope: SignalScope::Unknown,
    };
    let unknown = r.record_obligation(leader, unknown_kind).unwrap();
    let other = r
        .record_obligation(
            leader,
            ObligationKind::PendingSignal {
                signal: 12,
                code: -6,
                scope: SignalScope::Task,
            },
        )
        .unwrap();
    let own = r
        .record_obligation(
            thread,
            ObligationKind::PendingSignal {
                signal: 13,
                code: -6,
                scope: SignalScope::Task,
            },
        )
        .unwrap();
    let saved = r
        .record_obligation(
            thread,
            ObligationKind::SavedResume {
                pc: PC + 32,
                kind: ResumeKind::SignalFrame,
            },
        )
        .unwrap();
    let original = r.obligations().cloned().collect::<Vec<_>>();
    let ticket = pending(&mut r, thread);
    let transition = r
        .observe_exec_event(ticket, sequence(&r, thread), 101, 100, PC)
        .unwrap();
    assert_eq!(transition.superseded, [leader, thread]);
    assert_eq!(r.task(transition.task).unwrap().process, process);
    let inherited = r
        .obligations()
        .filter(|o| o.address_space == transition.address_space)
        .collect::<Vec<_>>();
    assert_eq!(inherited.len(), 2);
    assert_eq!(
        inherited
            .iter()
            .filter(|o| o.inherited_from == Some(unknown) && o.kind == unknown_kind)
            .count(),
        1
    );
    assert_eq!(
        inherited
            .iter()
            .filter(|o| o.inherited_from == Some(own))
            .count(),
        1
    );
    assert!(inherited.iter().all(|o| o.task == transition.task
        && o.inherited_from != Some(other)
        && o.inherited_from != Some(saved)));
    assert_eq!(
        r.obligations()
            .filter(|o| o.address_space == old_mm)
            .cloned()
            .collect::<Vec<_>>(),
        original
    );
}

#[test]
fn proved_early_exec_failure_keeps_the_existing_pure_transaction_contract() {
    // This caller-supplied fact includes old-mm survival. A native errno alone
    // does not provide that proof, particularly after the point of no return.
    let mut r = LifecycleRegistry::new_after_exec_syscall_exit(Limits::default(), 100, PC).unwrap();
    let task = r.root_task();
    let identity = r.task(task).unwrap().clone();
    let ticket = pending(&mut r, task);
    let n = sequence(&r, task);
    for invalid in [0, 1, -4096] {
        unchanged(&mut r, LifecycleError::EventMismatch, |r| {
            r.observe_exec_failure(ticket, n, PC, invalid)
        });
    }
    r.observe_exec_failure(ticket, n, PC, -2).unwrap();
    let record = r.task(task).unwrap();
    assert_eq!(
        (record.id, record.process, record.address_space),
        (identity.id, identity.process, identity.address_space)
    );
    assert_eq!(
        record.state,
        TaskState::Held {
            pc: PC,
            reason: HoldReason::SyscallExit
        }
    );
    entry(&mut r, task);
}
