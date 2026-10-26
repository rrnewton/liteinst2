//! Pure shared-mm ledger facts; these tests do not establish native task
//! exclusion, syscall phases, CET state, or physical thread disappearance.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
use liteinst_admission::entries::ResumeKind;
use liteinst_launch::lifecycle::*;
const PC: u64 = 0x401000;
const FLAGS: u64 = 0x10f00;
fn seq(r: &LifecycleRegistry, t: TaskId) -> u64 {
    r.task(t).unwrap().sequence + 1
}
fn resume(r: &mut LifecycleRegistry, t: TaskId) {
    r.resume(t, r.task(t).unwrap().sequence).unwrap();
}
fn entry(r: &mut LifecycleRegistry, t: TaskId) {
    resume(r, t);
    r.observe_stop(t, seq(r, t), PC + 2, HoldReason::SyscallEntry)
        .unwrap();
}
fn unchanged<T: std::fmt::Debug>(
    r: &mut LifecycleRegistry,
    error: LifecycleError,
    f: impl FnOnce(&mut LifecycleRegistry) -> Result<T, LifecycleError>,
) {
    let before = r.snapshot();
    assert_eq!(f(r).unwrap_err(), error);
    assert_eq!(r.snapshot(), before);
}
fn pending(r: &mut LifecycleRegistry, parent: TaskId) -> CreationTicket {
    entry(r, parent);
    let ticket = r
        .prepare_creation(parent, CreationRequest::Clone { flags: FLAGS })
        .unwrap();
    resume(r, parent);
    ticket
}
fn created(r: &mut LifecycleRegistry, parent: TaskId, ticket: CreationTicket) -> TaskId {
    r.observe_creation(
        ticket,
        seq(r, parent),
        CreationEvent {
            kind: CreationEventKind::Clone,
            child_tid: 101,
            child_tgid: 100,
            parent_visible_tid: 101,
            parent_pc: PC + 2,
        },
    )
    .unwrap()
}
fn pair(r: &mut LifecycleRegistry, parent: TaskId) -> TaskId {
    let ticket = pending(r, parent);
    let child = created(r, parent, ticket);
    r.observe_newborn_return_ready(child, 1, PC + 2).unwrap();
    resume(r, parent);
    r.observe_creation_exit(ticket, seq(r, parent), PC + 2, 101)
        .unwrap();
    child
}
fn exec(r: &mut LifecycleRegistry, task: TaskId) -> TaskId {
    entry(r, task);
    let ticket = r.prepare_exec(task).unwrap();
    resume(r, task);
    let fresh = r
        .observe_exec_event(ticket, seq(r, task), 100, 100, PC)
        .unwrap()
        .task;
    resume(r, fresh);
    r.observe_stop(fresh, 1, PC, HoldReason::SyscallExit)
        .unwrap();
    fresh
}
fn limits(tasks: usize, spaces: usize) -> Limits {
    Limits {
        tasks,
        processes: 1,
        address_spaces: spaces,
        obligations: 16,
    }
}

#[test]
fn thread_creation_shares_process_and_mm_but_preserves_distinct_return_phases() {
    let mut r = LifecycleRegistry::new_after_exec_syscall_exit(limits(2, 1), 100, PC).unwrap();
    let parent = r.root_task();
    let before = r.task(parent).unwrap().clone();
    let ticket = pending(&mut r, parent);
    let child = created(&mut r, parent, ticket);
    let new = r.task(child).unwrap();
    assert_ne!(new.id, parent);
    assert_eq!(new.tid, 101);
    assert_eq!(new.process, before.process);
    assert_eq!(new.address_space, before.address_space);
    assert_eq!(
        new.origin,
        TaskOrigin::Created {
            parent,
            request: CreationRequest::Clone { flags: FLAGS }
        }
    );
    assert_eq!(new.state, TaskState::Newborn);
    assert_eq!(r.snapshot().tasks().count(), 2);
    assert_eq!(r.snapshot().address_spaces().count(), 1);
    r.observe_newborn_return_ready(child, 1, PC + 2).unwrap();
    resume(&mut r, child);
    unchanged(&mut r, LifecycleError::EventMismatch, |r| {
        r.observe_stop(child, 2, PC + 2, HoldReason::SyscallExit)
    });
    r.observe_stop(child, 2, PC + 4, HoldReason::SyscallEntry)
        .unwrap();
    resume(&mut r, parent);
    r.observe_creation_exit(ticket, seq(&r, parent), PC + 2, 101)
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
            pc: PC + 4,
            reason: HoldReason::SyscallEntry
        }
    );
}
#[test]
fn shared_mm_candidates_include_both_tasks_and_original_obligation_provenance() {
    let mut r = LifecycleRegistry::new_after_exec_syscall_exit(limits(2, 1), 100, PC).unwrap();
    let parent = r.root_task();
    let mm = r.task(parent).unwrap().address_space;
    let obligation = r
        .record_obligation(
            parent,
            ObligationKind::SavedResume {
                pc: PC + 64,
                kind: ResumeKind::SignalFrame,
            },
        )
        .unwrap();
    let original = r.obligations().cloned().collect::<Vec<_>>();
    let child = pair(&mut r, parent);
    let candidate = r.exclusion_candidate(mm, 0).unwrap();
    assert_eq!(candidate.tasks, [parent, child]);
    assert_eq!(candidate.obligations, original);
    assert_eq!(candidate.obligations[0].id, obligation);
    assert_eq!(candidate.obligations[0].inherited_from, None);
    assert_eq!(r.obligations().count(), 1);
    resume(&mut r, child);
    assert_eq!(r.exclusion_candidate(mm, 0), Err(LifecycleError::NotHeld));
    assert_eq!(r.validate_candidate(&candidate), Err(LifecycleError::Stale));
    r.observe_stop(child, seq(&r, child), PC + 2, HoldReason::Interrupt)
        .unwrap();
    r.observe_exit(child, seq(&r, child), ExitStatus::Code(23))
        .unwrap();
    let survivor = r.exclusion_candidate(mm, 0).unwrap();
    assert_eq!(survivor.tasks, [parent]);
    assert_eq!(survivor.obligations, original);
    assert_eq!(
        r.task(child).unwrap().process,
        r.task(parent).unwrap().process
    );
}
#[test]
fn terminal_thread_does_not_refund_task_budget_or_reuse_numeric_identity() {
    let mut r = LifecycleRegistry::new_after_exec_syscall_exit(limits(2, 1), 100, PC).unwrap();
    let parent = r.root_task();
    let child = pair(&mut r, parent);
    r.observe_exit(child, seq(&r, child), ExitStatus::Code(23))
        .unwrap();
    assert_eq!(r.task_for_tid(101), None);
    let ticket = pending(&mut r, parent);
    unchanged(&mut r, LifecycleError::Exhausted, |r| {
        r.observe_creation(
            ticket,
            seq(r, parent),
            CreationEvent {
                kind: CreationEventKind::Clone,
                child_tid: 101,
                child_tgid: 100,
                parent_visible_tid: 101,
                parent_pc: PC + 2,
            },
        )
    });
    assert_eq!(
        r.task(child).unwrap().state,
        TaskState::Terminal(TerminalReason::Exit(ExitStatus::Code(23)))
    );
    assert_eq!(r.snapshot().tasks().count(), 2);
    assert_eq!(r.snapshot().address_spaces().count(), 1);
}
#[test]
fn exec_and_thread_orders_fit_one_process_two_mms_three_retained_tasks() {
    for exec_first in [false, true] {
        let mut r = LifecycleRegistry::new_after_exec_syscall_exit(limits(3, 2), 100, PC).unwrap();
        let root = r.root_task();
        let process = r.task(root).unwrap().process;
        let (leader, worker) = if exec_first {
            let leader = exec(&mut r, root);
            let worker = pair(&mut r, leader);
            r.observe_exit(worker, seq(&r, worker), ExitStatus::Code(23))
                .unwrap();
            (leader, worker)
        } else {
            let worker = pair(&mut r, root);
            r.observe_exit(worker, seq(&r, worker), ExitStatus::Code(23))
                .unwrap();
            (exec(&mut r, root), worker)
        };
        assert_eq!(r.snapshot().tasks().count(), 3);
        assert_eq!(r.snapshot().address_spaces().count(), 2);
        assert!(r.snapshot().tasks().all(|t| t.process == process));
        assert_eq!(r.task_for_tid(100), Some(leader));
        assert_eq!(r.task_for_tid(101), None);
        assert_eq!(
            r.task(worker).unwrap().state,
            TaskState::Terminal(TerminalReason::Exit(ExitStatus::Code(23)))
        );
        entry(&mut r, leader);
        let ticket = r.prepare_exec(leader).unwrap();
        resume(&mut r, leader);
        unchanged(&mut r, LifecycleError::Exhausted, |r| {
            r.observe_exec_event(ticket, seq(r, leader), 100, 100, PC)
        });
    }
}
#[test]
fn mismatched_thread_group_or_event_and_failed_clone_cannot_invent_membership() {
    let mut r = LifecycleRegistry::new_after_exec_syscall_exit(limits(2, 1), 100, PC).unwrap();
    let parent = r.root_task();
    let ticket = pending(&mut r, parent);
    for (kind, tgid) in [
        (CreationEventKind::Fork, 100),
        (CreationEventKind::Clone, 101),
    ] {
        unchanged(&mut r, LifecycleError::EventMismatch, |r| {
            r.observe_creation(
                ticket,
                seq(r, parent),
                CreationEvent {
                    kind,
                    child_tid: 101,
                    child_tgid: tgid,
                    parent_visible_tid: 101,
                    parent_pc: PC + 2,
                },
            )
        });
    }
    r.observe_creation_exit(ticket, seq(&r, parent), PC + 2, -11)
        .unwrap();
    assert_eq!(r.snapshot().tasks().count(), 1);
    assert_eq!(r.snapshot().address_spaces().count(), 1);
    let child = pair(&mut r, parent);
    assert_ne!(child, parent);
    assert_eq!(r.snapshot().tasks().count(), 2);
}
