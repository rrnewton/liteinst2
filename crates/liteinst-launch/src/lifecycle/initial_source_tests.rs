use super::*;

fn held_initial() -> LifecycleRegistry {
    let mut registry =
        LifecycleRegistry::new_after_exec_syscall_exit(Limits::default(), 101, 0x401000).unwrap();
    let root = registry.root_task();
    registry.resume(root, 0).unwrap();
    registry
        .observe_stop(root, 1, 0x401000, HoldReason::OwnedTrap)
        .unwrap();
    registry
}

fn check(registry: &LifecycleRegistry) -> Result<(), LifecycleError> {
    let task = registry.task(registry.root_task())?;
    registry.require_initial_source_singleton(task.id, task.process, task.address_space, task.tid)
}

#[test]
fn initial_source_singleton_keeps_exact_registry_and_candidate() {
    let registry = held_initial();
    let before = registry.snapshot();
    let task = registry.task(registry.root_task()).unwrap();
    let candidate = registry.exclusion_candidate(task.address_space, 0).unwrap();
    assert_eq!(candidate.tasks, [task.id]);
    assert!(candidate.obligations.is_empty());
    assert_eq!(check(&registry), Ok(()));
    assert_eq!(registry.snapshot(), before);
    registry.validate_candidate(&candidate).unwrap();
}

#[test]
fn initial_source_singleton_refuses_foreign_and_numeric_bindings_without_mutation() {
    let registry = held_initial();
    let foreign = held_initial();
    let task = registry.task(registry.root_task()).unwrap();
    let other = foreign.task(foreign.root_task()).unwrap();
    let before = registry.snapshot();
    for (selected, process, space, tid) in [
        (other.id, task.process, task.address_space, task.tid),
        (task.id, other.process, task.address_space, task.tid),
        (task.id, task.process, other.address_space, task.tid),
        (task.id, task.process, task.address_space, task.tid + 1),
        (task.id, task.process, task.address_space, 0),
    ] {
        assert!(
            registry
                .require_initial_source_singleton(selected, process, space, tid)
                .is_err()
        );
        assert_eq!(registry.snapshot(), before);
    }
}

#[test]
fn initial_source_singleton_rejects_live_model_changes_and_retains_diagnostics() {
    // Each fixture starts from the same valid model, then changes one fact.
    // Terminal history still violates this initial-only profile even though a
    // later general exclusion candidate may legitimately omit terminal tasks.
    for change in 0..15 {
        let mut registry = held_initial();
        let root = registry.root_task();
        let original = registry.task(root).unwrap().clone();
        let space = original.address_space;
        match change {
            0 => registry.state.tasks.get_mut(&root).unwrap().state = TaskState::Running,
            1 => {
                registry.state.tasks.get_mut(&root).unwrap().state = TaskState::Held {
                    pc: 0x401000,
                    reason: HoldReason::SyscallEntry,
                }
            }
            2 => registry.state.tasks.get_mut(&root).unwrap().syscall_open = true,
            3 => registry.state.tasks.get_mut(&root).unwrap().origin = TaskOrigin::Initial,
            4 => registry.state.spaces.get_mut(&space).unwrap().generation = 1,
            5 => registry.state.spaces.get_mut(&space).unwrap().poisoned = true,
            6 => {
                registry.state.spaces.get_mut(&space).unwrap().origin =
                    AddressSpaceOrigin::Exec { previous: space }
            }
            7 => {
                registry.state.tids.remove(&original.tid);
            }
            8 => {
                registry.state.tids.insert(original.tid + 1, root);
            }
            9 => {
                registry
                    .state
                    .processes
                    .get_mut(&original.process)
                    .unwrap()
                    .tgid += 1
            }
            10 => {
                let extra = TaskId {
                    registry: root.registry,
                    serial: 999,
                };
                let mut history = original.clone();
                history.id = extra;
                history.state = TaskState::Terminal(TerminalReason::Exit(ExitStatus::Code(0)));
                registry.state.tasks.insert(extra, history);
            }
            11 => {
                let extra = ProcessId {
                    registry: original.process.registry,
                    serial: 999,
                };
                registry
                    .state
                    .processes
                    .insert(extra, ProcessRecord { tgid: 102 });
            }
            12 => {
                let extra = AddressSpaceId {
                    registry: space.registry,
                    serial: 999,
                };
                let mut history = registry.address_space(space).unwrap().clone();
                history.id = extra;
                registry.state.spaces.insert(extra, history);
            }
            13 => {
                registry
                    .state
                    .add_obligation(
                        root,
                        space,
                        ObligationKind::PendingSignal {
                            signal: 10,
                            code: 0,
                            scope: SignalScope::Unknown,
                        },
                        None,
                    )
                    .unwrap();
            }
            14 => {
                let candidate = registry.exclusion_candidate(space, 0).unwrap();
                registry.begin_invalidation(&candidate).unwrap();
            }
            _ => unreachable!(),
        }
        let before = registry.snapshot();
        assert!(
            check(&registry).is_err(),
            "accepted initial-source mutation {change}"
        );
        assert_eq!(
            registry.snapshot(),
            before,
            "changed rejected model {change}"
        );
    }
}
