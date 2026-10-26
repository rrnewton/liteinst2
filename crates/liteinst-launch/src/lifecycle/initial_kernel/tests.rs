//! Model controls; no native stopped-task or namespace proof is constructed.
use super::*;

fn entry() -> LifecycleRegistry {
    let mut registry =
        LifecycleRegistry::new_after_exec_syscall_exit(Limits::default(), 101, 0x401000).unwrap();
    let root = registry.root_task();
    registry.resume(root, 0).unwrap();
    registry
        .observe_stop(root, 1, 0x401002, HoldReason::SyscallEntry)
        .unwrap();
    registry
}
fn check(registry: &LifecycleRegistry, phase: InitialKernelPhase) -> Result<(), LifecycleError> {
    let task = registry.task(registry.root_task())?;
    registry.require_initial_kernel_singleton(
        task.id,
        task.process,
        task.address_space,
        task.tid,
        phase,
    )
}
#[test]
fn kernel_singleton_requires_exact_entry_exit_and_pre_exit_model_phases() {
    let mut registry = entry();
    let root = registry.root_task();
    let original = registry.snapshot();
    assert_eq!(check(&registry, InitialKernelPhase::Entry), Ok(()));
    assert!(check(&registry, InitialKernelPhase::Exit).is_err());
    assert!(check(&registry, InitialKernelPhase::PreExit).is_err());
    assert_eq!(registry.snapshot(), original);
    registry.resume(root, 1).unwrap();
    let running = registry.snapshot();
    assert_eq!(check(&registry, InitialKernelPhase::PreExit), Ok(()));
    assert!(check(&registry, InitialKernelPhase::Entry).is_err());
    assert!(check(&registry, InitialKernelPhase::Exit).is_err());
    assert_eq!(registry.snapshot(), running);
    registry
        .observe_stop(root, 2, 0x401002, HoldReason::SyscallExit)
        .unwrap();
    let exited = registry.snapshot();
    assert_eq!(check(&registry, InitialKernelPhase::Exit), Ok(()));
    assert!(check(&registry, InitialKernelPhase::Entry).is_err());
    assert!(check(&registry, InitialKernelPhase::PreExit).is_err());
    assert_eq!(registry.snapshot(), exited);
}
#[test]
fn kernel_singleton_cannot_borrow_the_settled_source_predicate() {
    for phase in [
        InitialKernelPhase::Entry,
        InitialKernelPhase::Exit,
        InitialKernelPhase::PreExit,
    ] {
        let mut registry = entry();
        let root = registry.root_task();
        if phase != InitialKernelPhase::Entry {
            registry.resume(root, 1).unwrap();
        }
        if phase == InitialKernelPhase::Exit {
            registry
                .observe_stop(root, 2, 0x401002, HoldReason::SyscallExit)
                .unwrap();
        }
        let task = registry.task(root).unwrap();
        assert_eq!(check(&registry, phase), Ok(()));
        assert!(
            registry
                .require_initial_source_singleton(root, task.process, task.address_space, task.tid)
                .is_err()
        );
    }
}
#[test]
fn kernel_singleton_refuses_changed_membership_generation_origin_and_obligations() {
    for change in 0..12 {
        let mut registry = entry();
        let root = registry.root_task();
        let original = registry.task(root).unwrap().clone();
        match change {
            0 => registry.state.tasks.get_mut(&root).unwrap().syscall_open = false,
            1 => registry.state.tasks.get_mut(&root).unwrap().origin = TaskOrigin::Initial,
            2 => {
                registry
                    .state
                    .spaces
                    .get_mut(&original.address_space)
                    .unwrap()
                    .generation = 1
            }
            3 => {
                registry
                    .state
                    .spaces
                    .get_mut(&original.address_space)
                    .unwrap()
                    .poisoned = true
            }
            4 => {
                registry
                    .state
                    .spaces
                    .get_mut(&original.address_space)
                    .unwrap()
                    .origin = AddressSpaceOrigin::Exec {
                    previous: original.address_space,
                }
            }
            5 => {
                registry.state.tids.remove(&101);
            }
            6 => {
                registry.state.tids.insert(102, root);
            }
            7 => {
                registry
                    .state
                    .processes
                    .get_mut(&original.process)
                    .unwrap()
                    .tgid = 102
            }
            8 => {
                let mut extra = original.clone();
                extra.id = TaskId {
                    registry: root.registry,
                    serial: 999,
                };
                extra.state = TaskState::Terminal(TerminalReason::Exit(ExitStatus::Code(0)));
                registry.state.tasks.insert(extra.id, extra);
            }
            9 => {
                registry.state.processes.insert(
                    ProcessId {
                        registry: original.process.registry,
                        serial: 999,
                    },
                    ProcessRecord { tgid: 102 },
                );
            }
            10 => {
                let mut extra = registry
                    .address_space(original.address_space)
                    .unwrap()
                    .clone();
                extra.id = AddressSpaceId {
                    registry: extra.id.registry,
                    serial: 999,
                };
                registry.state.spaces.insert(extra.id, extra);
            }
            11 => {
                registry
                    .state
                    .add_obligation(
                        root,
                        original.address_space,
                        ObligationKind::PendingSignal {
                            signal: 10,
                            code: 0,
                            scope: SignalScope::Unknown,
                        },
                        None,
                    )
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let before = registry.snapshot();
        assert!(
            check(&registry, InitialKernelPhase::Entry).is_err(),
            "accepted mutation {change}"
        );
        assert_eq!(registry.snapshot(), before);
    }
}
