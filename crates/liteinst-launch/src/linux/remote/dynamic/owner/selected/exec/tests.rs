//! Pure registry/dispatch consistency controls, not native exec evidence.
use super::*;
use crate::lifecycle::{HoldReason, LifecycleRegistry};

struct Stops {
    original: DynamicStop,
    entry: DynamicStop,
    exec: DynamicStop,
    exit: DynamicStop,
    bootstrap: DynamicStop,
}

fn token(registry: &LifecycleRegistry, task: crate::lifecycle::TaskId) -> DynamicStop {
    let record = registry.task(task).unwrap();
    DynamicStop {
        session: 91,
        sequence: record.sequence,
        tid: record.tid,
        task: Some(task),
    }
}

fn model_stops() -> Stops {
    let mut registry = LifecycleRegistry::new(
        crate::lifecycle::Limits {
            tasks: 2,
            processes: 1,
            address_spaces: 2,
            obligations: 8,
        },
        100,
        0x401000,
    )
    .unwrap();
    let old = registry.root_task();
    for sequence in 1..=40 {
        registry.resume(old, sequence - 1).unwrap();
        registry
            .observe_stop(old, sequence, 0x401000, HoldReason::OwnedTrap)
            .unwrap();
    }
    let original = token(&registry, old);
    registry.resume(old, original.sequence).unwrap();
    registry
        .observe_stop(old, 41, 0x401002, HoldReason::SyscallEntry)
        .unwrap();
    let entry = token(&registry, old);
    let ticket = registry.prepare_exec(old).unwrap();
    registry.resume(old, entry.sequence).unwrap();
    let transition = registry
        .observe_exec_event(ticket, 42, 100, 100, 0x801000)
        .unwrap();
    let exec = token(&registry, transition.task);
    registry.resume(transition.task, exec.sequence).unwrap();
    registry
        .observe_stop(transition.task, 1, 0x801000, HoldReason::SyscallExit)
        .unwrap();
    let exit = token(&registry, transition.task);
    registry.resume(transition.task, exit.sequence).unwrap();
    registry
        .observe_stop(transition.task, 2, 0x801000, HoldReason::OwnedTrap)
        .unwrap();
    let bootstrap = token(&registry, transition.task);
    Stops {
        original,
        entry,
        exec,
        exit,
        bootstrap,
    }
}

#[test]
fn exec_registry_birth_has_its_own_sequence_namespace() {
    let stops = model_stops();
    assert_eq!(stops.original.sequence, 40);
    assert_eq!(stops.entry.sequence, 41);
    assert_eq!(stops.exec.sequence, 0);
    assert_eq!(stops.exit.sequence, 1);
    assert_eq!(stops.bootstrap.sequence, 2);
    assert!(original_entry_follows(&stops.original, &stops.entry));
    assert!(replacement_exec_birth(&stops.entry, &stops.exec));
    assert_eq!(stops.original.task, stops.entry.task);
    assert_ne!(stops.entry.task, stops.exec.task);
    assert_eq!(stops.exec.task, stops.exit.task);
    assert_eq!(stops.exit.task, stops.bootstrap.task);
    assert!(stops.exit.sequence > stops.exec.sequence);
    assert!(stops.bootstrap.sequence > stops.exit.sequence);
    assert!(stops.bootstrap.sequence < stops.original.sequence);
}

#[test]
fn exec_stop_consistency_rejects_stale_foreign_and_wrong_birth_tokens() {
    let stops = model_stops();
    for row in 0..6 {
        let mut bad = stops.entry.clone();
        match row {
            0 => bad.sequence = stops.original.sequence,
            1 => bad.sequence = stops.original.sequence - 1,
            2 => bad.session += 1,
            3 => bad.tid += 1,
            4 => bad.task = None,
            5 => bad.task = stops.exec.task,
            _ => unreachable!(),
        }
        assert!(
            !original_entry_follows(&stops.original, &bad),
            "old ENTRY case {row}"
        );
    }
    for row in 0..7 {
        let mut bad = stops.exec.clone();
        match row {
            0 => bad.sequence = 1,
            1 => bad.sequence = stops.entry.sequence + 1,
            2 => bad.sequence = u64::MAX,
            3 => bad.session += 1,
            4 => bad.tid += 1,
            5 => bad.task = None,
            6 => bad.task = stops.entry.task,
            _ => unreachable!(),
        }
        assert!(
            !replacement_exec_birth(&stops.entry, &bad),
            "new EXEC case {row}"
        );
    }
    let mut missing = stops.original.clone();
    missing.task = None;
    assert!(!original_entry_follows(&missing, &stops.entry));
    let mut missing = stops.entry.clone();
    missing.task = None;
    assert!(!replacement_exec_birth(&missing, &stops.exec));
    assert!(original_entry_follows(&stops.original, &stops.entry));
    assert!(replacement_exec_birth(&stops.entry, &stops.exec));
}
