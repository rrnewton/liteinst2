use super::*;
use crate::generation::{Disposition, Population, Terminal};
use std::sync::mpsc;
use std::time::Duration;

mod concurrent;

const INSTALL: u64 = 71;
const A: FunctionId = FunctionId(11);
fn limits() -> Limits {
    Limits {
        epochs: 3,
        threads: 3,
        depth: 4,
        records_per_epoch: 8,
        actions: 8,
    }
}
fn session(limits: Limits) -> Session {
    Session::new(
        INSTALL,
        &[FunctionSpec {
            function: A,
            group: 0,
        }],
        &[GroupSpec { mandatory: true }],
        limits,
    )
    .unwrap()
}
fn config(k: usize, m: usize, a: usize) -> Config {
    Config {
        retained_per_function: k,
        max_inflight: m,
        max_invocations: a,
    }
}
fn stage(s: &Session, k: usize, m: usize, a: usize) -> EpochHandle {
    s.stage(config(k, m, a)).unwrap()
}
fn publish(s: &Session, e: &EpochHandle) {
    assert_eq!(s.publish(e, FailurePoint::None), Ok(()));
}
fn slot(identity: u64) -> ModelReturnSlot {
    ModelReturnSlot {
        identity,
        word: 0x1000 + identity,
    }
}
fn enter(t: &mut ThreadModel, value: u64, rs: &mut ModelReturnSlot) -> IntervalEntry {
    let before = t.attempts;
    let entry = t.enter_interval(INSTALL, A, value, rs).unwrap();
    assert_eq!(t.attempts, before + 1);
    assert!(!t.in_callback);
    entry
}
fn finish(
    t: &mut ThreadModel,
    entry: &mut IntervalEntry,
    rs: &mut ModelReturnSlot,
    end: u64,
) -> (Completion, Payload) {
    let IntervalExit::Completed {
        completion,
        payload,
        stamp,
    } = t
        .finish_interval(entry, rs, Observation::Value(end))
        .unwrap()
    else {
        panic!("required admission")
    };
    assert_eq!(stamp, entry.stamp);
    assert_eq!(*rs, entry.original_slot);
    assert!(entry.state.is_none());
    (completion, payload)
}
fn unsampled(
    t: &mut ThreadModel,
    entry: &mut IntervalEntry,
    rs: &mut ModelReturnSlot,
    expected: UnsampledSummary,
) {
    let depth = t.depth();
    let sequence = t.completed_sequence();
    let token = *rs;
    assert_eq!(
        t.finish_interval(entry, rs, Observation::Value(99)),
        Ok(IntervalExit::Unsampled {
            reason: expected,
            stamp: entry.stamp
        })
    );
    assert_eq!(t.depth(), depth);
    assert_eq!(t.completed_sequence(), sequence);
    assert_eq!(*rs, token);
    assert!(entry.state.is_none());
}
fn published(e: &EpochHandle, index: usize, len: usize) -> EntryStamp {
    EntryStamp {
        history_len: len,
        binding: BindingChange::Published {
            action_index: index,
            generation: e.generation(),
        },
    }
}
fn row(
    e: &EpochHandle,
    invocation: usize,
    value: u64,
    frame: (u64, u64, u64, u64),
    disposition: Disposition,
) -> RecordObservation {
    let (thread, start, end, children) = frame;
    let admission = Admission {
        generation: e.generation(),
        invocation,
        function: A,
        entry_value: value,
    };
    RecordObservation {
        record: Record {
            admission,
            terminal: Some(Terminal::Completed {
                value: invocation as u64,
                disposition,
            }),
        },
        payload: Some(Payload {
            admission,
            thread,
            start_sequence: start,
            outcome: PayloadOutcome::Completed {
                end: Observation::Value(end),
                completed_children: children,
            },
        }),
    }
}
fn records(e: &EpochHandle) -> Vec<RecordObservation> {
    e.records().collect()
}
fn retained(rank: usize) -> Disposition {
    Disposition::Retained { rank }
}
fn refuse(
    t: &mut ThreadModel,
    install: u64,
    function: FunctionId,
    rs: &mut ModelReturnSlot,
    expected: IntervalEntryError,
) {
    let token = *rs;
    let depth = t.depth();
    let sequence = t.completed_sequence();
    assert_eq!(
        t.enter_interval(install, function, 999, rs).err(),
        Some(expected)
    );
    assert_eq!(*rs, token);
    assert_eq!(t.depth(), depth);
    assert_eq!(t.completed_sequence(), sequence);
}
fn model(e: EntryError) -> IntervalEntryError {
    IntervalEntryError::Model(e)
}
fn generation(e: AdmissionRefusal) -> IntervalEntryError {
    model(EntryError::Generation(e))
}

#[test]
fn p01_initial_off_crosses_arm() {
    let s = session(limits());
    let mut t = s.register_thread(1).unwrap();
    let mut rs = slot(1);
    let mut off = enter(&mut t, 10, &mut rs);
    assert_eq!(
        off.stamp,
        EntryStamp {
            history_len: 0,
            binding: BindingChange::Initial
        }
    );
    assert!(matches!(
        &off.state,
        Some(Entered::Unsampled(UnsampledOwner::Disarmed {
            observed: BindingChange::Initial
        }))
    ));
    assert_eq!(t.depth(), 0);
    assert_eq!(rs, slot(1));
    let e = stage(&s, 2, 2, 4);
    publish(&s, &e);
    assert!(records(&e).is_empty());
    unsampled(&mut t, &mut off, &mut rs, UnsampledSummary::InitialDisarmed);
    let mut admitted = enter(&mut t, 20, &mut rs);
    assert_eq!(admitted.stamp, published(&e, 0, 1));
    let (c, _) = finish(&mut t, &mut admitted, &mut rs, 30);
    assert_eq!(c.disposition, retained(0));
    assert_eq!(t.completed_sequence(), 1);
    assert_eq!(
        records(&e),
        vec![row(&e, 0, 20, (1, 0, 30, 0), retained(0))]
    );
}

#[test]
fn p02_old_off_new_combined_keeps_reports() {
    let s = session(limits());
    let old = stage(&s, 2, 2, 4);
    let new = stage(&s, 2, 2, 4);
    let mut t1 = s.register_thread(1).unwrap();
    let mut t2 = s.register_thread(2).unwrap();
    publish(&s, &old);
    let mut a = slot(1);
    let mut old_entry = enter(&mut t1, 10, &mut a);
    assert_eq!(s.remove_current(), Ok(()));
    assert!(old.try_report().is_none());
    let mut b = slot(2);
    let mut off = enter(&mut t2, 20, &mut b);
    assert_eq!(
        off.stamp,
        EntryStamp {
            history_len: 2,
            binding: BindingChange::Removed {
                action_index: 1,
                generation: old.generation()
            }
        }
    );
    publish(&s, &new);
    unsampled(
        &mut t2,
        &mut off,
        &mut b,
        UnsampledSummary::Removed {
            generation: old.generation(),
        },
    );
    assert!(records(&new).is_empty());
    finish(&mut t1, &mut old_entry, &mut a, 30);
    let report = old.try_report().unwrap();
    let retained_rows: Vec<_> = report.records().collect();
    assert_eq!(
        retained_rows,
        vec![row(&old, 0, 10, (1, 0, 30, 0), retained(0))]
    );
    let mut newest = enter(&mut t2, 40, &mut b);
    assert_eq!(newest.stamp, published(&new, 2, 3));
    finish(&mut t2, &mut newest, &mut b, 50);
    assert_eq!(
        records(&new),
        vec![row(&new, 0, 40, (2, 0, 50, 0), retained(0))]
    );
    assert_eq!(report.generation(), old.generation());
    assert_eq!(report.records().collect::<Vec<_>>(), retained_rows);
    let fresh = old.try_report().unwrap();
    assert_eq!(fresh.generation(), old.generation());
    assert_eq!(fresh.records().collect::<Vec<_>>(), retained_rows);
    assert_eq!((t1.completed_sequence(), t2.completed_sequence()), (1, 1));
    assert_eq!(s.snapshot().unwrap().actions.len(), 3);
    assert_eq!(s.snapshot().unwrap().enabled, vec![true]);
}

#[test]
fn p03_function_closed_retains_original_owner_across_rearm() {
    let s = session(limits());
    let old = stage(&s, 1, 2, 4);
    let new = stage(&s, 1, 2, 4);
    let mut t = s.register_thread(1).unwrap();
    publish(&s, &old);
    let mut rs = slot(1);
    let mut first = enter(&mut t, 10, &mut rs);
    finish(&mut t, &mut first, &mut rs, 20);
    let mut closed = enter(&mut t, 30, &mut rs);
    assert!(
        matches!(&closed.state, Some(Entered::Unsampled(UnsampledOwner::FunctionClosed { owner, function }))
        if Arc::ptr_eq(owner, &old.owner) && *function == A)
    );
    assert_eq!(old.reservations(), 0);
    assert_eq!(t.completed_sequence(), 1);
    assert_eq!(s.remove_current(), Ok(()));
    let report = old.try_report().unwrap(); // A closed-function pair is still alive.
    let saved: Vec<_> = report.records().collect();
    publish(&s, &new);
    unsampled(
        &mut t,
        &mut closed,
        &mut rs,
        UnsampledSummary::FunctionClosed {
            generation: old.generation(),
            function: A,
        },
    );
    let mut next = enter(&mut t, 40, &mut rs);
    finish(&mut t, &mut next, &mut rs, 50);
    assert_eq!(
        records(&old),
        vec![row(&old, 0, 10, (1, 0, 20, 0), retained(0))]
    );
    assert_eq!(
        records(&new),
        vec![row(&new, 0, 40, (1, 1, 50, 0), retained(0))]
    );
    assert_eq!(report.generation(), old.generation());
    assert_eq!(report.records().collect::<Vec<_>>(), saved);
    assert_eq!(
        old.try_report().unwrap().records().collect::<Vec<_>>(),
        saved
    );
    assert_eq!(t.completed_sequence(), 2);
}

#[test]
fn p04_real_lifo_nested_counts_only_admitted_children() {
    let s = session(limits());
    let old = stage(&s, 2, 2, 4);
    let new = stage(&s, 2, 2, 4);
    let mut t = s.register_thread(1).unwrap();
    publish(&s, &old);
    let (mut a, mut b, mut c) = (slot(1), slot(2), slot(3));
    let mut outer = enter(&mut t, 10, &mut a);
    assert_eq!(s.remove_current(), Ok(()));
    let mut off = enter(&mut t, 20, &mut b);
    publish(&s, &new);
    let mut inner = enter(&mut t, 30, &mut c);
    assert_eq!(t.depth(), 2); // The caller owns three opaque pairs.
    finish(&mut t, &mut inner, &mut c, 40);
    unsampled(
        &mut t,
        &mut off,
        &mut b,
        UnsampledSummary::Removed {
            generation: old.generation(),
        },
    );
    finish(&mut t, &mut outer, &mut a, 50);
    assert_eq!(
        records(&new),
        vec![row(&new, 0, 30, (1, 0, 40, 0), retained(0))]
    );
    assert_eq!(
        records(&old),
        vec![row(&old, 0, 10, (1, 0, 50, 1), retained(0))]
    );
    assert_eq!((a, b, c), (slot(1), slot(2), slot(3)));
    assert_eq!((t.depth(), t.completed_sequence()), (0, 2));
}

#[test]
fn p05_stale_action_counts_without_changing_binding() {
    let s = session(limits());
    let old = stage(&s, 1, 2, 4);
    let new = stage(&s, 1, 2, 4);
    let mut t = s.register_thread(1).unwrap();
    publish(&s, &old);
    let mut rs = slot(1);
    let mut first = enter(&mut t, 10, &mut rs);
    let request = finish(&mut t, &mut first, &mut rs, 20)
        .0
        .deactivate
        .unwrap();
    publish(&s, &new);
    assert_eq!(s.deactivate(request, FailurePoint::None), Ok(()));
    let before = s.snapshot().unwrap();
    assert_eq!(
        before.actions.iter().map(|a| a.kind).collect::<Vec<_>>(),
        vec![
            ActionKind::Published,
            ActionKind::Published,
            ActionKind::Stale
        ]
    );
    let mut entry = enter(&mut t, 30, &mut rs);
    assert_eq!(entry.stamp, published(&new, 1, 3));
    finish(&mut t, &mut entry, &mut rs, 40);
    assert_eq!(s.snapshot().unwrap(), before);
    assert_eq!(
        records(&old),
        vec![row(&old, 0, 10, (1, 0, 20, 0), retained(0))]
    );
    assert_eq!(
        records(&new),
        vec![row(&new, 0, 30, (1, 1, 40, 0), retained(0))]
    );
}

#[test]
fn p06_existing_k_close_gap_keeps_dropped_admission() {
    let s = session(limits());
    let e = stage(&s, 1, 2, 4);
    publish(&s, &e);
    let mut first = s.register_thread(1).unwrap();
    let mut second = s.register_thread(2).unwrap();
    let mut a = slot(1);
    first.enter(INSTALL, A, 10, &mut a).unwrap(); // Unchanged old-model setup.
    let (paused_tx, paused_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        let worker = scope.spawn(move || {
            first
                .finish_inner(
                    &mut a,
                    Observation::Value(20),
                    || {},
                    || {
                        paused_tx.send(()).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                    },
                )
                .unwrap()
        });
        paused_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let mut b = slot(2);
        let mut admitted = enter(&mut second, 30, &mut b);
        let (c, _) = finish(&mut second, &mut admitted, &mut b, 40);
        assert_eq!(c.disposition, Disposition::DroppedAfterBudget);
        assert_eq!(e.reservations(), 1);
        release_tx.send(()).unwrap();
        assert_eq!(worker.join().unwrap().0.disposition, retained(0));
        let mut closed = enter(&mut second, 50, &mut b);
        unsampled(
            &mut second,
            &mut closed,
            &mut b,
            UnsampledSummary::FunctionClosed {
                generation: e.generation(),
                function: A,
            },
        );
    });
    assert_eq!(second.completed_sequence(), 1);
    assert_eq!(e.reservations(), 0);
    assert_eq!(
        records(&e),
        vec![
            row(&e, 0, 10, (1, 0, 20, 0), retained(0)),
            row(&e, 1, 30, (2, 0, 40, 0), Disposition::DroppedAfterBudget)
        ]
    );
    assert_eq!(
        e.population(A).unwrap().population,
        Population {
            admitted: 2,
            completed: 2,
            retained: 1,
            dropped: 1,
            ..Population::default()
        }
    );
}

#[test]
fn r01_writer_busy_is_nonblocking_and_resets_callback() {
    let s = session(limits());
    let mut t = s.register_thread(1).unwrap();
    let (held_tx, held_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        let worker = scope.spawn(move || {
            let _guard = s.inner.writer.lock().unwrap();
            held_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        });
        held_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let mut rs = slot(1);
        refuse(
            &mut t,
            INSTALL,
            A,
            &mut rs,
            IntervalEntryError::ControllerBusy,
        );
        assert!(!t.in_callback);
        assert_eq!(t.attempts, 1);
        release_tx.send(()).unwrap();
        worker.join().unwrap();
    });
    let mut rs = slot(2);
    let mut entry = enter(&mut t, 1, &mut rs);
    assert_eq!(t.attempts, 2);
    unsampled(
        &mut t,
        &mut entry,
        &mut rs,
        UnsampledSummary::InitialDisarmed,
    );
}

#[test]
fn r02_registry_busy_releases_writer_and_resets_callback() {
    let s = session(limits());
    let mut t = s.register_thread(1).unwrap();
    let guard = s.inner.registry.lock().unwrap();
    let mut rs = slot(1);
    refuse(&mut t, INSTALL, A, &mut rs, model(EntryError::RegistryBusy));
    assert!(!t.in_callback);
    assert!(s.inner.writer.try_lock().is_ok());
    drop(guard);
    let mut entry = enter(&mut t, 2, &mut rs);
    unsampled(
        &mut t,
        &mut entry,
        &mut rs,
        UnsampledSummary::InitialDisarmed,
    );
}

#[test]
fn r03_writer_and_registry_poison_remain_errors() {
    for writer in [true, false] {
        let s = session(limits());
        let mut t = s.register_thread(1).unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if writer {
                let _guard = s.inner.writer.lock().unwrap();
                panic!("required writer poison");
            } else {
                let _guard = s.inner.registry.lock().unwrap();
                panic!("required registry poison");
            }
        }));
        assert!(result.is_err());
        let mut rs = slot(1);
        refuse(
            &mut t,
            INSTALL,
            A,
            &mut rs,
            if writer {
                IntervalEntryError::ControllerPoisoned
            } else {
                model(EntryError::RegistryPoisoned)
            },
        );
        assert!(!t.in_callback);
        assert_eq!(t.attempts, 1);
    }
}

#[test]
fn r04_terminal_after_mutation_is_never_disarmed() {
    let s = session(limits());
    let e = stage(&s, 1, 1, 1);
    let mut t = s.register_thread(1).unwrap();
    assert_eq!(
        s.publish(&e, FailurePoint::AfterMutation),
        Err(ControlError::InjectedAfter)
    );
    let before = s.snapshot().unwrap();
    assert_eq!(before.status, ControllerStatus::TerminalFailure);
    assert_eq!(before.retained_failed_generation, Some(e.generation()));
    let mut rs = slot(1);
    refuse(
        &mut t,
        INSTALL,
        A,
        &mut rs,
        IntervalEntryError::ControllerTerminal,
    );
    assert_eq!(s.snapshot().unwrap(), before);
    // A deliberately corrupted empty diagnostic cannot hide terminal status.
    s.inner.writer.lock().unwrap().current = None;
    s.inner.registry.lock().unwrap().current = None;
    refuse(
        &mut t,
        INSTALL,
        A,
        &mut rs,
        IntervalEntryError::ControllerTerminal,
    );
    assert_eq!(s.snapshot().unwrap().actions, before.actions);
    assert_eq!(
        s.snapshot().unwrap().retained_failed_generation,
        Some(e.generation())
    );
    assert!(!t.in_callback);
}

#[test]
fn r05_wrong_install_and_unregistered_thread_precede_off_result() {
    let s = session(limits());
    let mut t = s.register_thread(1).unwrap();
    let mut rs = slot(1);
    refuse(
        &mut t,
        INSTALL + 1,
        A,
        &mut rs,
        model(EntryError::WrongInstall),
    );
    assert!(!t.in_callback);
    assert_eq!(t.attempts, 1);
    t.identity = 99; // No such registered identity; no fake native thread claim.
    refuse(
        &mut t,
        INSTALL,
        A,
        &mut rs,
        model(EntryError::UnknownThread),
    );
    assert!(!t.in_callback);
    assert_eq!(t.attempts, 2);
    t.identity = 1;
    let mut off = enter(&mut t, 1, &mut rs);
    unsampled(&mut t, &mut off, &mut rs, UnsampledSummary::InitialDisarmed);
}

#[test]
fn r06_unknown_function_is_not_an_off_pair() {
    let s = session(limits());
    let mut t = s.register_thread(1).unwrap();
    let mut rs = slot(1);
    refuse(
        &mut t,
        INSTALL,
        FunctionId(99),
        &mut rs,
        generation(AdmissionRefusal::UnknownFunction),
    );
    assert!(!t.in_callback);
    assert_eq!(t.attempts, 1);
}

#[test]
fn r07_receipts_require_exact_spec_and_registered_thread() {
    let s = session(limits());
    let other = session(limits());
    let mut t = s.register_thread(1).unwrap();
    let mut same_numbers = other.register_thread(1).unwrap();
    let mut other_thread = s.register_thread(2).unwrap();
    let mut rs = slot(1);
    let mut entry = enter(&mut t, 1, &mut rs);
    for wrong in [&mut same_numbers, &mut other_thread] {
        assert_eq!(
            wrong.finish_interval(&mut entry, &mut rs, Observation::Value(2)),
            Err(IntervalExitError::ForeignEntry)
        );
        assert_eq!(rs, slot(1));
        assert!(entry.state.is_some());
        assert_eq!(wrong.completed_sequence(), 0);
    }
    unsampled(
        &mut t,
        &mut entry,
        &mut rs,
        UnsampledSummary::InitialDisarmed,
    );
}

#[test]
fn r08_closed_present_epoch_is_not_removed() {
    let s = session(limits());
    let e = stage(&s, 2, 1, 2);
    let mut t = s.register_thread(1).unwrap();
    publish(&s, &e);
    assert_eq!(e.close(), 0);
    let mut rs = slot(1);
    refuse(
        &mut t,
        INSTALL,
        A,
        &mut rs,
        generation(AdmissionRefusal::EpochClosed),
    );
    assert_eq!(s.snapshot().unwrap().current, Some(e.generation()));
    assert!(records(&e).is_empty());
    assert!(!t.in_callback);
}

#[test]
fn r09_inflight_and_record_storage_refusals_are_not_unsampled() {
    let s = session(limits());
    let e = stage(&s, 4, 1, 2);
    let mut t = s.register_thread(1).unwrap();
    publish(&s, &e);
    let (mut a, mut b) = (slot(1), slot(2));
    let mut held = enter(&mut t, 10, &mut a);
    let before = records(&e);
    refuse(
        &mut t,
        INSTALL,
        A,
        &mut b,
        generation(AdmissionRefusal::InflightLimit),
    );
    assert_eq!(records(&e), before);
    assert_eq!(e.reservations(), 1);
    assert!(!t.in_callback);
    finish(&mut t, &mut held, &mut a, 20);
    let mut second = enter(&mut t, 30, &mut b);
    finish(&mut t, &mut second, &mut b, 40);
    let before = records(&e);
    refuse(
        &mut t,
        INSTALL,
        A,
        &mut b,
        generation(AdmissionRefusal::StorageExhausted),
    );
    assert_eq!(records(&e), before);
    assert_eq!(e.reservations(), 0);
    assert!(e.try_report().is_some());
    assert!(!t.in_callback);
}

#[test]
fn r10_model_depth_limit_is_exact() {
    let s = session(Limits {
        depth: 1,
        ..limits()
    });
    let e = stage(&s, 2, 2, 4);
    let mut t = s.register_thread(1).unwrap();
    assert_eq!(t.interval_depth_limit(), 1);
    publish(&s, &e);
    let (mut a, mut b) = (slot(1), slot(2));
    let mut entry = enter(&mut t, 10, &mut a);
    let before = records(&e);
    refuse(&mut t, INSTALL, A, &mut b, model(EntryError::Depth));
    assert_eq!(records(&e), before);
    assert!(!t.in_callback);
    finish(&mut t, &mut entry, &mut a, 20);
    // Mixed-pair/event depth is owned by the deferred bridge, not this method.
}

#[test]
fn r11_slot_reentry_and_both_counter_exhaustions_remain_exact() {
    let s = session(limits());
    let e = stage(&s, 2, 2, 4);
    let mut t = s.register_thread(1).unwrap();
    publish(&s, &e);
    let mut rs = slot(1);
    t.in_callback = true;
    refuse(&mut t, INSTALL, A, &mut rs, model(EntryError::Reentry));
    assert!(t.in_callback); // Pre-existing reentry ownership is not cleared.
    assert_eq!(t.attempts, 0);
    t.in_callback = false;
    let mut entry = enter(&mut t, 10, &mut rs);
    let before = records(&e);
    let mut duplicate = slot(1);
    refuse(
        &mut t,
        INSTALL,
        A,
        &mut duplicate,
        model(EntryError::SlotInUse),
    );
    assert!(!t.in_callback);
    assert_eq!(records(&e), before);
    finish(&mut t, &mut entry, &mut rs, 20);
    for attempts in [true, false] {
        let s = session(limits());
        let mut t = s.register_thread(1).unwrap();
        if attempts {
            t.attempts = u64::MAX;
        } else {
            t.completed_sequence = u64::MAX;
        }
        let mut rs = slot(1);
        refuse(
            &mut t,
            INSTALL,
            A,
            &mut rs,
            model(EntryError::CounterExhausted),
        );
        assert!(t.exhausted);
        assert!(!t.in_callback);
        refuse(
            &mut t,
            INSTALL,
            A,
            &mut rs,
            model(EntryError::CounterExhausted),
        );
    }
}

#[test]
fn r13_non_top_and_full_frame_corruption_refuse_before_completion() {
    let s = session(limits());
    let e = stage(&s, 4, 2, 4);
    let mut t = s.register_thread(1).unwrap();
    publish(&s, &e);
    let (mut a, mut b) = (slot(1), slot(2));
    let mut outer = enter(&mut t, 10, &mut a);
    let mut inner = enter(&mut t, 20, &mut b);
    let before = records(&e);
    assert_eq!(
        t.finish_interval(&mut outer, &mut a, Observation::Value(30)),
        Err(IntervalExitError::ForeignEntry)
    );
    assert_eq!(records(&e), before);
    assert_eq!(t.depth(), 2);
    for part in 0..4 {
        let frame = t.frames.last_mut().unwrap();
        match part {
            0 => frame.thread += 1,
            1 => frame.start_sequence += 1,
            2 => frame.slot.word ^= 1,
            3 => frame.slot.identity += 1,
            _ => unreachable!(),
        }
        assert_eq!(
            t.finish_interval(&mut inner, &mut b, Observation::Value(30)),
            Err(IntervalExitError::ForeignEntry)
        );
        assert_eq!(records(&e), before);
        assert_eq!(t.completed_sequence(), 0);
        let frame = t.frames.last_mut().unwrap();
        match part {
            0 => frame.thread -= 1,
            1 => frame.start_sequence -= 1,
            2 => frame.slot.word ^= 1,
            3 => frame.slot.identity -= 1,
            _ => unreachable!(),
        }
    }
    let foreign = session(limits());
    let foreign_epoch = stage(&foreign, 4, 2, 4);
    let saved = Arc::clone(&t.frames.last().unwrap().owner);
    t.frames.last_mut().unwrap().owner = Arc::clone(&foreign_epoch.owner);
    assert_eq!(
        t.finish_interval(&mut inner, &mut b, Observation::Value(30)),
        Err(IntervalExitError::ForeignEntry)
    );
    assert_eq!(records(&e), before);
    t.frames.last_mut().unwrap().owner = saved;
    // Same frame but a changed receipt's complete admission is also refused.
    if let Some(Entered::Admitted { admission, .. }) = &mut inner.state {
        admission.entry_value += 1;
    }
    assert_eq!(
        t.finish_interval(&mut inner, &mut b, Observation::Value(30)),
        Err(IntervalExitError::ForeignEntry)
    );
    if let Some(Entered::Admitted { admission, .. }) = &mut inner.state {
        admission.entry_value -= 1;
    }
    t.completed_sequence = u64::MAX;
    assert_eq!(
        t.finish_interval(&mut inner, &mut b, Observation::Value(30)),
        Err(IntervalExitError::Model(ExitError::Sequence))
    );
    assert_eq!(records(&e), before);
    assert_eq!(t.depth(), 2);
    assert!(inner.state.is_some());
    t.completed_sequence = 0;
    finish(&mut t, &mut inner, &mut b, 30);
    finish(&mut t, &mut outer, &mut a, 40);
    assert_eq!(
        records(&e),
        vec![
            row(&e, 0, 10, (1, 0, 40, 1), retained(1)),
            row(&e, 1, 20, (1, 0, 30, 0), retained(0))
        ]
    );
}

#[test]
fn r14_full_token_and_consumed_receipt_refuse() {
    let s = session(limits());
    let mut t = s.register_thread(1).unwrap();
    let mut rs = slot(1);
    let mut off = enter(&mut t, 10, &mut rs);
    for dirty in [
        ModelReturnSlot { word: 0, ..slot(1) },
        ModelReturnSlot {
            identity: 2,
            ..slot(1)
        },
    ] {
        let mut changed = dirty;
        assert_eq!(
            t.finish_interval(&mut off, &mut changed, Observation::Value(20)),
            Err(IntervalExitError::TokenMismatch)
        );
        assert_eq!(changed, dirty);
        assert!(off.state.is_some());
    }
    unsampled(&mut t, &mut off, &mut rs, UnsampledSummary::InitialDisarmed);
    assert_eq!(
        t.finish_interval(&mut off, &mut rs, Observation::Value(20)),
        Err(IntervalExitError::Consumed)
    );
    let e = stage(&s, 2, 2, 4);
    publish(&s, &e);
    let mut entry = enter(&mut t, 30, &mut rs);
    rs.word ^= 1;
    assert_eq!(
        t.finish_interval(&mut entry, &mut rs, Observation::Value(40)),
        Err(IntervalExitError::TokenMismatch)
    );
    assert_eq!(t.depth(), 1);
    rs.word ^= 1;
    finish(&mut t, &mut entry, &mut rs, 40);
    assert_eq!(rs, slot(1));
    assert_eq!(
        t.finish_interval(&mut entry, &mut rs, Observation::Value(50)),
        Err(IntervalExitError::Consumed)
    );
    assert_eq!(
        records(&e),
        vec![row(&e, 0, 30, (1, 0, 40, 0), retained(0))]
    );
}

#[test]
fn r15_model_drop_cancels_admission_but_unsampled_creates_no_terminal() {
    let s = session(limits());
    let e = stage(&s, 2, 2, 4);
    let mut t = s.register_thread(1).unwrap();
    let mut off_slot = slot(1);
    let off = enter(&mut t, 10, &mut off_slot);
    publish(&s, &e);
    let mut rs = slot(2);
    let admitted = enter(&mut t, 20, &mut rs);
    drop(t);
    drop(off);
    drop(admitted);
    assert_eq!(off_slot, slot(1));
    assert_eq!(rs.word, MODEL_CONTINUATION); // Drop makes no external token repair claim.
    let admission = Admission {
        generation: e.generation(),
        invocation: 0,
        function: A,
        entry_value: 20,
    };
    assert_eq!(
        records(&e),
        vec![RecordObservation {
            record: Record {
                admission,
                terminal: Some(Terminal::Cancelled(CancelReason::DroppedTicket))
            },
            payload: Some(Payload {
                admission,
                thread: 1,
                start_sequence: 0,
                outcome: PayloadOutcome::Cancelled(CancelReason::DroppedTicket)
            }),
        }]
    );
}

#[test]
fn r16_history_full_preserves_exact_prefix_and_current_owner() {
    let s = session(Limits {
        actions: 1,
        ..limits()
    });
    let e = stage(&s, 2, 2, 4);
    let mut t = s.register_thread(1).unwrap();
    publish(&s, &e);
    let before = s.snapshot().unwrap();
    assert_eq!(s.remove_current(), Err(ControlError::HistoryFull));
    assert_eq!(s.snapshot().unwrap(), before);
    let mut rs = slot(1);
    let mut entry = enter(&mut t, 10, &mut rs);
    assert_eq!(entry.stamp, published(&e, 0, 1));
    finish(&mut t, &mut entry, &mut rs, 20);
    assert_eq!(s.snapshot().unwrap(), before);
    assert_eq!(
        records(&e),
        vec![row(&e, 0, 10, (1, 0, 20, 0), retained(0))]
    );

    let s = session(Limits {
        actions: 1,
        ..limits()
    });
    let e = stage(&s, 2, 2, 4);
    let mut t = s.register_thread(1).unwrap();
    assert_eq!(
        s.publish(&e, FailurePoint::BeforeMutation),
        Err(ControlError::InjectedBefore)
    );
    let mut off = enter(&mut t, 10, &mut rs);
    assert_eq!(
        off.stamp,
        EntryStamp {
            history_len: 1,
            binding: BindingChange::Initial
        }
    );
    unsampled(&mut t, &mut off, &mut rs, UnsampledSummary::InitialDisarmed);
    assert!(records(&e).is_empty());
}

#[test]
fn closed_function_receipt_alone_retains_e_permit_until_consumed() {
    let s = session(Limits {
        epochs: 1,
        ..limits()
    });
    let e = stage(&s, 1, 2, 4);
    let mut t = s.register_thread(1).unwrap();
    publish(&s, &e);
    let mut rs = slot(1);
    let mut admitted = enter(&mut t, 10, &mut rs);
    finish(&mut t, &mut admitted, &mut rs, 20);
    let mut closed = enter(&mut t, 30, &mut rs);
    let generation = e.generation();
    assert_eq!(s.remove_current(), Ok(()));
    drop(e);
    assert_eq!(s.retained_epochs(), 1);
    assert_eq!(s.stage(config(1, 1, 1)).err(), Some(SetupError::EpochLimit));
    unsampled(
        &mut t,
        &mut closed,
        &mut rs,
        UnsampledSummary::FunctionClosed {
            generation,
            function: A,
        },
    );
    assert_eq!(s.retained_epochs(), 0);
    let new = stage(&s, 1, 1, 1);
    assert_ne!(new.generation(), generation);
}

#[test]
fn inconsistent_binding_or_history_is_an_error_not_off() {
    for part in 0..6 {
        let s = session(limits());
        let e = stage(&s, 2, 2, 4);
        let mut t = s.register_thread(1).unwrap();
        publish(&s, &e);
        match part {
            0 => s.inner.writer.lock().unwrap().current = None,
            1 => s.inner.writer.lock().unwrap().actions.clear(),
            2 => s.inner.writer.lock().unwrap().actions[0].current = None,
            3 => s.inner.writer.lock().unwrap().actions[0].function = Some(A),
            4 => {
                let foreign = session(limits());
                let e2 = stage(&foreign, 2, 2, 4);
                s.inner.writer.lock().unwrap().current = Some(e2.generation());
                s.inner.writer.lock().unwrap().actions[0].generation = e2.generation();
                s.inner.writer.lock().unwrap().actions[0].current = Some(e2.generation());
                s.inner.registry.lock().unwrap().current = Some(Arc::clone(&e2.owner));
            }
            5 => {
                let mut w = s.inner.writer.lock().unwrap();
                let action = w.actions[0];
                w.actions.resize(s.inner.spec.limits.actions + 1, action);
            }
            _ => unreachable!(),
        }
        let mut rs = slot(1);
        let before = records(&e);
        refuse(
            &mut t,
            INSTALL,
            A,
            &mut rs,
            IntervalEntryError::BindingInconsistent,
        );
        assert_eq!(records(&e), before);
        assert!(!t.in_callback);
    }
}
