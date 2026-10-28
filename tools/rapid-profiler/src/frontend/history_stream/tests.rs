//! Pure model controls; no native execution or transport qualification.
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

const F: FunctionId = FunctionId(11);
fn limits(actions: usize) -> Limits {
    Limits {
        epochs: 2,
        threads: 1,
        depth: 2,
        records_per_epoch: 4,
        actions,
    }
}
fn session(actions: usize, mandatory: bool) -> Session {
    Session::new_streaming_history(
        71,
        &[FunctionSpec {
            function: F,
            group: 0,
        }],
        &[GroupSpec { mandatory }],
        limits(actions),
    )
    .unwrap()
}
fn config() -> Config {
    Config {
        retained_per_function: 1,
        max_inflight: 1,
        max_invocations: 4,
    }
}
fn complete(s: &Session) {
    let mut thread = s.register_thread(1).unwrap();
    let mut slot = ModelReturnSlot {
        identity: 1,
        word: 17,
    };
    let mut entered = thread.enter_interval_waiting(71, F, 12, &mut slot).unwrap();
    thread
        .finish_interval(&mut entered, &mut slot, Observation::Value(13))
        .unwrap();
    assert_eq!(slot.word, 17);
}

#[test]
fn contiguous_small_resident_chunks_cross_256_and_512_without_retaining_permits() {
    let s = session(4, true);
    let mut chunks = Vec::new();
    let mut generations = Vec::new();
    for n in 0..300u64 {
        let e = s.stage(config()).unwrap();
        generations.push(e.generation());
        s.publish(&e, FailurePoint::None).unwrap();
        s.remove_current().unwrap();
        assert_eq!(s.history_committed_end(), (n + 1) * 2);
        assert_eq!(s.snapshot(), Err(ControlError::HistoryMode));
        if n & 1 == 1 {
            let c = s.drain_history().unwrap().unwrap();
            assert_eq!(c.range, n * 2 - 2..n * 2 + 2);
            assert_eq!(c.number, n.div_ceil(2));
            assert_eq!(c.actions.len(), 4);
            if let Some(previous) = chunks.last() {
                let previous: &HistoryChunk = previous;
                assert_eq!(c.before, previous.after);
            } else {
                assert_eq!(c.before, HistoryBinding::Initial);
            }
            assert_eq!(
                c.after,
                HistoryBinding::Removed {
                    action_index: n * 2 + 1,
                    generation: e.generation(),
                }
            );
            chunks.push(c);
        }
    }
    assert_eq!(s.retained_epochs(), 0);
    assert_eq!(chunks.len(), 150);
    for (i, action) in chunks.iter().flat_map(|c| &c.actions).enumerate() {
        assert_eq!(action.generation, generations[i / 2]);
        assert_eq!(
            action.kind,
            if i & 1 == 0 {
                ActionKind::Published
            } else {
                ActionKind::Removed
            }
        );
        assert_eq!(action.current, (i & 1 == 0).then_some(generations[i / 2]));
    }
    let before = s.history_window().unwrap();
    assert_eq!(before.chunk.range, 600..600);
    assert_eq!(s.drain_history().unwrap(), None);
    assert_eq!(s.history_window().unwrap(), before);
}

#[test]
fn initial_carry_can_have_nonzero_base_and_every_failure_append_is_committed() {
    let s = session(4, true);
    let e = s.stage(config()).unwrap();
    assert_eq!(
        s.publish(&e, FailurePoint::BeforeMutation),
        Err(ControlError::InjectedBefore)
    );
    s.deactivate(
        DeactivationRequest {
            generation: e.generation(),
            function: F,
        },
        FailurePoint::None,
    )
    .unwrap();
    assert_eq!(s.history_committed_end(), 2);
    let c = s.drain_history().unwrap().unwrap();
    assert_eq!(
        c.actions.iter().map(|a| a.kind).collect::<Vec<_>>(),
        [ActionKind::FailedBefore, ActionKind::Stale]
    );
    assert_eq!(
        (c.before, c.after),
        (HistoryBinding::Initial, HistoryBinding::Initial)
    );
    let mut thread = s.register_thread(1).unwrap();
    let mut slot = ModelReturnSlot {
        identity: 1,
        word: 17,
    };
    let mut entered = thread.enter_interval_waiting(71, F, 1, &mut slot).unwrap();
    assert!(matches!(
        entered.summary(),
        Some(IntervalEntrySummary::Unsampled {
            reason: UnsampledSummary::InitialDisarmed,
            history_len: 2,
            binding: BindingChange::Initial,
        })
    ));
    thread
        .finish_interval(&mut entered, &mut slot, Observation::Value(2))
        .unwrap();
    assert_eq!(slot.word, 17);
    assert_eq!(
        s.publish(&e, FailurePoint::AfterMutation),
        Err(ControlError::InjectedAfter)
    );
    assert_eq!(s.history_committed_end(), 3);
    let before = s.history_window().unwrap();
    assert_eq!(before.status, ControllerStatus::TerminalFailure);
    assert_eq!(before.current, Some(e.generation()));
    assert_eq!(before.retained_failed_generation, Some(e.generation()));
    assert_eq!(before.chunk.before, HistoryBinding::Initial);
    assert_eq!(before.chunk.after, HistoryBinding::Initial);
    assert_eq!(before.chunk.actions[0].kind, ActionKind::FailedAfter);
    assert_eq!(before.chunk.actions[0].current, Some(e.generation()));
    assert!(matches!(
        thread.enter_interval_waiting(71, F, 3, &mut slot),
        Err(IntervalEntryError::ControllerTerminal)
    ));
    assert_eq!(slot.word, 17);
    assert_eq!(s.drain_history(), Err(ControlError::TerminalFailure));
    assert_eq!(s.history_window().unwrap(), before);
}

#[test]
fn deactivation_variants_and_scan_publish_actual_appends_not_worst_case_reservations() {
    for (mandatory, failure, expected) in [
        (true, FailurePoint::None, ActionKind::Deferred),
        (false, FailurePoint::None, ActionKind::Disabled),
        (
            false,
            FailurePoint::BeforeMutation,
            ActionKind::FailedBefore,
        ),
        (false, FailurePoint::AfterMutation, ActionKind::FailedAfter),
    ] {
        let s = session(4, mandatory);
        let e = s.stage(config()).unwrap();
        s.publish(&e, FailurePoint::None).unwrap();
        complete(&s);
        let actual = s.deactivate(
            DeactivationRequest {
                generation: e.generation(),
                function: F,
            },
            failure,
        );
        assert_eq!(
            actual,
            match failure {
                FailurePoint::None => Ok(()),
                FailurePoint::BeforeMutation => Err(ControlError::InjectedBefore),
                FailurePoint::AfterMutation => Err(ControlError::InjectedAfter),
            }
        );
        assert_eq!(s.history_committed_end(), 2);
        assert_eq!(s.history_window().unwrap().chunk.actions[1].kind, expected);
    }
    let s = Session::new_streaming_history(
        71,
        &[
            FunctionSpec {
                function: F,
                group: 0,
            },
            FunctionSpec {
                function: FunctionId(12),
                group: 1,
            },
        ],
        &[GroupSpec { mandatory: true }, GroupSpec { mandatory: true }],
        limits(3),
    )
    .unwrap();
    let e = s.stage(config()).unwrap();
    s.publish(&e, FailurePoint::None).unwrap();
    complete(&s);
    assert_eq!(s.scan_closed(), Ok(1));
    assert_eq!(s.history_committed_end(), 2); // Reserved space for two, appended one.
    let before = s.history_window().unwrap();
    assert_eq!(s.scan_closed(), Err(ControlError::HistoryFull));
    assert_eq!(s.history_window().unwrap(), before);
}

#[test]
fn absolute_end_sequence_reserve_and_resident_refusals_preserve_the_complete_window() {
    let s = session(2, true);
    let e = s.stage(config()).unwrap();
    s.publish(&e, FailurePoint::None).unwrap();
    s.remove_current().unwrap();
    let next = s.stage(config()).unwrap();
    let before = s.history_window().unwrap();
    assert_eq!(
        s.publish(&next, FailurePoint::None),
        Err(ControlError::HistoryFull)
    );
    FAIL_RESERVE.set(true);
    assert_eq!(s.drain_history(), Err(ControlError::HistoryAllocation));
    FAIL_RESERVE.set(false);
    assert_eq!(s.history_window().unwrap(), before);
    s.drain_history().unwrap();
    {
        let mut w = s.inner.writer.lock().unwrap();
        w.history.base = MAX_HISTORY_POSITION;
        w.history.carry = BindingChange::Initial;
        s.inner
            .committed_end
            .store(MAX_HISTORY_POSITION, Ordering::Release);
    }
    let before = s.history_window().unwrap();
    assert_eq!(
        s.publish(&next, FailurePoint::None),
        Err(ControlError::HistoryExhausted)
    );
    assert_eq!(s.drain_history().unwrap(), None); // Valid final end; no increment.
    assert_eq!(s.history_window().unwrap(), before);
    {
        let mut w = s.inner.writer.lock().unwrap();
        w.history.base = MAX_HISTORY_POSITION - 1;
        w.history.number = u64::MAX;
        s.inner
            .committed_end
            .store(MAX_HISTORY_POSITION - 1, Ordering::Release);
    }
    s.publish(&next, FailurePoint::None).unwrap(); // Final encodable end is legal.
    assert_eq!(s.history_committed_end(), MAX_HISTORY_POSITION);
    let before = s.history_window().unwrap();
    assert_eq!(s.drain_history(), Err(ControlError::HistoryExhausted));
    assert_eq!(s.history_window().unwrap(), before);
}

#[test]
fn inconsistent_high_water_foreign_registry_and_poison_never_clear_history() {
    let s = session(4, true);
    let e = s.stage(config()).unwrap();
    s.publish(&e, FailurePoint::None).unwrap();
    let original = s.history_window().unwrap();
    s.inner.committed_end.store(0, Ordering::Release);
    assert_eq!(s.drain_history(), Err(ControlError::HistoryInvariant));
    s.inner.committed_end.store(1, Ordering::Release);
    assert_eq!(s.history_window().unwrap(), original);
    let foreign = session(4, true);
    let other = foreign.stage(config()).unwrap();
    let real = s
        .inner
        .registry
        .lock()
        .unwrap()
        .current
        .replace(Arc::clone(&other.owner));
    assert_eq!(s.drain_history(), Err(ControlError::HistoryInvariant));
    s.inner.registry.lock().unwrap().current = real;
    assert_eq!(s.history_window().unwrap(), original);
    for registry in [false, true] {
        let s = session(4, true);
        let e = s.stage(config()).unwrap();
        s.publish(&e, FailurePoint::None).unwrap();
        let poisoned = catch_unwind(AssertUnwindSafe(|| {
            if registry {
                let _lock = s.inner.registry.lock().unwrap();
                panic!("registry poison");
            } else {
                let _lock = s.inner.writer.lock().unwrap();
                panic!("writer poison");
            }
        }));
        assert!(poisoned.is_err());
        assert_eq!(s.drain_history(), Err(ControlError::Poisoned));
        assert_eq!(s.history_committed_end(), 1);
        assert_eq!(
            s.inner
                .writer
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .actions
                .len(),
            1
        );
    }
}
