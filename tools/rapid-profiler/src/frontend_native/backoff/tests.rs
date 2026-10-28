use super::*;

#[test]
fn bounded_full_and_disconnect_return_the_exact_owned_item() {
    let (tx, rx) = mpsc::sync_channel(1);
    let first = Box::new([1_u8; 512]);
    let second = Box::new([2_u8; 512]);
    let address = second.as_ptr();
    send(&tx, first).unwrap();
    let (error, retained) = send(&tx, second).unwrap_err();
    assert_eq!(error, Error::Full);
    assert_eq!(retained.as_ptr(), address);
    assert_eq!(*rx.recv().unwrap(), [1; 512]);
    drop(rx);
    let (error, retained) = send(&tx, retained).unwrap_err();
    assert_eq!(error, Error::Disconnected);
    assert_eq!(retained.as_ptr(), address);
    assert_eq!(*retained, [2; 512]);
}

#[test]
fn absolute_deadline_does_not_drift_or_catch_up() {
    let due = Instant::now();
    let late = Duration::from_millis(2);
    assert_eq!(
        driver::arm_due(due - Duration::from_millis(1), due, late),
        Ok(false)
    );
    assert_eq!(driver::arm_due(due, due, late), Ok(true));
    assert_eq!(driver::arm_due(due + late, due, late), Ok(true));
    assert_eq!(
        driver::arm_due(due + late + Duration::from_nanos(1), due, late),
        Err(Error::Deadline)
    );
    assert_eq!(
        driver::arm_due(due + Duration::from_millis(10), due, late),
        Err(Error::Deadline)
    );
    let p = Policy::ten_ms(10, 600, 10000).unwrap();
    assert_eq!(p.period() * p.epoch_limit(), Duration::from_secs(6));
    assert_eq!(
        Policy::ten_ms(1000, 1, 1).unwrap().config().max_invocations,
        1000
    );
    for (k, epochs, calls) in [
        (0, 1, 1),
        (11, 1, 1),
        (10, 0, 1),
        (10, 4097, 1),
        (10, 1, 0),
        (10, 1, 1000001),
    ] {
        assert_eq!(Policy::ten_ms(k, epochs, calls), Err(Error::Policy));
    }
}

#[test]
fn stop_is_shared_sticky_and_does_not_forge_worker_completion() {
    let shared = Arc::new(Shared {
        stop: AtomicBool::new(false),
        controller_failed: AtomicBool::new(false),
        attached: AtomicBool::new(false),
        start: OnceLock::new(),
        finished: OnceLock::new(),
    });
    let a = StopHandle(Arc::clone(&shared));
    let b = a.clone();
    assert!(!a.requested());
    b.request();
    a.request();
    assert!(a.requested() && b.requested());
    assert!(shared.finished.get().is_none());
    assert!(shared.start.get().is_none());
    assert!(!shared.attached.load(Ordering::Acquire));
}

#[test]
fn batch_cursor_refuses_loss_duplicate_reset_and_changed_gate_without_commit() {
    let empty = PairTotals::default();
    let full = PairTotals {
        entries: 4,
        returns: 4,
        completed: 3,
        unsampled: 1,
    };
    let first = advance(Cursor::default(), 1, empty, full, 4, 91).unwrap();
    let end = PairTotals {
        entries: 6,
        returns: 6,
        completed: 4,
        unsampled: 2,
    };
    let second = advance(first, 2, full, end, 2, 93).unwrap();
    assert_eq!(second.totals, end);
    for (number, before, after, n, gate) in [
        (1, full, end, 2, 93),
        (3, full, end, 2, 93),
        (2, empty, end, 2, 93),
        (2, full, end, 1, 93),
        (2, full, end, 2, 92),
        (2, full, end, 2, 94),
        (2, full, PairTotals { returns: 5, ..end }, 2, 93),
        (
            2,
            full,
            PairTotals {
                completed: 2,
                unsampled: 4,
                ..end
            },
            2,
            93,
        ),
    ] {
        assert_eq!(
            advance(first, number, before, after, n, gate),
            Err(Error::Sequence)
        );
    }
    assert_eq!(first.totals, full);
    assert_eq!(advance(first, 2, full, full, 0, 91), Err(Error::Sequence));
    assert_eq!(
        advance(Cursor::default(), 1, empty, full, 5, 91),
        Err(Error::Sequence)
    );
}

#[test]
fn historical_binding_join_is_owner_and_reason_specific() {
    use crate::generation::Epoch;
    let config = Policy::ten_ms(10, 1, 1).unwrap().config();
    let a = Epoch::new(&[FunctionId(1)], config).unwrap();
    let b = Epoch::new(&[FunctionId(1)], config).unwrap();
    let published = HistoryBinding::Published {
        action_index: 599,
        generation: a.id(),
    };
    let removed = HistoryBinding::Removed {
        action_index: 600,
        generation: a.id(),
    };
    assert!(binding_matches(
        RawIntervalOwner::Sampled {
            generation: a.id().get(),
            invocation: 0
        },
        published,
        600
    ));
    assert!(binding_matches(
        RawIntervalOwner::FunctionClosed {
            generation: a.id().get()
        },
        published,
        600
    ));
    assert!(binding_matches(
        RawIntervalOwner::Removed {
            generation: a.id().get()
        },
        removed,
        601
    ));
    assert!(binding_matches(
        RawIntervalOwner::InitialDisarmed,
        HistoryBinding::Initial,
        0
    ));
    assert!(!binding_matches(
        RawIntervalOwner::Sampled {
            generation: b.id().get(),
            invocation: 0
        },
        published,
        600
    ));
    assert!(!binding_matches(
        RawIntervalOwner::Sampled {
            generation: a.id().get(),
            invocation: 0
        },
        removed,
        601
    ));
    assert!(!binding_matches(
        RawIntervalOwner::Removed {
            generation: a.id().get()
        },
        published,
        600
    ));
    assert!(!binding_matches(
        RawIntervalOwner::FunctionClosed {
            generation: a.id().get()
        },
        removed,
        601
    ));
    // Absolute 600 must not be silently replaced by its low nine bits (88),
    // and a binding at index599 is not yet visible at prefix599.
    assert!(!binding_matches(
        RawIntervalOwner::Sampled {
            generation: a.id().get(),
            invocation: 0
        },
        published,
        600 & 0x1ff
    ));
    assert!(!binding_matches(
        RawIntervalOwner::Sampled {
            generation: a.id().get(),
            invocation: 0
        },
        published,
        599
    ));
}

#[test]
fn exported_values_and_controller_move_without_unsafe_send() {
    fn send_type<T: Send>() {}
    send_type::<Driver>();
    send_type::<Client>();
    send_type::<StopHandle>();
    send_type::<Export>();
    send_type::<WorkerFinish>();
    // Thread deliberately has no Send assertion: IntervalThread contains Rc phantom.
    assert_eq!(ROWS, 4);
    assert_eq!(SLOTS, 3);
    assert_eq!(HISTORY, 8);
    assert_eq!(WORK_QUEUE, 2);
    assert_eq!(EXPORT_QUEUE, 4);
}

#[test]
fn acknowledged_stop_never_arms_again_and_deadline_never_restarts() {
    use driver::{Clock, Decision};
    let start = Instant::now();
    let policy = Policy::ten_ms(10, 10, 100).unwrap();
    let mut clock = Clock::new(start, policy).unwrap();
    assert_eq!(clock.poll(start, false, 0), Ok(Decision::Arm(start)));
    // Request may race the already-started publication, but its next observed
    // boundary issues exactly one Stop/removal, even if request later reads false.
    let observed = start + Duration::from_millis(1);
    assert_eq!(clock.poll(observed, true, 1), Ok(Decision::Stop));
    assert_eq!(
        clock.poll(start + Duration::from_millis(10), false, 1),
        Ok(Decision::Wait)
    );
    assert_eq!(
        clock.poll(start + Duration::from_millis(20), true, 1),
        Ok(Decision::Wait)
    );
    assert_eq!(
        clock.poll(observed + policy.shutdown(), true, 1),
        Err(Error::Deadline)
    );
}

#[test]
fn end_of_run_cannot_hide_missed_publications() {
    use driver::{Clock, Decision};
    let start = Instant::now();
    let policy = Policy::ten_ms(10, 3, 100).unwrap();
    let mut clock = Clock::new(start, policy).unwrap();
    let end = start + policy.period() * policy.epoch_limit();
    assert_eq!(clock.poll(end, false, 1), Err(Error::Deadline));
    let mut complete = Clock::new(start, policy).unwrap();
    assert_eq!(complete.poll(end, false, 3), Ok(Decision::Stop));
    assert_eq!(
        complete.poll(end + Duration::from_millis(1), false, 3),
        Ok(Decision::Wait)
    );
}

#[test]
fn disconnected_sender_is_not_a_detach_or_completed_export() {
    let (tx, rx) = mpsc::sync_channel::<u8>(2);
    drop(tx);
    assert_eq!(rx.try_recv(), Err(mpsc::TryRecvError::Disconnected));
    assert_eq!(driver::finished_ok(None), Err(Error::Worker));
    let done = WorkerStatus {
        totals: Some(PairTotals::default()),
        detached: true,
        error: None,
        unexported: false,
    };
    assert_eq!(driver::finished_ok(Some(done)), Ok(()));
    for invalid in [
        WorkerStatus {
            detached: false,
            ..done
        },
        WorkerStatus {
            error: Some(Error::Full),
            ..done
        },
        WorkerStatus {
            unexported: true,
            ..done
        },
        WorkerStatus {
            totals: None,
            ..done
        },
        WorkerStatus {
            totals: Some(PairTotals {
                entries: 1,
                ..PairTotals::default()
            }),
            ..done
        },
    ] {
        assert_eq!(driver::finished_ok(Some(invalid)), Err(Error::Worker));
    }
}

#[test]
fn final_completion_rechecks_both_frozen_shutdown_deadlines() {
    use driver::{Clock, Decision};
    let start = Instant::now();
    let policy = Policy::ten_ms(10, 3, 100).unwrap();
    let end = start + policy.period() * policy.epoch_limit();
    for observed in [
        start,
        end - Duration::from_millis(1),
        end,
        end + Duration::from_millis(1),
    ] {
        let mut clock = Clock::new(start, policy).unwrap();
        assert_eq!(clock.poll(observed, true, 3), Ok(Decision::Stop));
        let deadline = (observed + policy.shutdown()).min(end + policy.shutdown());
        assert_eq!(
            clock.check_deadline(deadline - Duration::from_nanos(1)),
            Ok(())
        );
        assert_eq!(clock.check_deadline(deadline), Err(Error::Deadline));
        assert_eq!(
            clock.check_deadline(deadline + Duration::from_nanos(1)),
            Err(Error::Deadline)
        );
    }
}
