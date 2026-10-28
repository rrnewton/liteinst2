use super::*;
use std::cell::Cell;

fn budget(start: Instant, shutdown: Instant) -> Budget {
    Budget::new(
        start,
        Some(start),
        Duration::from_millis(2),
        shutdown,
        Some(start),
    )
    .unwrap()
}
type Packet = Box<[u64; 512]>;
fn full() -> (mpsc::SyncSender<Packet>, mpsc::Receiver<Packet>) {
    let (tx, rx) = mpsc::sync_channel(EXPORT_QUEUE);
    for n in 0..EXPORT_QUEUE {
        tx.try_send(Box::new([n as u64; 512])).unwrap();
    }
    (tx, rx)
}
fn retained_item<T>(out: Outcome<T>, expected: Error) -> (T, Option<DeadlineFailure>) {
    match out {
        Outcome::Retained {
            packet,
            error,
            deadline,
        } => {
            assert_eq!(error, expected);
            (packet, deadline)
        }
        Outcome::Accepted(_) => panic!("unexpected acceptance"),
    }
}
#[test]
fn capacity_four_retries_transfer_the_same_allocation_once() {
    assert_eq!(EXPORT_QUEUE, 4);
    assert_eq!(
        (POLL, QUANTUM),
        (Duration::from_millis(1), Duration::from_micros(250))
    );
    let start = Instant::now();
    let clock = Cell::new(start);
    let waits = Cell::new(0);
    let (tx, rx) = full();
    let packet = Box::new([99; 512]);
    let address = packet.as_ptr();
    let out = transfer(
        &tx,
        packet,
        Some(budget(start, start + Duration::from_secs(1))),
        || clock.get(),
        |duration| {
            assert_eq!(duration, QUANTUM);
            assert_eq!(waits.replace(waits.get() + 1), 0);
            assert_eq!(*rx.try_recv().unwrap(), [0; 512]);
            clock.set(clock.get() + duration);
        },
    );
    assert!(matches!(out, Outcome::Accepted(None)));
    assert_eq!(waits.get(), 1);
    for n in 1..EXPORT_QUEUE {
        assert_eq!(*rx.try_recv().unwrap(), [n as u64; 512]);
    }
    let received = rx.try_recv().unwrap();
    assert_eq!(received.as_ptr(), address);
    assert_eq!(*received, [99; 512]);
    assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
}
#[test]
fn full_local_expiry_hard_priority_and_coincident_boundaries() {
    let start = Instant::now();
    let ns = Duration::from_nanos(1);
    let ms = Duration::from_millis(1);
    // At arm equality Full wins local expiry; coincident shutdown equality
    // refuses, and one nanosecond beyond an arm is a real Deadline.
    for (origin, after, shutdown, expected, inclusive) in [
        (
            start,
            start + ms,
            start + Duration::from_secs(1),
            Error::Full,
            None,
        ),
        (start, start + ms, start + ms, Error::Deadline, Some(true)),
        (
            start + ms,
            start + ms * 2,
            start + Duration::from_secs(1),
            Error::Full,
            None,
        ),
        (
            start + ms,
            start + ms * 2,
            start + ms * 2,
            Error::Deadline,
            Some(true),
        ),
        (
            start + ms,
            start + ms * 2 + ns,
            start + Duration::from_secs(1),
            Error::Deadline,
            Some(false),
        ),
    ] {
        let (tx, rx) = full();
        let packet = Box::new([99; 512]);
        let address = packet.as_ptr();
        let mut observations = [origin, after].into_iter();
        let out = transfer(
            &tx,
            packet,
            Some(budget(start, shutdown)),
            || observations.next().unwrap(),
            |_| panic!("must not sleep"),
        );
        let (packet, failure) = retained_item(out, expected);
        assert_eq!(packet.as_ptr(), address);
        assert_eq!(failure.map(|f| f.at_limit_is_late), inclusive);
        assert!(failure.is_none_or(|f| f.phase == DeadlinePhase::SinkExportPending));
        assert_eq!(rx.try_iter().count(), EXPORT_QUEUE);
    }
    // Inclusive arm equality permits an immediate send, but does not permit
    // a zero-duration spin when that attempt is Full.
    let at = start + ms * 2;
    let (tx, rx) = mpsc::sync_channel(EXPORT_QUEUE);
    assert!(matches!(
        transfer(
            &tx,
            7,
            Some(budget(start, at + ms)),
            || at,
            |_| panic!("no wait")
        ),
        Outcome::Accepted(None)
    ));
    assert_eq!(rx.try_recv().unwrap(), 7);
    let (tx, _rx) = full();
    let (_, failure) = retained_item(
        transfer(
            &tx,
            Box::new([7; 512]),
            Some(budget(start, at + ms)),
            || at,
            |_| panic!("zero wait"),
        ),
        Error::Full,
    );
    assert!(failure.is_none());
}
#[test]
fn retry_window_limits_attempt_admission_not_successful_send_latency() {
    let start = Instant::now();
    for late in [false, true] {
        let (tx, rx) = full();
        let post = start
            + if late {
                Duration::from_millis(2) + Duration::from_nanos(1)
            } else {
                Duration::from_micros(1250)
            };
        let mut observations = [start, start, start + QUANTUM, post].into_iter();
        let out = transfer(
            &tx,
            Box::new([99; 512]),
            Some(budget(start, start + Duration::from_secs(1))),
            || observations.next().unwrap(),
            |_| {
                rx.try_recv().unwrap();
            },
        );
        let Outcome::Accepted(failure) = out else {
            panic!("actual send must stay accepted")
        };
        assert_eq!(failure.is_some(), late);
        assert!(failure.is_none_or(|f| f.phase == DeadlinePhase::SinkExportAccepted));
        assert_eq!(rx.try_iter().filter(|p| **p == [99; 512]).count(), 1);
    }
    // Even a first try can return after the local retry window; only hard
    // deadlines qualify its success. No extra attempt was started here.
    let (tx, rx) = mpsc::sync_channel(EXPORT_QUEUE);
    let mut times = [start, start + Duration::from_micros(1500)].into_iter();
    assert!(matches!(
        transfer(
            &tx,
            9,
            Some(budget(start, start + Duration::from_secs(1))),
            || times.next().unwrap(),
            |_| panic!("first send")
        ),
        Outcome::Accepted(None)
    ));
    assert_eq!(rx.try_recv().unwrap(), 9);
}
#[test]
fn missing_budget_disconnect_and_scoped_unwind_retain_authority() {
    let start = Instant::now();
    let (tx, rx) = full();
    let p = Box::new([88; 512]);
    let address = p.as_ptr();
    let (p, failure) = retained_item(
        transfer(
            &tx,
            p,
            None,
            || panic!("missing budget must not read clock"),
            |_| panic!("no wait"),
        ),
        Error::Sequence,
    );
    assert_eq!(p.as_ptr(), address);
    assert!(failure.is_none());
    drop(rx);
    let (p, failure) = retained_item(
        transfer(
            &tx,
            p,
            Some(budget(start, start + Duration::from_secs(1))),
            || start,
            |_| panic!("disconnect does not retry"),
        ),
        Error::Disconnected,
    );
    assert_eq!(p.as_ptr(), address);
    assert!(failure.is_none());

    let (tx, _rx) = full();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_clock(
            TestClock::new(move || start, |_| panic!("forced wait unwind")),
            || {
                let mut context = Context {
                    budget: Some(budget(start, start + Duration::from_secs(1))),
                };
                let _ = context.emit(&tx, Box::new([9; 512]), &mut None, &mut 0, &mut None);
            },
        );
    }));
    assert!(result.is_err());
    CLOCK.with(|slot| assert!(slot.borrow().is_none()));
    with_clock(TestClock::new(move || start, |_| panic!("unused")), || {
        CLOCK.with(|slot| assert!(slot.borrow().is_some()));
    });
    CLOCK.with(|slot| assert!(slot.borrow().is_none()));
}

#[test]
fn sink_policy_is_explicit_and_orthogonal_without_changing_limits() {
    let base = Policy::ten_ms(10, 520, 100000).unwrap();
    assert!(!base.worker_backpressure());
    assert!(!base.sink_backpressure());
    let sink = base.with_sink_backpressure();
    assert!(sink.sink_backpressure());
    assert!(!sink.worker_backpressure());
    let worker = base.with_worker_backpressure();
    assert!(worker.worker_backpressure());
    assert!(!worker.sink_backpressure());
    let both = worker.with_sink_backpressure();
    assert!(both.worker_backpressure() && both.sink_backpressure());
    for p in [base, sink, worker, both] {
        assert_eq!(
            (p.retained(), p.epoch_limit(), p.call_limit()),
            (10, 520, 100000)
        );
        assert_eq!(
            (p.period(), p.lateness(), p.shutdown()),
            (
                Duration::from_millis(10),
                Duration::from_millis(2),
                Duration::from_secs(2)
            )
        );
    }
    assert_eq!(
        (ROWS, SLOTS, HISTORY, WORK_QUEUE, EXPORT_QUEUE),
        (4, 3, 8, 2, 4)
    );
}
