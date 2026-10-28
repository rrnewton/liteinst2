//! Real bounded channels, simulated time, and owned transport sentinels only.
//! These controls grant no native call, drain, callback or report credit.
use super::*;
use crate::frontend_native::always_on as model;
use std::cell::Cell;

fn shared(start: Option<Instant>) -> Shared {
    let shared = Shared {
        stop: AtomicBool::new(false),
        controller_failed: AtomicBool::new(false),
        attached: AtomicBool::new(false),
        start: OnceLock::new(),
        finished: OnceLock::new(),
    };
    if let Some(start) = start {
        shared.start.set(start).unwrap();
    }
    shared
}
fn policy() -> Policy {
    Policy::ten_ms(10, 520, 100000)
        .unwrap()
        .with_worker_backpressure()
}
fn item(id: u8) -> Box<[u8; 512]> {
    Box::new([id; 512])
}

#[test]
fn immediate_default_ignores_waiting_state_and_keeps_full_refusal() {
    let immediate = Policy::ten_ms(10, 520, 100000).unwrap();
    assert!(!immediate.worker_backpressure());
    assert!(immediate.with_worker_backpressure().worker_backpressure());
    assert_eq!(immediate.config(), policy().config());
    assert_eq!(
        (
            immediate.period(),
            immediate.lateness(),
            immediate.shutdown()
        ),
        (policy().period(), policy().lateness(), policy().shutdown())
    );
    let shared = shared(None);
    shared.controller_failed.store(true, Ordering::Release);
    let (tx, rx) = mpsc::sync_channel(WORK_QUEUE);
    send(&tx, item(1)).unwrap();
    send(&tx, item(2)).unwrap();
    let value = item(3);
    let address = value.as_ptr();
    let (error, retained) = transfer(
        &tx,
        value,
        immediate,
        &shared,
        || panic!("default must not observe a new deadline"),
        |_| panic!("default must never wait"),
    )
    .unwrap_err();
    assert_eq!(error, Error::Full);
    assert_eq!(retained.as_ptr(), address);
    assert_eq!(*rx.try_recv().unwrap(), [1; 512]);
    assert_eq!(*rx.try_recv().unwrap(), [2; 512]);
    assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
}

#[test]
fn saturation_preserves_identity_fifo_and_normal_stop_flush() {
    let start = Instant::now();
    let shared = shared(Some(start));
    shared.stop.store(true, Ordering::Release); // Normal stop must still flush.
    let time = Cell::new(start);
    let waits = Cell::new(0);
    let (tx, rx) = mpsc::sync_channel(WORK_QUEUE);
    send(&tx, item(1)).unwrap();
    send(&tx, item(2)).unwrap();
    let value = item(3);
    let address = value.as_ptr();
    transfer(
        &tx,
        value,
        policy(),
        &shared,
        || time.get(),
        |duration| {
            assert_eq!(duration, POLL);
            waits.set(waits.get() + 1);
            time.set(time.get() + duration);
            if waits.get() == 2 {
                assert_eq!(*rx.try_recv().unwrap(), [1; 512]);
            }
        },
    )
    .unwrap();
    assert_eq!(waits.get(), 2);
    assert_eq!(*rx.try_recv().unwrap(), [2; 512]);
    let received = rx.try_recv().unwrap();
    assert_eq!(received.as_ptr(), address);
    assert_eq!(*received, [3; 512]);
    assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    assert!(shared.finished.get().is_none());
}

#[test]
fn disconnect_is_terminal_before_first_send_or_after_wait() {
    for disconnect_first in [true, false] {
        let start = Instant::now();
        let shared = shared(Some(start));
        let (tx, rx) = mpsc::sync_channel(WORK_QUEUE);
        send(&tx, item(1)).unwrap();
        send(&tx, item(2)).unwrap();
        let mut rx = Some(rx);
        if disconnect_first {
            drop(rx.take());
        }
        let value = item(3);
        let address = value.as_ptr();
        let mut waits = 0;
        let (error, retained) = transfer(
            &tx,
            value,
            policy(),
            &shared,
            || start,
            |_| {
                waits += 1;
                assert_eq!(waits, 1);
                drop(rx.take());
            },
        )
        .unwrap_err();
        assert_eq!(error, Error::Disconnected);
        assert_eq!(retained.as_ptr(), address);
        assert_eq!(*retained, [3; 512]);
        assert_eq!(waits, usize::from(!disconnect_first));
    }
}

#[test]
fn failed_controller_refuses_initially_and_after_wake_even_with_space() {
    for fail_first in [true, false] {
        let start = Instant::now();
        let shared = shared(Some(start));
        let (tx, rx) = mpsc::sync_channel(WORK_QUEUE);
        if !fail_first {
            send(&tx, item(1)).unwrap();
            send(&tx, item(2)).unwrap();
        }
        shared
            .controller_failed
            .store(fail_first, Ordering::Release);
        let value = item(3);
        let address = value.as_ptr();
        let mut waits = 0;
        let (error, retained) = transfer(
            &tx,
            value,
            policy(),
            &shared,
            || start,
            |_| {
                waits += 1;
                assert_eq!(waits, 1);
                assert_eq!(*rx.try_recv().unwrap(), [1; 512]);
                assert_eq!(*rx.try_recv().unwrap(), [2; 512]);
                shared.controller_failed.store(true, Ordering::Release);
            },
        )
        .unwrap_err();
        assert_eq!(error, Error::ControllerFailed);
        assert_eq!(retained.as_ptr(), address);
        assert_eq!(*retained, [3; 512]);
        assert_eq!(waits, usize::from(!fail_first));
        // There was space after failure: a forbidden send would be observable.
        assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    }
}

#[test]
fn original_cutoff_exact_oversleep_and_repeated_full_never_renew() {
    for mode in 0..3 {
        let start = Instant::now();
        let shared = shared(Some(start));
        let cutoff = start + Duration::from_millis(7200);
        let time = Cell::new(if mode == 0 { cutoff } else { cutoff - POLL * 2 });
        let (tx, rx) = mpsc::sync_channel(WORK_QUEUE);
        if mode != 0 {
            send(&tx, item(1)).unwrap();
            send(&tx, item(2)).unwrap();
        }
        let value = item(3);
        let address = value.as_ptr();
        let mut waits = 0;
        let (error, retained) = transfer(
            &tx,
            value,
            policy(),
            &shared,
            || time.get(),
            |duration| {
                waits += 1;
                assert!(waits <= 2);
                assert_eq!(duration, POLL);
                time.set(if mode == 1 {
                    cutoff + POLL
                } else {
                    time.get() + duration
                });
                if time.get() >= cutoff {
                    assert_eq!(*rx.try_recv().unwrap(), [1; 512]);
                    assert_eq!(*rx.try_recv().unwrap(), [2; 512]);
                }
            },
        )
        .unwrap_err();
        assert_eq!(error, Error::Deadline);
        assert_eq!(retained.as_ptr(), address);
        assert_eq!(*retained, [3; 512]);
        assert_eq!(waits, mode); // No new send after equality or oversleep.
        assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    }
}

#[test]
fn last_wait_is_clipped_and_a_wake_before_cutoff_can_transfer() {
    let start = Instant::now();
    let shared = shared(Some(start));
    let cutoff = start + Duration::from_millis(7200);
    let time = Cell::new(cutoff - Duration::from_nanos(200));
    let (tx, rx) = mpsc::sync_channel(WORK_QUEUE);
    send(&tx, item(1)).unwrap();
    send(&tx, item(2)).unwrap();
    let value = item(3);
    let address = value.as_ptr();
    let mut waits = 0;
    transfer(
        &tx,
        value,
        policy(),
        &shared,
        || time.get(),
        |duration| {
            waits += 1;
            assert_eq!(waits, 1);
            assert_eq!(duration, Duration::from_nanos(200));
            time.set(cutoff - Duration::from_nanos(100));
            assert_eq!(*rx.try_recv().unwrap(), [1; 512]);
        },
    )
    .unwrap();
    assert_eq!(*rx.try_recv().unwrap(), [2; 512]);
    let received = rx.try_recv().unwrap();
    assert_eq!(received.as_ptr(), address);
    assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
}

#[test]
fn missing_start_and_time_spent_sending_do_not_grant_a_fresh_wait() {
    let start = Instant::now();
    let absent = shared(None);
    let (tx, rx) = mpsc::sync_channel(WORK_QUEUE);
    let value = item(1);
    let address = value.as_ptr();
    let (error, retained) = transfer(
        &tx,
        value,
        policy(),
        &absent,
        || panic!("missing start"),
        |_| panic!("missing start"),
    )
    .unwrap_err();
    assert_eq!(error, Error::NotStarted);
    assert_eq!(retained.as_ptr(), address);
    send(&tx, retained).unwrap();
    send(&tx, item(2)).unwrap();
    let active = shared(Some(start));
    let cutoff = start + Duration::from_millis(7200);
    let reads = Cell::new(0);
    let value = item(3);
    let address = value.as_ptr();
    let (error, retained) = transfer(
        &tx,
        value,
        policy(),
        &active,
        || {
            reads.set(reads.get() + 1);
            if reads.get() == 1 {
                cutoff - Duration::from_nanos(1)
            } else {
                cutoff
            }
        },
        |_| panic!("must recheck before sleeping"),
    )
    .unwrap_err();
    assert_eq!(error, Error::Deadline);
    assert_eq!(retained.as_ptr(), address);
    assert_eq!(reads.get(), 2);
    assert_eq!(*rx.try_recv().unwrap(), [1; 512]);
    assert_eq!(*rx.try_recv().unwrap(), [2; 512]);
    assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
}

#[test]
fn terminal_pending_and_first_error_survive_real_finish_cleanup() {
    // Synthetic site and deliberately invalid transport marker; no native entry
    // is made and the marker is never admitted as a drain/report/call receipt.
    let Prepared { driver, client, .. } =
        unsafe { prepare(model::backoff_test_site(), 71, FunctionId(11), policy()) }.unwrap();
    let words = [0_u64; 2];
    let begin = words.as_ptr() as u64;
    // SAFETY: live readable local range through finish, metadata only, no calls.
    let stack = unsafe { ReadableStack::new(begin, begin + 16) }.unwrap();
    let mut thread = unsafe { client.attach(stack, IntervalJournal::allocate()) }.unwrap();
    let native =
        model::backoff_test_transport(driver.history_window().unwrap().stream().clone(), 93);
    let address = native.journal().as_ptr();
    let packet = CompletedBatch {
        native,
        calls: [None; ROWS],
    };
    thread.shared.start.set(Instant::now()).unwrap();
    thread
        .shared
        .controller_failed
        .store(true, Ordering::Release);
    let (error, packet) = transfer(
        &thread.tx,
        packet,
        thread.policy,
        &thread.shared,
        Instant::now,
        |_| panic!("failed before send"),
    )
    .unwrap_err();
    thread.pending = Some(packet);
    thread.fail(error); // Same terminal flush ownership branch.
    thread.fail(Error::Disconnected);
    assert_eq!(thread.error, Some(Error::ControllerFailed));
    assert_eq!(thread.flush(), Err(Error::ControllerFailed));
    let shared = Arc::clone(&thread.shared);
    let finished = thread.finish();
    assert_eq!(finished.status.error, Some(Error::ControllerFailed));
    assert!(finished.status.unexported);
    assert!(!finished.status.detached);
    assert_eq!(finished.status.totals, Some(PairTotals::default()));
    assert_eq!(shared.finished.get(), Some(&finished.status));
    let retained = finished.unexported.unwrap();
    assert_eq!(retained.native.journal().as_ptr(), address);
    assert_eq!(retained.native.journal(), &[93; 512]);
    assert!(finished.partial_calls.iter().all(Option::is_none));
}
