use super::*;

fn stop(seed: u64) -> Stop {
    Stop {
        site: seed + 17,
        count: seed * 3 + 1,
        encounters: seed * 5 + 2,
        registers: std::array::from_fn(|i| seed ^ (i as u64).wrapping_mul(0x9e3779b97f4a7c15)),
        words: [seed, !seed, seed.rotate_left(19)],
    }
}

#[test]
fn every_payload_word_and_reply_survive_all_4096_generations() {
    let (mut w, mut c) = channel();
    for i in 0..MAX_STOPS as u64 {
        let expected = stop(i);
        w.publish(expected.clone()).unwrap();
        let event = c.receive(Duration::ZERO).unwrap();
        assert_eq!(event.stop(), &expected);
        assert_eq!(
            event.resume(expected.site, expected.count).unwrap(),
            expected
        );
        assert_eq!(w.poll_reply(), Ok(Some((expected.site, expected.count))));
        assert_eq!(w.slot.phase.load(Ordering::Acquire), word(i + 1, IDLE));
    }
    assert_eq!(w.publish(stop(0)), Err(Error::Protocol));
    assert!(matches!(
        c.receive(Duration::ZERO),
        Err(Error::Disconnected)
    ));
}

#[test]
fn concurrent_handoffs_preserve_every_payload_and_actual_reply() {
    let (mut worker, mut controller) = channel();
    let wait = super::super::WAIT;
    let task = std::thread::spawn(move || {
        for generation in 0..MAX_STOPS as u64 {
            let expected = stop(generation);
            let reply = worker.exchange(expected.clone(), wait).unwrap();
            assert_eq!(reply, (expected.site, expected.count));
        }
    });
    for generation in 0..MAX_STOPS as u64 {
        let expected = stop(generation);
        let event = controller.receive(wait).unwrap();
        assert_eq!(event.stop(), &expected);
        assert_eq!(
            event.resume(expected.site, expected.count).unwrap(),
            expected
        );
    }
    assert!(matches!(controller.receive(wait), Err(Error::Disconnected)));
    task.join()
        .expect("exact producer joined after every handoff");
}

#[test]
fn zero_stop_close_requires_no_synthetic_event() {
    let (w, mut c) = channel();
    drop(w);
    assert!(matches!(
        c.receive(Duration::ZERO),
        Err(Error::Disconnected)
    ));
}

#[test]
fn queued_stop_precedes_worker_close_but_reply_fails() {
    let (mut w, mut c) = channel();
    let expected = stop(7);
    w.publish(expected.clone()).unwrap();
    drop(w);
    let event = c.receive(Duration::ZERO).unwrap();
    assert_eq!(event.stop(), &expected);
    assert_eq!(
        event.resume(expected.site, expected.count),
        Err(Error::Disconnected)
    );
}

#[test]
fn queued_reply_precedes_controller_close() {
    let (mut w, mut c) = channel();
    w.publish(stop(7)).unwrap();
    c.receive(Duration::ZERO).unwrap().resume(24, 22).unwrap();
    drop(c);
    assert_eq!(w.poll_reply(), Ok(Some((24, 22))));
    assert_eq!(w.publish(stop(8)), Err(Error::Disconnected));
}

#[test]
fn reply_is_the_actual_tuple_not_reconstructed_from_stop() {
    for reply in [(0, 22), (24, 0)] {
        let (mut w, mut c) = channel();
        w.publish(stop(7)).unwrap();
        c.receive(Duration::ZERO)
            .unwrap()
            .resume(reply.0, reply.1)
            .unwrap();
        // The callback must independently refuse this wrong site/count. The
        // transport cannot silently replace a bad reply with the expected one.
        assert_eq!(w.poll_reply(), Ok(Some(reply)));
        assert_ne!(reply, (24, 22));
    }
}

#[test]
fn dropping_controller_before_observation_never_acknowledges() {
    let (mut w, c) = channel();
    w.publish(stop(0)).unwrap();
    drop(c);
    assert_eq!(w.poll_reply(), Err(Error::Disconnected));
    assert_eq!(w.slot.phase.load(Ordering::Acquire), word(1, PUBLISHED));
}

#[test]
fn dropping_event_latches_failure_without_resume() {
    let (mut w, mut c) = channel();
    w.publish(stop(0)).unwrap();
    drop(c.receive(Duration::ZERO).unwrap());
    assert_eq!(w.poll_reply(), Err(Error::Disconnected));
    assert!(matches!(c.receive(Duration::ZERO), Err(Error::Protocol)));
    assert_eq!(w.slot.phase.load(Ordering::Acquire), word(1, OBSERVED));
}

#[test]
fn forgotten_event_cannot_be_replaced_by_a_new_receive() {
    let (mut w, mut c) = channel();
    w.publish(stop(0)).unwrap();
    std::mem::forget(c.receive(Duration::ZERO).unwrap());
    assert!(matches!(c.receive(Duration::ZERO), Err(Error::Protocol)));
    assert_eq!(w.poll_reply(), Err(Error::Disconnected));
}

#[test]
fn forgotten_event_without_another_receive_times_out() {
    let (mut w, mut c) = channel();
    w.publish(stop(0)).unwrap();
    std::mem::forget(c.receive(Duration::ZERO).unwrap());
    assert_eq!(w.wait_reply(Instant::now()), Err(Error::Timeout));
    assert_eq!(w.slot.phase.load(Ordering::Acquire), word(1, OBSERVED));
}

#[test]
fn timed_out_reply_cannot_be_revived_by_late_resume() {
    let (mut w, mut c) = channel();
    w.publish(stop(0)).unwrap();
    let event = c.receive(Duration::ZERO).unwrap();
    assert_eq!(w.wait_reply(Instant::now()), Err(Error::Timeout));
    assert_eq!(event.resume(17, 1), Err(Error::Disconnected));
    assert_eq!(
        w.wait_reply(Instant::now() + Duration::from_secs(2)),
        Err(Error::Timeout)
    );
    assert_eq!(w.publish(stop(1)), Err(Error::Timeout));
}

#[test]
fn controller_timeout_is_terminal_and_prevents_publication() {
    let (mut w, mut c) = channel();
    assert!(matches!(c.receive(Duration::ZERO), Err(Error::Timeout)));
    assert_eq!(w.publish(stop(0)), Err(Error::Disconnected));
    assert!(matches!(
        c.receive(Duration::from_secs(2)),
        Err(Error::Timeout)
    ));
}

#[test]
fn duplicate_publication_cannot_overwrite_the_queued_stop() {
    let (mut w, mut c) = channel();
    let expected = stop(0);
    w.publish(expected.clone()).unwrap();
    assert_eq!(w.publish(stop(1)), Err(Error::Protocol));
    let event = c.receive(Duration::ZERO).unwrap();
    assert_eq!(event.stop(), &expected);
    assert_eq!(event.resume(17, 1), Err(Error::Disconnected));
}

#[test]
fn stale_or_future_generation_is_not_a_current_stop() {
    for generation in [0, 2, MAX_STOPS as u64 + 1] {
        let (mut w, mut c) = channel();
        w.publish(stop(0)).unwrap();
        w.slot
            .phase
            .store(word(generation, PUBLISHED), Ordering::Release);
        assert!(matches!(c.receive(Duration::ZERO), Err(Error::Protocol)));
    }
}

#[test]
fn stale_or_future_acknowledgement_is_not_consumed() {
    for generation in [0, 2, MAX_STOPS as u64 + 1] {
        let (mut w, mut c) = channel();
        w.publish(stop(0)).unwrap();
        c.receive(Duration::ZERO).unwrap().resume(17, 1).unwrap();
        w.slot
            .phase
            .store(word(generation, ACKNOWLEDGED), Ordering::Release);
        assert_eq!(w.poll_reply(), Err(Error::Protocol));
    }
}

#[test]
fn second_receive_after_reply_waits_for_worker_then_next_stop() {
    let (mut w, mut c) = channel();
    w.publish(stop(0)).unwrap();
    c.receive(Duration::ZERO).unwrap().resume(17, 1).unwrap();
    assert_eq!(c.poll_stop(), Ok(None));
    assert_eq!(w.poll_reply(), Ok(Some((17, 1))));
    assert_eq!(c.poll_stop(), Ok(None));
    w.publish(stop(1)).unwrap();
    assert_eq!(
        c.receive(Duration::ZERO).unwrap().resume(18, 4).unwrap(),
        stop(1)
    );
    assert_eq!(w.poll_reply(), Ok(Some((18, 4))));
}

#[test]
fn worker_panic_preserves_queued_stop_and_is_a_join_failure() {
    let (mut w, mut c) = channel();
    let worker = std::thread::spawn(move || {
        w.publish(stop(9)).unwrap();
        panic!("intentional worker failure after publication");
    });
    assert!(worker.join().is_err());
    let event = c.receive(Duration::ZERO).unwrap();
    assert_eq!(event.stop(), &stop(9));
    assert_eq!(event.resume(26, 28), Err(Error::Disconnected));
}

#[test]
fn slot_is_retained_by_detached_peer_until_that_peer_drops() {
    let (mut w, c) = channel();
    let weak = Arc::downgrade(&w.slot);
    drop(c);
    assert!(weak.upgrade().is_some());
    assert_eq!(w.publish(stop(0)), Err(Error::Disconnected));
    drop(w);
    assert!(weak.upgrade().is_none());
}

#[test]
fn controller_unwind_drops_event_without_authorizing_progress() {
    let (mut w, mut c) = channel();
    w.publish(stop(0)).unwrap();
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _event = c.receive(Duration::ZERO).unwrap();
        panic!("intentional controller unwind while observing");
    }));
    assert!(failed.is_err());
    assert_eq!(w.poll_reply(), Err(Error::Disconnected));
    assert!(matches!(c.receive(Duration::ZERO), Err(Error::Protocol)));
    assert_eq!(w.slot.phase.load(Ordering::Acquire), word(1, OBSERVED));
}

#[test]
fn worker_drop_during_observation_makes_resume_fail() {
    let (mut w, mut c) = channel();
    w.publish(stop(0)).unwrap();
    let event = c.receive(Duration::ZERO).unwrap();
    drop(w);
    assert_eq!(event.resume(17, 1), Err(Error::Disconnected));
}

#[test]
fn unresponsive_live_worker_does_not_turn_deadline_into_completion() {
    let (w, mut c) = channel();
    assert!(matches!(c.receive(Duration::ZERO), Err(Error::Timeout)));
    drop(w);
    // Later disconnection does not relabel the original timeout as completion.
    assert!(matches!(c.receive(Duration::ZERO), Err(Error::Timeout)));
}
