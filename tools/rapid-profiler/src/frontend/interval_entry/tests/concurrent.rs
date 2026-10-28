use super::*;

fn waited(s: &Session, expected: [usize; 2]) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while s.interval_waits() != expected {
        assert!(
            std::time::Instant::now() < deadline,
            "entry did not contend"
        );
        std::thread::yield_now();
    }
}

#[test]
fn waiting_entry_observes_complete_publication_and_removal() {
    for remove in [false, true] {
        let s = session(limits());
        let e = stage(&s, 2, 1, 2);
        let mut t = s.register_thread(1).unwrap();
        if remove {
            publish(&s, &e);
        }
        let (held_tx, held_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        std::thread::scope(|scope| {
            let s = &s;
            let e = &e;
            let control = scope.spawn(move || {
                let hold = |_: &[bool]| {
                    held_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                };
                if remove {
                    s.remove_with_controls(Some(e.generation()), hold)
                } else {
                    s.publish_with_controls(e, FailurePoint::None, hold)
                }
                .unwrap();
            });
            held_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            let entry = scope.spawn(move || {
                let mut rs = slot(1);
                let mut entry = t.enter_interval_waiting(INSTALL, A, 10, &mut rs).unwrap();
                assert_eq!(t.attempts, 1);
                assert!(!t.in_callback);
                let summary = entry.summary().unwrap();
                let exit = t
                    .finish_interval(&mut entry, &mut rs, Observation::Value(20))
                    .unwrap();
                assert_eq!(exit.summary(), summary);
                assert_eq!(rs, slot(1));
                assert_eq!(t.depth(), 0);
                done_tx.send((summary, t.completed_sequence())).unwrap();
            });
            waited(s, [1, 0]);
            assert!(matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
            release_tx.send(()).unwrap();
            control.join().unwrap();
            entry.join().unwrap();
        });
        let (summary, completed) = done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        if remove {
            assert_eq!(
                summary,
                IntervalEntrySummary::Unsampled {
                    reason: UnsampledSummary::Removed {
                        generation: e.generation()
                    },
                    history_len: 2,
                    binding: BindingChange::Removed {
                        action_index: 1,
                        generation: e.generation()
                    },
                }
            );
            assert_eq!(completed, 0);
            assert!(records(&e).is_empty());
        } else {
            assert_eq!(
                summary,
                IntervalEntrySummary::Admitted {
                    generation: e.generation(),
                    invocation: 0,
                    history_len: 1,
                    binding: BindingChange::Published {
                        action_index: 0,
                        generation: e.generation()
                    },
                }
            );
            assert_eq!(completed, 1);
            s.remove_current().unwrap();
            assert_eq!(
                records(&e),
                vec![row(&e, 0, 10, (1, 0, 20, 0), retained(0))]
            );
        }
        assert_eq!(s.interval_waits(), [1, 0]);
    }
}

#[test]
fn waiting_registry_keeps_writer_authority_until_reservation() {
    let s = session(limits());
    let e = stage(&s, 2, 1, 2);
    publish(&s, &e);
    let mut t = s.register_thread(1).unwrap();
    std::thread::scope(|scope| {
        // Guard belongs to this scope body, so assertion unwinding releases it
        // before scope joins the waiting worker.
        let registry = s.inner.registry.lock().unwrap();
        let worker = scope.spawn(move || {
            let mut rs = slot(1);
            let mut entry = t.enter_interval_waiting(INSTALL, A, 10, &mut rs).unwrap();
            assert_eq!(entry.stamp, published(&e, 0, 1));
            finish(&mut t, &mut entry, &mut rs, 20);
            assert_eq!(t.attempts, 1);
        });
        waited(&s, [0, 1]);
        assert!(matches!(
            s.inner.writer.try_lock(),
            Err(TryLockError::WouldBlock)
        ));
        drop(registry);
        worker.join().unwrap();
    });
    assert!(s.inner.writer.try_lock().is_ok());
}

#[test]
fn waiting_poison_is_refused_without_reservation_or_slot_mutation() {
    for writer in [true, false] {
        let s = session(limits());
        let mut t = s.register_thread(1).unwrap();
        let (held_tx, held_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        std::thread::scope(|scope| {
            let s = &s;
            let control = scope.spawn(move || {
                if writer {
                    let _guard = s.inner.writer.lock().unwrap();
                    held_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                    panic!("required waiting writer poison");
                } else {
                    let _guard = s.inner.registry.lock().unwrap();
                    held_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                    panic!("required waiting registry poison");
                }
            });
            held_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            let worker = scope.spawn(move || {
                let mut rs = slot(1);
                let expected = if writer {
                    IntervalEntryError::ControllerPoisoned
                } else {
                    model(EntryError::RegistryPoisoned)
                };
                assert_eq!(
                    t.enter_interval_waiting(INSTALL, A, 1, &mut rs).err(),
                    Some(expected)
                );
                assert_eq!(rs, slot(1));
                assert_eq!((t.attempts, t.depth(), t.completed_sequence()), (1, 0, 0));
                assert!(!t.in_callback);
            });
            waited(s, if writer { [1, 0] } else { [0, 1] });
            release_tx.send(()).unwrap();
            assert!(control.join().is_err());
            worker.join().unwrap();
        });
    }
}

#[test]
fn old_return_needs_no_controller_lock_after_rearm() {
    let s = session(limits());
    let old = stage(&s, 2, 1, 2);
    let new = stage(&s, 2, 1, 2);
    let mut t = s.register_thread(1).unwrap();
    publish(&s, &old);
    let mut rs = slot(1);
    let mut entry = t.enter_interval_waiting(INSTALL, A, 10, &mut rs).unwrap();
    let summary = entry.summary().unwrap();
    publish(&s, &new);
    assert!(old.try_report().is_none());
    let writer = s.inner.writer.lock().unwrap();
    let registry = s.inner.registry.lock().unwrap();
    let exit = t
        .finish_interval(&mut entry, &mut rs, Observation::Value(20))
        .unwrap();
    assert_eq!(exit.summary(), summary);
    assert_eq!(rs, slot(1));
    assert_eq!(
        records(&old),
        vec![row(&old, 0, 10, (1, 0, 20, 0), retained(0))]
    );
    assert_eq!(new.reservations(), 0);
    assert_eq!(s.interval_waits(), [0, 0]);
    drop(registry);
    drop(writer);
    let mut second = t.enter_interval_waiting(INSTALL, A, 30, &mut rs).unwrap();
    assert_eq!(second.stamp, published(&new, 1, 2));
    finish(&mut t, &mut second, &mut rs, 40);
    s.remove_current().unwrap();
    assert_eq!(
        records(&new),
        vec![row(&new, 0, 30, (1, 1, 40, 0), retained(0))]
    );
}
