use super::*;
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[test]
fn concurrent_bridge_waits_for_complete_binding_and_keeps_exact_journal() {
    let mut p = prepared(limits());
    let e = p.stage(config(2)).unwrap();
    // SAFETY: synthetic metadata only; the worker owns its own State.
    let (mut c, client) = unsafe { p.activate_concurrent() }.unwrap();
    let (held_tx, held_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (go_tx, go_rx) = mpsc::sync_channel(1);
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    thread::scope(|scope| {
        let worker = scope.spawn(move || {
            let mut s = state(&client);
            ready_tx.send(()).unwrap();
            go_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            enter(&mut s, 0x8000);
            finish(&mut s, 0x8000);
            assert_eq!(
                s.totals,
                PairTotals {
                    entries: 1,
                    returns: 1,
                    completed: 1,
                    unsampled: 0
                }
            );
            assert_eq!((s.depth, s.model.depth()), (0, 0));
            done_tx.send((row(&s, 0), row(&s, 1))).unwrap();
        });
        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        // Identical metadata publication used by arm; this fixed test closure
        // holds its two guards after commit and introduces no production hook.
        let session = &c.binding.session;
        let owner = c.owner(&e).unwrap();
        let control = scope.spawn(move || {
            let _marker = ControllerScope::enter().unwrap();
            session
                .publish_with_controls(owner, FailurePoint::None, |_| {
                    held_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                })
                .unwrap();
        });
        held_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        go_tx.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while session.interval_waits() != [1, 0] {
            assert!(
                Instant::now() < deadline,
                "bridge never observed contention"
            );
            thread::yield_now();
        }
        assert!(matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
        release_tx.send(()).unwrap();
        control.join().unwrap();
        worker.join().unwrap();
    });
    let (entry, exit) = done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(
        entry,
        [1, 1, 0x1000, 0x8000, 0x2005, e.generation().get(), 8193]
    );
    assert_eq!(
        exit,
        [2, 1, 0x1012, 0x8000, 0x2005, e.generation().get(), 8193]
    );
    c.disarm(&e).unwrap();
    let report = records(&c, &e);
    assert_eq!(report.len(), 1);
    assert_eq!(report[0].record.admission.generation, e.generation());
    assert_eq!(report[0].record.admission.invocation, 0);
}

#[test]
fn controller_scope_refuses_same_thread_entry_and_nested_controls_without_mutation() {
    for concurrent in [false, true] {
        let mut p = prepared(limits());
        let e = p.stage(config(2)).unwrap();
        let (mut c, client) = unsafe {
            if concurrent {
                p.activate_concurrent()
            } else {
                p.activate()
            }
        }
        .unwrap();
        let mut s = state(&client);
        let before = c.history().unwrap();
        {
            let _scope = ControllerScope::enter().unwrap();
            assert_eq!(
                s.enter(0x1000, 0x8000, 0x2005),
                Err(error(Cause::ControllerReentry))
            );
            assert_eq!(c.arm(&e), Err(error(Cause::ControllerReentry)));
            assert_eq!(c.disarm(&e), Err(error(Cause::ControllerReentry)));
            assert_eq!(c.history(), Err(error(Cause::ControllerReentry)));
            assert!(
                CONTROLLER_ACTIVE.get(),
                "failed nested scopes cannot clear the owner"
            );
            assert_eq!(s.totals, PairTotals::default());
            assert_eq!(
                (s.depth, s.model.depth(), s.journal.used(), s.next),
                (0, 0, 0, 1)
            );
            assert!(s.failure.is_none());
        }
        assert!(!CONTROLLER_ACTIVE.get());
        assert_eq!(c.history().unwrap(), before);
        c.arm(&e).unwrap();
        enter(&mut s, 0x8000);
        finish(&mut s, 0x8000);
        c.disarm(&e).unwrap();
        assert_eq!(records(&c, &e).len(), 1);
    }
}

#[test]
fn controller_scope_unwinds_without_leaking_thread_marker() {
    let result = std::panic::catch_unwind(|| {
        let _scope = ControllerScope::enter().unwrap();
        assert!(CONTROLLER_ACTIVE.get());
        panic!("required controller unwind before any native call");
    });
    assert!(result.is_err());
    assert!(!CONTROLLER_ACTIVE.get());
    let (_c, client) = unsafe { prepared(limits()).activate_concurrent() }.unwrap();
    let mut s = state(&client);
    enter(&mut s, 0x8000);
    finish(&mut s, 0x8000);
    assert_eq!(
        s.totals,
        PairTotals {
            entries: 1,
            returns: 1,
            completed: 0,
            unsampled: 1
        }
    );
}
