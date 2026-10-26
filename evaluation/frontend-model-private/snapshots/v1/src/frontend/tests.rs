use super::*;
use crate::generation::{Disposition, Population, Terminal};
use std::collections::BTreeMap;
use std::sync::mpsc;
use std::time::{Duration, Instant};

const A: FunctionId = FunctionId(11);
const B: FunctionId = FunctionId(29);
const INSTALL: u64 = 71;
fn limits() -> Limits { Limits { epochs: 3, threads: 3, depth: 16, records_per_epoch: 32, actions: 64 } }
fn config(k: usize, m: usize, a: usize) -> Config {
    Config { retained_per_function: k, max_inflight: m, max_invocations: a }
}
fn session_with(limits: Limits, shared: bool, mandatory: bool) -> Session {
    let functions = [FunctionSpec { function: A, group: 0 },
        FunctionSpec { function: B, group: if shared { 0 } else { 1 } }];
    let groups = vec![GroupSpec { mandatory }; if shared { 1 } else { 2 }];
    Session::new(INSTALL, &functions, &groups, limits).unwrap()
}
fn setup(k: usize, m: usize, a: usize) -> (Session, EpochHandle, ThreadModel) {
    let s = session_with(limits(), false, false);
    let e = s.stage(config(k, m, a)).unwrap();
    s.publish(&e, FailurePoint::None).unwrap();
    let t = s.register_thread(1).unwrap();
    (s, e, t)
}
fn slot(identity: u64) -> ModelReturnSlot { ModelReturnSlot { identity, word: 0x1000 + identity } }
fn retained(value: u64, rank: usize) -> Terminal {
    Terminal::Completed { value, disposition: Disposition::Retained { rank } }
}
fn dropped(value: u64) -> Terminal { Terminal::Completed { value, disposition: Disposition::DroppedAfterBudget } }
fn observed(owners: &[&EpochHandle]) -> BTreeMap<(GenerationId, usize), RecordObservation> {
    let mut out = BTreeMap::new();
    for owner in owners {
        for row in owner.records() {
            assert!(out.insert((row.record.admission.generation, row.record.admission.invocation), row).is_none());
        }
    }
    out
}
// This reference ledger constructs literal identities/outcomes. It does not call
// Epoch retention/population/controller methods or replay the production atomics.
fn expected_row(generation: GenerationId, invocation: usize, function: FunctionId,
    entry: u64, terminal: Option<Terminal>, payload: Option<(u64, u64, PayloadOutcome)>) -> RecordObservation {
    let admission = Admission { generation, invocation, function, entry_value: entry };
    RecordObservation { record: Record { admission, terminal }, payload: payload.map(|(thread, start_sequence, outcome)|
        Payload { admission, thread, start_sequence, outcome }) }
}
fn ledger(rows: &[RecordObservation]) -> BTreeMap<(GenerationId, usize), RecordObservation> {
    let mut out = BTreeMap::new();
    for &row in rows {
        assert!(out.insert((row.record.admission.generation, row.record.admission.invocation), row).is_none());
    }
    out
}
fn completed(end: u64, children: u64) -> PayloadOutcome {
    PayloadOutcome::Completed { end: Observation::Value(end), completed_children: children }
}
fn action(kind: ActionKind, generation: GenerationId, function: Option<FunctionId>,
    current: Option<GenerationId>, group: Option<usize>) -> Action {
    Action { kind, generation, function, current, group }
}
fn report_bounded(e: &EpochHandle) -> Report {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(r) = e.try_report() { return r; }
        assert!(Instant::now() < deadline, "required bounded drain before join");
        std::thread::yield_now();
    }
}

#[test]
fn g01_per_function_k_two_and_global_storage() {
    let (_s, e, mut t) = setup(2, 2, 4);
    for (i, f) in [A, B, A, B].into_iter().enumerate() {
        let mut rs = slot(i as u64);
        t.enter(INSTALL, f, 10 + i as u64, &mut rs).unwrap();
        let (c, _) = t.finish(&mut rs, Observation::Value(20 + i as u64)).unwrap();
        assert_eq!(c.disposition, Disposition::Retained { rank: i / 2 });
        assert_eq!(rs, slot(i as u64));
    }
    e.close();
    assert_eq!(observed(&[&e]), ledger(&[
        expected_row(e.generation(), 0, A, 10, Some(retained(0, 0)), Some((1, 0, completed(20, 0)))),
        expected_row(e.generation(), 1, B, 11, Some(retained(1, 0)), Some((1, 1, completed(21, 0)))),
        expected_row(e.generation(), 2, A, 12, Some(retained(2, 1)), Some((1, 2, completed(22, 0)))),
        expected_row(e.generation(), 3, B, 13, Some(retained(3, 1)), Some((1, 3, completed(23, 0)))),
    ]));
    for f in [A, B] {
        assert_eq!(e.population(f).unwrap().population, Population { admitted: 2, completed: 2,
            retained: 2, ..Population::default() });
    }
    assert_eq!(e.try_report().unwrap().records().count(), 4);
}

#[test]
fn g02_old_frame_keeps_removed_owner_and_payload() {
    let (s, old, mut t) = setup(2, 2, 4);
    let mut rs = slot(1); t.enter(INSTALL, A, 101, &mut rs).unwrap();
    let old_id = old.generation(); let weak = Arc::downgrade(&old.owner);
    s.remove_current().unwrap();
    assert!(old.try_report().is_none());
    let new = s.stage(config(2, 2, 4)).unwrap(); s.publish(&new, FailurePoint::None).unwrap();
    drop(old);
    assert!(weak.upgrade().is_some());
    let (c, payload) = t.finish(&mut rs, Observation::Value(103)).unwrap();
    assert_eq!(c.admission.generation, old_id);
    assert_eq!(payload.outcome, completed(103, 0));
    assert_eq!(new.records().count(), 0);
    assert_eq!(rs, slot(1));
    assert!(weak.upgrade().is_none());
    assert_eq!(s.retained_epochs(), 1);
}

#[test]
fn g03_nested_old_new_frames_keep_two_children() {
    let (s, old, mut t) = setup(8, 4, 8);
    let mut outer = slot(1); let mut inner = slot(2); let mut later = slot(3);
    t.enter(INSTALL, A, 10, &mut outer).unwrap();
    t.enter(INSTALL, B, 11, &mut inner).unwrap();
    t.finish(&mut inner, Observation::Value(12)).unwrap();
    let new = s.stage(config(8, 4, 8)).unwrap(); s.publish(&new, FailurePoint::None).unwrap();
    t.enter(INSTALL, B, 20, &mut later).unwrap();
    t.finish(&mut later, Observation::Value(21)).unwrap();
    let (_, payload) = t.finish(&mut outer, Observation::Value(13)).unwrap();
    assert_eq!(payload.outcome, completed(13, 2));
    new.close();
    assert_eq!(observed(&[&old, &new]), ledger(&[
        expected_row(old.generation(), 0, A, 10, Some(retained(0, 0)), Some((1, 0, completed(13, 2)))),
        expected_row(old.generation(), 1, B, 11, Some(retained(1, 0)), Some((1, 0, completed(12, 0)))),
        expected_row(new.generation(), 0, B, 20, Some(retained(0, 0)), Some((1, 1, completed(21, 0)))),
    ]));
    assert_eq!(old.try_report().unwrap().records().count(), 2);
    assert_eq!(new.try_report().unwrap().records().count(), 1);
    assert_eq!([outer, inner, later], [slot(1), slot(2), slot(3)]);
    assert_eq!(t.completed_sequence(), 3);
}

#[test]
fn g04_stale_disable_cannot_mutate_new_generation() {
    let (s, old, mut t) = setup(1, 2, 4);
    let mut rs = slot(1); t.enter(INSTALL, A, 10, &mut rs).unwrap();
    let request = t.finish(&mut rs, Observation::Value(20)).unwrap().0.deactivate.unwrap();
    let new = s.stage(config(1, 2, 4)).unwrap(); s.publish(&new, FailurePoint::None).unwrap();
    s.deactivate(request, FailurePoint::AfterMutation).unwrap();
    let snap = s.snapshot().unwrap();
    assert_eq!(snap.enabled, vec![true, true]);
    assert_eq!(snap.status, ControllerStatus::Ready);
    assert_eq!(snap.actions, vec![
        action(ActionKind::Published, old.generation(), None, Some(old.generation()), None),
        action(ActionKind::Published, new.generation(), None, Some(new.generation()), None),
        action(ActionKind::Stale, old.generation(), Some(A), Some(new.generation()), None),
    ]);
    assert_eq!(new.records().count(), 0);
}

#[test]
fn g05_acquired_owner_after_close_refuses() {
    let (s, old, mut t) = setup(2, 2, 4);
    let acquired = s.acquire(1, INSTALL).unwrap();
    let new = s.stage(config(2, 2, 4)).unwrap(); s.publish(&new, FailurePoint::None).unwrap();
    let mut rs = slot(1);
    assert_eq!(t.enter_acquired(&acquired, A, 9, &mut rs), Err(EntryError::Generation(AdmissionRefusal::EpochClosed)));
    assert_eq!(rs, slot(1)); assert_eq!(old.records().count(), 0); assert_eq!(new.records().count(), 0);
}

#[test]
fn g05_reserved_before_close_completes_to_old() {
    let (s, old, mut t) = setup(2, 2, 4);
    let acquired = s.acquire(1, INSTALL).unwrap(); let mut rs = slot(1);
    let admission = t.enter_acquired(&acquired, A, 9, &mut rs).unwrap();
    old.close();
    assert!(old.try_report().is_none());
    let (c, _) = t.finish(&mut rs, Observation::Unavailable(77)).unwrap();
    assert_eq!(c.admission, admission);
    assert_eq!(old.try_report().unwrap().records().next().unwrap().payload.unwrap().outcome,
        PayloadOutcome::Completed { end: Observation::Unavailable(77), completed_children: 0 });
}

#[test]
fn g05_install_and_foreign_handle_refuse_without_slot_change() {
    let (s, e, mut t) = setup(2, 2, 4);
    let mut rs = slot(1);
    assert_eq!(t.enter(INSTALL + 1, A, 1, &mut rs), Err(EntryError::WrongInstall));
    let (_other, _oe, mut ot) = setup(2, 2, 4);
    let h = s.acquire(1, INSTALL).unwrap();
    assert_eq!(ot.enter_acquired(&h, A, 2, &mut rs), Err(EntryError::ForeignHandle));
    let other_thread = s.register_thread(2).unwrap();
    let h2 = s.acquire(other_thread.identity(), INSTALL).unwrap();
    assert_eq!(t.enter_acquired(&h2, A, 3, &mut rs), Err(EntryError::ForeignHandle));
    assert_eq!(rs, slot(1)); assert_eq!(e.records().count(), 0);
}

#[test]
fn g06_kth_gap_keeps_seven_terminals_and_one_other() {
    let (s, e, mut first) = setup(1, 2, 8);
    let mut second = s.register_thread(2).unwrap();
    let mut a = slot(1); first.enter(INSTALL, A, 1, &mut a).unwrap();
    let (paused_tx, paused_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        let worker = scope.spawn(move || first.finish_inner(&mut a, Observation::Value(10), || {}, || {
            paused_tx.send(()).unwrap(); release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        }).unwrap());
        paused_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        for i in 2..=6 {
            let mut rs = slot(i); second.enter(INSTALL, A, i, &mut rs).unwrap();
            assert_eq!(second.finish(&mut rs, Observation::Value(i * 10)).unwrap().0.disposition,
                Disposition::DroppedAfterBudget);
        }
        let mut held = slot(7); second.enter(INSTALL, A, 7, &mut held).unwrap();
        release_tx.send(()).unwrap();
        let (winner, _) = worker.join().unwrap();
        assert_eq!(winner.other_reservations_after_close, Some(1));
        assert_eq!(winner.disposition, Disposition::Retained { rank: 0 });
        assert_eq!(e.reservations(), 1);
        second.finish(&mut held, Observation::Value(70)).unwrap();
    });
    e.close();
    assert_eq!(e.population(A).unwrap().population, Population { admitted: 7, completed: 7,
        retained: 1, dropped: 6, ..Population::default() });
    let mut expected = vec![expected_row(e.generation(), 0, A, 1, Some(retained(0, 0)), Some((1, 0, completed(10, 0))))];
    for i in 1..7 { expected.push(expected_row(e.generation(), i, A, i as u64 + 1,
        Some(dropped(i as u64)), Some((2, i as u64 - 1, completed((i as u64 + 1) * 10, 0))))); }
    assert_eq!(observed(&[&e]), ledger(&expected));
}

#[test]
fn g07_sixteen_payloads_visible_after_drain_before_join() {
    let (_s, e, mut t) = setup(16, 16, 16);
    let mut slots = (0..16).map(slot).collect::<Vec<_>>();
    for (i, rs) in slots.iter_mut().enumerate() { t.enter(INSTALL, A, i as u64, rs).unwrap(); }
    assert_eq!(e.close(), 16);
    let (release_tx, release_rx) = mpsc::channel();
    std::thread::scope(|scope| {
        let worker = scope.spawn(move || {
            for i in (0..16).rev() { t.finish(&mut slots[i], Observation::Value(i as u64 ^ 0xfedc_ba98)).unwrap(); }
            release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            assert_eq!(slots, (0..16).map(slot).collect::<Vec<_>>());
        });
        let report = report_bounded(&e);
        let expected = (0..16).map(|i| expected_row(e.generation(), i, A, i as u64,
            Some(retained(i as u64, 15 - i)), Some((1, 0, completed(i as u64 ^ 0xfedc_ba98, (15 - i) as u64)))))
            .collect::<Vec<_>>();
        assert_eq!(report.records().collect::<Vec<_>>(), expected);
        assert_eq!(expected.len(), 16);
        release_tx.send(()).unwrap(); worker.join().unwrap();
        assert_eq!(report.records().collect::<Vec<_>>(), expected);
    });
}

#[test]
fn g07_payload_before_release_pause_blocks_drain() {
    let (_s, e, mut t) = setup(1, 1, 1); let mut rs = slot(1);
    t.enter(INSTALL, A, 3, &mut rs).unwrap(); e.close();
    let (paused_tx, paused_rx) = mpsc::sync_channel(1);
    let (resume_tx, resume_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::channel();
    std::thread::scope(|scope| {
        let worker = scope.spawn(move || {
            t.finish_inner(&mut rs, Observation::Value(5), || {
                paused_tx.send(()).unwrap(); resume_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            }, || {}).unwrap();
            release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        });
        paused_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(e.try_report().is_none()); assert_eq!(e.reservations(), 1);
        assert_eq!(e.records().collect::<Vec<_>>(), vec![expected_row(e.generation(), 0, A, 3,
            None, Some((1, 0, completed(5, 0))))]);
        resume_tx.send(()).unwrap();
        let report = report_bounded(&e);
        assert_eq!(report.records().collect::<Vec<_>>(), vec![expected_row(e.generation(), 0, A, 3,
            Some(retained(0, 0)), Some((1, 0, completed(5, 0))))]);
        release_tx.send(()).unwrap(); worker.join().unwrap();
    });
}

#[test]
fn g08_explicit_cancel_and_drop_publish_distinct_payloads_first() {
    let (_s, e, mut t) = setup(1, 2, 4);
    let mut a = slot(1); t.enter(INSTALL, A, 1, &mut a).unwrap(); t.cancel(&mut a).unwrap();
    let mut b = slot(2); t.enter(INSTALL, A, 2, &mut b).unwrap(); drop(t);
    assert_eq!(a, slot(1)); assert_eq!(b.word, MODEL_CONTINUATION); // Drop claims no slot restoration.
    e.close();
    assert_eq!(observed(&[&e]), ledger(&[
        expected_row(e.generation(), 0, A, 1, Some(Terminal::Cancelled(CancelReason::Explicit)),
            Some((1, 0, PayloadOutcome::Cancelled(CancelReason::Explicit)))),
        expected_row(e.generation(), 1, A, 2, Some(Terminal::Cancelled(CancelReason::DroppedTicket)),
            Some((1, 0, PayloadOutcome::Cancelled(CancelReason::DroppedTicket)))),
    ]));
    assert_eq!(e.population(A).unwrap().population, Population { admitted: 2, cancelled: 2, ..Population::default() });
    assert_eq!(e.owner.epoch.function_closed(A), Some(false));
}

#[test]
fn g08_forgotten_complete_frame_retains_reservation_and_permit() {
    let s = session_with(Limits { epochs: 1, ..limits() }, false, false);
    let e = s.stage(config(2, 2, 4)).unwrap(); s.publish(&e, FailurePoint::None).unwrap();
    let mut t = s.register_thread(1).unwrap(); let mut rs = slot(1);
    t.enter(INSTALL, A, 1, &mut rs).unwrap();
    let weak = Arc::downgrade(&e.owner); s.remove_current().unwrap();
    let frame = t.frames.pop().unwrap(); std::mem::forget(frame); // privileged model calibration only
    assert!(e.try_report().is_none()); assert_eq!(e.reservations(), 1);
    drop(e); drop(t);
    assert!(weak.upgrade().is_some()); assert_eq!(s.retained_epochs(), 1);
    assert_eq!(s.stage(config(2, 2, 4)).err(), Some(SetupError::EpochLimit));
}

#[test]
fn g08_standalone_owned_ticket_has_no_frontend_permit_claim() {
    let s = session_with(Limits { epochs: 1, ..limits() }, false, false);
    let plain = Arc::new(Epoch::new(&[A], config(1, 1, 1)).unwrap());
    let weak = Arc::downgrade(&plain); let ticket = plain.enter_owned(A, 1).unwrap();
    plain.close(); drop(plain); std::mem::forget(ticket);
    assert!(weak.upgrade().is_some()); assert_eq!(s.retained_epochs(), 0);
    let frontend = s.stage(config(1, 1, 1)).unwrap();
    assert_eq!(s.retained_epochs(), 1); drop(frontend); assert_eq!(s.retained_epochs(), 0);
}

#[test]
fn g09_a_storage_exhaustion_preserves_records_and_slot() {
    let (_s, e, mut t) = setup(8, 4, 1);
    let mut rs = slot(1); t.enter(INSTALL, A, 1, &mut rs).unwrap(); t.finish(&mut rs, Observation::Value(2)).unwrap();
    let before = observed(&[&e]);
    assert_eq!(t.enter(INSTALL, B, 3, &mut rs), Err(EntryError::Generation(AdmissionRefusal::StorageExhausted)));
    assert_eq!(observed(&[&e]), before); assert_eq!(rs, slot(1));
    assert!(e.try_report().is_some());
}

#[test]
fn g09_m_reservation_exhaustion_preserves_records_and_slot() {
    let (_s, e, mut t) = setup(8, 1, 4);
    let mut a = slot(1); let mut b = slot(2); t.enter(INSTALL, A, 1, &mut a).unwrap();
    let before = observed(&[&e]);
    assert_eq!(t.enter(INSTALL, B, 2, &mut b), Err(EntryError::Generation(AdmissionRefusal::InflightLimit)));
    assert_eq!(observed(&[&e]), before); assert_eq!(b, slot(2));
    t.cancel(&mut a).unwrap(); e.close(); assert!(e.try_report().is_some());
}

#[test]
fn g09_t_registration_limit_and_duplicate_are_exact() {
    let s = session_with(Limits { threads: 1, ..limits() }, false, false);
    let first = s.register_thread(1).unwrap();
    assert_eq!(s.register_thread(1).err(), Some(SetupError::DuplicateThread));
    assert_eq!(s.register_thread(2).err(), Some(SetupError::ThreadLimit));
    drop(first); // T is lifetime registration capacity, not a reusable thread ID pool.
    assert_eq!(s.register_thread(2).err(), Some(SetupError::ThreadLimit));
    assert_eq!(s.inner.registry.lock().unwrap().threads, vec![1]);
}

#[test]
fn g09_d_frame_limit_preserves_owned_frame_and_slot() {
    let s = session_with(Limits { depth: 1, ..limits() }, false, false);
    let e = s.stage(config(4, 4, 4)).unwrap(); s.publish(&e, FailurePoint::None).unwrap();
    let mut t = s.register_thread(1).unwrap(); let mut a = slot(1); let mut b = slot(2);
    t.enter(INSTALL, A, 1, &mut a).unwrap(); let before = observed(&[&e]);
    assert_eq!(t.enter(INSTALL, B, 2, &mut b), Err(EntryError::Depth));
    assert_eq!(observed(&[&e]), before); assert_eq!(b, slot(2)); assert_eq!(t.depth(), 1);
    t.finish(&mut a, Observation::Value(3)).unwrap(); assert_eq!(a, slot(1));
}

#[test]
fn g09_e_handles_reports_final_owner_and_forgotten_owners() {
    for forget in [false, true] {
        for report in [false, true] {
            let s = session_with(Limits { epochs: 1, ..limits() }, false, false);
            let e = s.stage(config(1, 1, 1)).unwrap(); s.publish(&e, FailurePoint::None).unwrap();
            let _t = s.register_thread(1).unwrap();
            let handle = s.acquire(1, INSTALL).unwrap(); s.remove_current().unwrap();
            let final_report = e.try_report().unwrap();
            drop(e); assert_eq!(s.retained_epochs(), 1);
            if report {
                drop(handle);
                if forget { std::mem::forget(final_report); } else {
                    assert_eq!(s.stage(config(1, 1, 1)).err(), Some(SetupError::EpochLimit));
                    drop(final_report);
                }
            } else {
                drop(final_report);
                if forget { std::mem::forget(handle); } else {
                    assert_eq!(s.stage(config(1, 1, 1)).err(), Some(SetupError::EpochLimit));
                    drop(handle);
                }
            }
            if forget { assert_eq!(s.retained_epochs(), 1); assert_eq!(s.stage(config(1, 1, 1)).err(), Some(SetupError::EpochLimit)); }
            else { assert_eq!(s.retained_epochs(), 0); drop(s.stage(config(1, 1, 1)).unwrap()); assert_eq!(s.retained_epochs(), 0); }
        }
    }
}

#[test]
fn g09_constructor_bounds_and_failed_stage_release_permit() {
    let base = limits();
    let invalid = [Limits { epochs: 0, ..base }, Limits { epochs: 9, ..base },
        Limits { threads: 0, ..base }, Limits { threads: 9, ..base },
        Limits { depth: 0, ..base }, Limits { depth: 33, ..base },
        Limits { records_per_epoch: 0, ..base }, Limits { records_per_epoch: 4097, ..base },
        Limits { actions: 0, ..base }, Limits { actions: 257, ..base },
        Limits { epochs: 8, records_per_epoch: 4096, ..base }];
    let fs = [FunctionSpec { function: A, group: 0 }]; let gs = [GroupSpec { mandatory: false }];
    let mut refusals = 0;
    for bounds in invalid {
        assert_eq!(Session::new(INSTALL, &fs, &gs, bounds).err(), Some(SetupError::InvalidLimits)); refusals += 1;
    }
    for (install, functions, groups, expected) in [
        (0, fs.to_vec(), gs.to_vec(), SetupError::InvalidLimits),
        (INSTALL, fs.to_vec(), vec![], SetupError::InvalidLimits),
        (INSTALL, vec![FunctionSpec { function: A, group: 1 }], gs.to_vec(), SetupError::InvalidLimits),
        (INSTALL, fs.to_vec(), vec![gs[0], gs[0]], SetupError::InvalidLimits),
        (INSTALL, vec![fs[0], fs[0]], gs.to_vec(), SetupError::InvalidFunctions),
        (INSTALL, vec![], gs.to_vec(), SetupError::InvalidFunctions),
        (INSTALL, vec![fs[0]; 17], gs.to_vec(), SetupError::InvalidFunctions),
    ] { assert_eq!(Session::new(install, &functions, &groups, base).err(), Some(expected)); refusals += 1; }
    let s = session_with(base, false, false);
    assert_eq!(s.stage(config(1, 1, base.records_per_epoch + 1)).err(), Some(SetupError::InvalidLimits)); refusals += 1;
    assert_eq!(s.stage(config(0, 1, 1)).err(), Some(SetupError::Generation(CreateError::ZeroRetainedBudget))); refusals += 1;
    assert_eq!(refusals, 20); assert_eq!(s.retained_epochs(), 0);
    drop(s.stage(config(1, 1, 1)).unwrap()); assert_eq!(s.retained_epochs(), 0);
}

#[test]
fn g10_registry_contention_refuses_before_slot_mutation() {
    let (s, e, mut t) = setup(1, 1, 1); let mut rs = slot(1);
    let guard = s.inner.registry.lock().unwrap();
    assert_eq!(t.enter(INSTALL, A, 1, &mut rs), Err(EntryError::RegistryBusy));
    assert_eq!(rs, slot(1)); assert_eq!(e.records().count(), 0); drop(guard);
    t.enter(INSTALL, A, 1, &mut rs).unwrap(); t.cancel(&mut rs).unwrap();
}

#[test]
fn g10_registry_poison_refuses_before_slot_mutation() {
    let (s, e, mut t) = setup(1, 1, 1); let mut rs = slot(1);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = s.inner.registry.lock().unwrap(); panic!("required registry poison calibration");
    }));
    assert!(result.is_err());
    assert_eq!(t.enter(INSTALL, A, 1, &mut rs), Err(EntryError::RegistryPoisoned));
    assert_eq!(rs, slot(1)); assert_eq!(e.records().count(), 0);
}

#[test]
fn g10_unregistered_thread_and_empty_binding_are_explicit() {
    let (s, e, _t) = setup(1, 1, 1);
    assert_eq!(s.acquire(99, INSTALL).err(), Some(EntryError::UnknownThread));
    s.remove_current().unwrap();
    assert_eq!(s.acquire(1, INSTALL).err(), Some(EntryError::NoCurrent));
    assert_eq!(e.records().count(), 0);
}

#[test]
fn g10_reentry_and_duplicate_slot_preserve_existing_frames() {
    let (_s, e, mut t) = setup(4, 4, 4); let mut rs = slot(1);
    t.in_callback = true;
    assert_eq!(t.enter(INSTALL, A, 1, &mut rs), Err(EntryError::Reentry));
    assert_eq!(rs, slot(1)); assert_eq!(e.records().count(), 0); t.in_callback = false;
    t.enter(INSTALL, A, 2, &mut rs).unwrap(); let before = observed(&[&e]);
    let mut duplicate = slot(1);
    assert_eq!(t.enter(INSTALL, B, 3, &mut duplicate), Err(EntryError::SlotInUse));
    assert_eq!(observed(&[&e]), before); assert_eq!(duplicate, slot(1));
    let mut wrong = slot(99);
    assert_eq!(t.finish(&mut wrong, Observation::Value(4)), Err(ExitError::SlotMismatch));
    assert_eq!(observed(&[&e]), before); assert_eq!(t.depth(), 1);
    t.finish(&mut rs, Observation::Value(5)).unwrap(); assert_eq!(rs, slot(1));
    assert_eq!(t.finish(&mut rs, Observation::Value(6)), Err(ExitError::Empty));
}

#[test]
fn g10_nonwrapping_sequences_refuse_and_remain_terminal() {
    for attempts in [false, true] {
        let (_s, e, mut t) = setup(1, 1, 1); let mut rs = slot(1);
        if attempts { t.attempts = u64::MAX; } else { t.completed_sequence = u64::MAX; }
        assert_eq!(t.enter(INSTALL, A, 1, &mut rs), Err(EntryError::CounterExhausted));
        assert_eq!(t.enter(INSTALL, A, 2, &mut rs), Err(EntryError::CounterExhausted));
        assert!(t.exhausted); assert_eq!(rs, slot(1)); assert_eq!(e.records().count(), 0);
    }
}

#[test]
fn g11_shared_group_keeps_b_then_disables_after_b_closes() {
    let s = session_with(limits(), true, false); let e = s.stage(config(1, 2, 4)).unwrap();
    s.publish(&e, FailurePoint::None).unwrap(); let mut t = s.register_thread(1).unwrap();
    let mut rs = slot(1);
    t.enter(INSTALL, A, 1, &mut rs).unwrap();
    let request_a = t.finish(&mut rs, Observation::Value(2)).unwrap().0.deactivate.unwrap();
    s.deactivate(request_a, FailurePoint::None).unwrap(); assert_eq!(s.snapshot().unwrap().enabled, vec![true]);
    t.enter(INSTALL, B, 3, &mut rs).unwrap();
    let request_b = t.finish(&mut rs, Observation::Value(4)).unwrap().0.deactivate.unwrap();
    s.deactivate(request_b, FailurePoint::None).unwrap();
    let snap = s.snapshot().unwrap(); assert_eq!(snap.enabled, vec![false]);
    assert_eq!(snap.actions, vec![
        action(ActionKind::Published, e.generation(), None, Some(e.generation()), None),
        action(ActionKind::Deferred, e.generation(), Some(A), Some(e.generation()), Some(0)),
        action(ActionKind::Disabled, e.generation(), Some(B), Some(e.generation()), Some(0)),
    ]);
    assert_eq!(e.population(A).unwrap().population.retained, 1);
    assert_eq!(e.population(B).unwrap().population.retained, 1);
}

#[test]
fn g11_mandatory_action_remains_after_all_profiling_functions_close() {
    let s = session_with(limits(), true, true); let e = s.stage(config(1, 2, 4)).unwrap();
    s.publish(&e, FailurePoint::None).unwrap(); let mut t = s.register_thread(1).unwrap();
    for f in [A, B] {
        let mut rs = slot(f.0); t.enter(INSTALL, f, 1, &mut rs).unwrap();
        let request = t.finish(&mut rs, Observation::Value(2)).unwrap().0.deactivate.unwrap();
        s.deactivate(request, FailurePoint::None).unwrap();
    }
    assert_eq!(s.snapshot().unwrap().enabled, vec![true]);
    assert_eq!(s.snapshot().unwrap().actions.iter().map(|a| a.kind).collect::<Vec<_>>(),
        vec![ActionKind::Published, ActionKind::Deferred, ActionKind::Deferred]);
    assert_eq!(e.records().count(), 2);
}

#[test]
fn g12_before_mutation_failures_keep_binding_and_group_state() {
    let (s, old, mut t) = setup(1, 2, 4); let next = s.stage(config(1, 2, 4)).unwrap();
    assert_eq!(s.publish(&next, FailurePoint::BeforeMutation), Err(ControlError::InjectedBefore));
    assert_eq!(s.acquire(1, INSTALL).unwrap().generation(), old.generation());
    assert!(!old.owner.epoch.is_closed()); assert_eq!(next.records().count(), 0);
    let mut rs = slot(1); t.enter(INSTALL, A, 1, &mut rs).unwrap();
    let request = t.finish(&mut rs, Observation::Value(2)).unwrap().0.deactivate.unwrap();
    assert_eq!(s.deactivate(request, FailurePoint::BeforeMutation), Err(ControlError::InjectedBefore));
    let snap = s.snapshot().unwrap(); assert_eq!(snap.status, ControllerStatus::Ready);
    assert_eq!(snap.enabled, vec![true, true]); assert_eq!(snap.retained_failed_generation, None);
    assert_eq!(snap.actions, vec![
        action(ActionKind::Published, old.generation(), None, Some(old.generation()), None),
        action(ActionKind::FailedBefore, next.generation(), None, Some(old.generation()), None),
        action(ActionKind::FailedBefore, old.generation(), Some(A), Some(old.generation()), Some(0)),
    ]);
}

#[test]
fn g12_after_mutation_failures_retain_owner_and_refuse_retry() {
    for publication in [false, true] {
        let (s, e, mut t) = setup(1, 2, 4); let mut rs = slot(1);
        t.enter(INSTALL, A, 1, &mut rs).unwrap();
        let request = t.finish(&mut rs, Observation::Value(2)).unwrap().0.deactivate.unwrap();
        let target = if publication {
            let next = s.stage(config(1, 2, 4)).unwrap();
            assert_eq!(s.publish(&next, FailurePoint::AfterMutation), Err(ControlError::InjectedAfter)); next
        } else {
            assert_eq!(s.deactivate(request, FailurePoint::AfterMutation), Err(ControlError::InjectedAfter)); e.clone()
        };
        let id = target.generation(); let weak = Arc::downgrade(&target.owner);
        let snap = s.snapshot().unwrap(); assert_eq!(snap.status, ControllerStatus::TerminalFailure);
        assert_eq!(snap.retained_failed_generation, Some(id));
        assert_eq!(snap.enabled, if publication { vec![true, true] } else { vec![false, true] });
        assert_eq!(snap.actions.last().unwrap().kind, ActionKind::FailedAfter);
        assert_eq!(s.deactivate(request, FailurePoint::None), Err(ControlError::TerminalFailure));
        assert_eq!(s.publish(&target, FailurePoint::None), Err(ControlError::TerminalFailure));
        assert_eq!(s.remove_current(), Err(ControlError::TerminalFailure));
        assert_eq!(s.snapshot().unwrap(), snap);
        assert_eq!(t.enter(INSTALL, B, 3, &mut rs), Err(EntryError::Generation(AdmissionRefusal::EpochClosed)));
        drop(target); drop(e); drop(t); assert!(weak.upgrade().is_some());
        drop(s); assert!(weak.upgrade().is_none()); // metadata model only: no executable mapping exists
    }
}

#[test]
fn g12_history_exhaustion_refuses_before_any_controller_mutation() {
    let s = session_with(Limits { actions: 1, ..limits() }, false, false);
    let e = s.stage(config(1, 2, 4)).unwrap(); s.publish(&e, FailurePoint::None).unwrap();
    let mut t = s.register_thread(1).unwrap(); let mut rs = slot(1);
    t.enter(INSTALL, A, 1, &mut rs).unwrap();
    let request = t.finish(&mut rs, Observation::Value(2)).unwrap().0.deactivate.unwrap();
    let before = s.snapshot().unwrap();
    assert_eq!(s.deactivate(request, FailurePoint::None), Err(ControlError::HistoryFull));
    assert_eq!(s.scan_closed(), Err(ControlError::HistoryFull));
    assert_eq!(s.remove_current(), Err(ControlError::HistoryFull));
    assert_eq!(s.snapshot().unwrap(), before);
    assert_eq!(s.acquire(1, INSTALL).unwrap().generation(), e.generation());
}

#[test]
fn g12_bounded_scan_recovers_closed_actions_without_notification_queue() {
    let (s, e, mut t) = setup(1, 2, 4); let mut rs = slot(1);
    t.enter(INSTALL, A, 1, &mut rs).unwrap(); t.finish(&mut rs, Observation::Value(2)).unwrap();
    assert_eq!(s.scan_closed(), Ok(1));
    assert_eq!(s.snapshot().unwrap().enabled, vec![false, true]);
    assert_eq!(s.snapshot().unwrap().actions, vec![
        action(ActionKind::Published, e.generation(), None, Some(e.generation()), None),
        action(ActionKind::Disabled, e.generation(), Some(A), Some(e.generation()), Some(0)),
    ]);
    let next = s.stage(config(1, 2, 4)).unwrap(); next.close();
    let before = s.snapshot().unwrap();
    assert_eq!(s.publish(&next, FailurePoint::None), Err(ControlError::ClosedEpoch));
    assert_eq!(s.snapshot().unwrap(), before);
}

#[test]
fn reference_ledger_rejects_eight_identity_payload_action_mutations() {
    let (_s, e, _t) = setup(1, 1, 1);
    let expected = ledger(&[expected_row(e.generation(), 0, A, 7, Some(retained(0, 0)), Some((1, 0, completed(9, 0))))]);
    let expected_action = action(ActionKind::Disabled, e.generation(), Some(A), Some(e.generation()), Some(0));
    let row = *expected.values().next().unwrap();
    let mut mutants = Vec::new();
    for edit in 0..6 {
        let mut m = row;
        match edit {
            0 => m.record.admission.invocation = 1,
            1 => m.record.admission.function = B,
            2 => m.record.terminal = Some(dropped(0)),
            3 => m.payload.as_mut().unwrap().thread = 2,
            4 => m.payload.as_mut().unwrap().start_sequence = 1,
            5 => m.payload.as_mut().unwrap().outcome = completed(10, 0),
            _ => unreachable!(),
        }
        mutants.push(ledger(&[m]));
    }
    for m in &mutants { assert_ne!(m, &expected); }
    let mut wrong_kind = expected_action; wrong_kind.kind = ActionKind::Deferred;
    let mut wrong_generation = expected_action; wrong_generation.current = None;
    assert_ne!(wrong_kind, expected_action); assert_ne!(wrong_generation, expected_action);
    assert_eq!(mutants.len() + 2, 8);
    assert_eq!(ledger(&[row]), expected);
    assert_eq!(action(ActionKind::Disabled, e.generation(), Some(A), Some(e.generation()), Some(0)), expected_action);
}
