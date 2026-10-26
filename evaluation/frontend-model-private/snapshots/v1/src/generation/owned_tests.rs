use super::*;

const A: FunctionId = FunctionId(11);
const B: FunctionId = FunctionId(29);
fn owner(k: usize, m: usize, a: usize) -> Arc<Epoch> {
    Arc::new(Epoch::new(&[A, B], Config { retained_per_function: k,
        max_inflight: m, max_invocations: a }).unwrap())
}

#[test]
fn owned_and_borrowed_records_have_exact_terminal_parity() {
    let borrowed = owner(1, 3, 4);
    let owned = owner(1, 3, 4);
    let b0 = borrowed.enter(A, 10).unwrap();
    let b1 = borrowed.enter(A, 20).unwrap();
    let b2 = borrowed.enter(B, 30).unwrap();
    let o0 = owned.enter_owned(A, 10).unwrap();
    let o1 = owned.enter_owned(A, 20).unwrap();
    let o2 = owned.enter_owned(B, 30).unwrap();
    b1.complete(21); o1.complete(21);
    b0.complete(11); o0.complete(11);
    b2.cancel(); o2.cancel();
    drop(borrowed.enter(B, 40).unwrap());
    drop(owned.enter_owned(B, 40).unwrap());
    borrowed.close(); owned.close();
    assert_ne!(borrowed.id(), owned.id());
    let expected = vec![
        (0, A, 10, Terminal::Completed { value: 11, disposition: Disposition::DroppedAfterBudget }),
        (1, A, 20, Terminal::Completed { value: 21, disposition: Disposition::Retained { rank: 0 } }),
        (2, B, 30, Terminal::Cancelled(CancelReason::Explicit)),
        (3, B, 40, Terminal::Cancelled(CancelReason::DroppedTicket)),
    ];
    for epoch in [&borrowed, &owned] {
        assert_eq!(epoch.try_drain().unwrap().records().map(|(a, t)| {
            assert_eq!(a.generation, epoch.id());
            (a.invocation, a.function, a.entry_value, t)
        }).collect::<Vec<_>>(), expected);
    }
}

#[test]
fn owned_ticket_retains_original_epoch_until_its_terminal() {
    let epoch = owner(1, 1, 1);
    let weak = Arc::downgrade(&epoch);
    let generation = epoch.id();
    let ticket = epoch.enter_owned(A, 41).unwrap();
    epoch.close();
    drop(epoch);
    assert_eq!(weak.upgrade().unwrap().reservations(), 1);
    let completion = ticket.complete(43);
    assert_eq!(completion.admission.generation, generation);
    assert_eq!(completion.disposition, Disposition::Retained { rank: 0 });
    assert!(weak.upgrade().is_none());
}

#[test]
fn owned_refusals_preserve_slots_and_original_identity() {
    let epoch = owner(2, 1, 2);
    assert_eq!(epoch.enter_owned(FunctionId(77), 9).err(), Some(AdmissionRefusal::UnknownFunction));
    let ticket = epoch.enter_owned(A, 10).unwrap();
    let before = epoch.records().collect::<Vec<_>>();
    assert_eq!(epoch.enter_owned(B, 11).err(), Some(AdmissionRefusal::InflightLimit));
    assert_eq!(epoch.records().collect::<Vec<_>>(), before);
    epoch.close();
    assert_eq!(epoch.enter_owned(B, 12).err(), Some(AdmissionRefusal::EpochClosed));
    let done = ticket.complete(13);
    assert_eq!(done.admission, before[0].admission);
    assert_eq!(epoch.try_drain().unwrap().records().count(), 1);
}

#[test]
fn owned_cancel_and_drop_keep_exact_old_epoch_after_new_creation() {
    let old = owner(2, 2, 2);
    let explicit = old.enter_owned(A, 1).unwrap();
    let dropped = old.enter_owned(B, 2).unwrap();
    old.close();
    let new = owner(2, 2, 2);
    explicit.cancel(); drop(dropped);
    assert_eq!(old.try_drain().unwrap().records().map(|(a, t)| (a.function, t)).collect::<Vec<_>>(),
        vec![(A, Terminal::Cancelled(CancelReason::Explicit)),
             (B, Terminal::Cancelled(CancelReason::DroppedTicket))]);
    assert_eq!(new.records().count(), 0);
    assert_eq!(new.reservations(), 0);
    assert_eq!(new.function_closed(A), Some(false));
}
