//! Metadata controls only. Synthetic sites never grant native installation authority.
use super::*;
use crate::frontend::{EntryError, PayloadOutcome};
use crate::generation::AdmissionRefusal;

mod concurrent;

const FUNCTION: FunctionId = FunctionId(11);
fn limits() -> Limits {
    Limits {
        epochs: 4,
        threads: 3,
        depth: 4,
        records_per_epoch: 16,
        actions: 32,
    }
}
fn config(k: usize) -> Config {
    Config {
        retained_per_function: k,
        max_inflight: 8,
        max_invocations: 16,
    }
}
fn prepared(limits: Limits) -> PreparedIntervalController {
    PreparedIntervalController::new(site::synthetic_site(), 71, FUNCTION, limits).unwrap()
}
fn activate(p: PreparedIntervalController) -> (IntervalController, IntervalClient) {
    // SAFETY: synthetic metadata only, on this test thread; no fork/native publication.
    unsafe { p.activate() }.unwrap()
}
fn state(client: &IntervalClient) -> State {
    let model = client.binding.session.register_thread(1).unwrap();
    let mut journal = IntervalJournal::allocate();
    journal.header(7, 0);
    State {
        binding: Arc::clone(&client.binding),
        actual_thread: thread::current().id(),
        tid: 7,
        registration: 1,
        stack: ReadableStack {
            start: 0x7000,
            end: 0x9000,
        },
        model,
        pairs: std::array::from_fn(|_| None),
        depth: 0,
        next: 1,
        totals: PairTotals::default(),
        journal,
        failure: None,
        timing: None,
    }
}
fn enter(s: &mut State, rsp: u64) {
    s.enter(0x1000, rsp, 0x2005).unwrap();
}
fn finish(s: &mut State, rsp: u64) {
    s.finish(0x1012, rsp, 0x2005).unwrap();
}
fn row(s: &State, n: usize) -> [u64; 7] {
    s.journal.page.0[4 + n * 7..4 + (n + 1) * 7]
        .try_into()
        .unwrap()
}
fn records(c: &IntervalController, e: &IntervalEpoch) -> Vec<crate::frontend::RecordObservation> {
    c.report(e).unwrap().unwrap().records().collect()
}

#[test]
fn initial_off_pair_keeps_initial_stamp_across_real_publication() {
    let mut p = prepared(limits());
    let e = p.stage(config(2)).unwrap();
    let (mut c, client) = activate(p);
    let mut s = state(&client);
    enter(&mut s, 0x8000);
    assert_eq!(s.model.depth(), 0);
    c.arm(&e).unwrap();
    finish(&mut s, 0x8000);
    assert_eq!(row(&s, 0), [3, 1, 4096, 32768, 8197, 0, 4194304]);
    assert_eq!(row(&s, 1), [4, 1, 4114, 32768, 8197, 0, 4194304]);
    assert_eq!(s.model.completed_sequence(), 0);
    enter(&mut s, 0x8000);
    finish(&mut s, 0x8000);
    c.disarm(&e).unwrap();
    assert_eq!(records(&c, &e).len(), 1);
    assert_eq!(
        s.totals,
        PairTotals {
            entries: 2,
            returns: 2,
            completed: 1,
            unsampled: 1
        }
    );
    assert_eq!(row(&s, 2)[6], 8193);
}
#[test]
fn admitted_removed_new_mixed_lifo_retains_exact_original_owner() {
    let mut p = prepared(limits());
    let old = p.stage(config(4)).unwrap();
    let new = p.stage(config(4)).unwrap();
    let (mut c, client) = activate(p);
    let mut s = state(&client);
    c.arm(&old).unwrap();
    enter(&mut s, 0x8000);
    c.disarm(&old).unwrap();
    enter(&mut s, 0x7ff0);
    c.arm(&new).unwrap();
    enter(&mut s, 0x7fe0);
    assert_eq!((s.depth, s.model.depth()), (3, 2));
    assert!(c.report(&old).unwrap().is_none());
    finish(&mut s, 0x7fe0);
    finish(&mut s, 0x7ff0);
    finish(&mut s, 0x8000);
    c.disarm(&new).unwrap();
    assert_eq!(
        s.totals,
        PairTotals {
            entries: 3,
            returns: 3,
            completed: 2,
            unsampled: 1
        }
    );
    assert_eq!(
        (s.depth, s.model.depth(), s.model.completed_sequence()),
        (0, 0, 2)
    );
    assert_eq!(row(&s, 0)[5..], [old.generation().get(), 8193]);
    assert_eq!(row(&s, 1)[5..], [old.generation().get(), 8404992]);
    assert_eq!(row(&s, 2)[5..], [new.generation().get(), 24577]);
    assert_eq!(row(&s, 3)[5..], row(&s, 2)[5..]);
    assert_eq!(row(&s, 4)[5..], row(&s, 1)[5..]);
    assert_eq!(row(&s, 5)[5..], row(&s, 0)[5..]);
    assert!(matches!(
        records(&c, &old)[0].payload.unwrap().outcome,
        PayloadOutcome::Completed {
            completed_children: 1,
            end: Observation::Value(1)
        }
    ));
}
#[test]
fn closed_function_pair_is_unsampled_and_keeps_old_report_unchanged() {
    let mut p = prepared(limits());
    let old = p.stage(config(1)).unwrap();
    let new = p.stage(config(2)).unwrap();
    let (mut c, client) = activate(p);
    let mut s = state(&client);
    c.arm(&old).unwrap();
    enter(&mut s, 0x8000);
    finish(&mut s, 0x8000);
    enter(&mut s, 0x8000);
    assert_eq!(s.model.depth(), 0);
    c.arm(&new).unwrap();
    let retained = c.report(&old).unwrap().unwrap();
    let before: Vec<_> = retained.records().collect();
    finish(&mut s, 0x8000);
    assert_eq!(s.model.completed_sequence(), 1);
    assert_eq!(row(&s, 2)[5..], [old.generation().get(), 12591104]);
    assert_eq!(row(&s, 3)[5..], row(&s, 2)[5..]);
    enter(&mut s, 0x8000);
    finish(&mut s, 0x8000);
    c.disarm(&new).unwrap();
    assert_eq!(retained.generation(), old.generation());
    assert_eq!(retained.records().collect::<Vec<_>>(), before);
    assert_eq!(
        c.report(&old).unwrap().unwrap().generation(),
        old.generation()
    );
    assert_eq!(records(&c, &old), before);
    assert_eq!(
        s.totals,
        PairTotals {
            entries: 3,
            returns: 3,
            completed: 2,
            unsampled: 1
        }
    );
}
#[test]
fn old_admission_blocks_report_until_its_own_ret_after_new_arm() {
    let mut p = prepared(limits());
    let old = p.stage(config(2)).unwrap();
    let new = p.stage(config(2)).unwrap();
    let (mut c, client) = activate(p);
    let mut s = state(&client);
    c.arm(&old).unwrap();
    enter(&mut s, 0x8000);
    c.arm(&new).unwrap();
    assert!(c.report(&old).unwrap().is_none());
    finish(&mut s, 0x8000);
    let retained = c.report(&old).unwrap().unwrap();
    let before: Vec<_> = retained.records().collect();
    enter(&mut s, 0x8000);
    finish(&mut s, 0x8000);
    c.disarm(&new).unwrap();
    assert_eq!(retained.generation(), old.generation());
    assert_eq!(retained.records().collect::<Vec<_>>(), before);
    assert_eq!(records(&c, &old), before);
    assert_eq!(records(&c, &new)[0].record.admission.invocation, 0);
    assert_eq!(row(&s, 2)[6], 16385);
}
#[test]
fn journal_preserves_entire_page_literal_header_rows_and_zero_tail() {
    let (_c, client) = activate(prepared(limits()));
    let mut s = state(&client);
    enter(&mut s, 0x8000);
    finish(&mut s, 0x8000);
    let mut expected = [0u64; 512];
    expected[..4].copy_from_slice(&[2, 0, 7, 0]);
    expected[4..11].copy_from_slice(&[3, 1, 4096, 32768, 8197, 0, 4194304]);
    expected[11..18].copy_from_slice(&[4, 1, 4114, 32768, 8197, 0, 4194304]);
    assert_eq!(s.journal.page.0, expected);
    assert_eq!(std::mem::size_of::<Page>(), 4096);
    assert_eq!(s.journal.address() % 4096, 0);
}
#[test]
fn event_capacity_reserves_every_pending_exit_before_any_new_admission() {
    let mut p = prepared(limits());
    let e = p.stage(config(4)).unwrap();
    let (mut c, client) = activate(p);
    c.arm(&e).unwrap();
    let mut s = state(&client);
    enter(&mut s, 0x8000);
    // Existing row plus bounded synthetic prior rows; this isolates capacity, not native output.
    s.journal.page.0[0] = 62;
    let before = s.next;
    assert_eq!(s.enter(0x1000, 0x7ff0, 0x2005), Err(error(Cause::Capacity)));
    assert_eq!((s.next, s.depth, s.model.depth()), (before, 1, 1));
    assert_eq!(c.owner(&e).unwrap().reservations(), 1);
    finish(&mut s, 0x8000);
    assert_eq!(s.journal.used(), 63);
}
#[test]
fn mixed_pair_depth_uses_minimum_of_fixed_four_and_model_limit() {
    let mut l = limits();
    l.depth = 2;
    let (_c, client) = activate(prepared(l));
    let mut s = state(&client);
    enter(&mut s, 0x8000);
    enter(&mut s, 0x7ff0);
    assert_eq!(s.enter(0x1000, 0x7fe0, 0x2005), Err(error(Cause::Capacity)));
    assert_eq!((s.depth, s.model.depth(), s.next), (2, 0, 3));
    finish(&mut s, 0x7ff0);
    finish(&mut s, 0x8000);
}
#[test]
fn ordinal_and_totals_exhaustion_refuse_before_model_mutation() {
    let (_c, client) = activate(prepared(limits()));
    let mut s = state(&client);
    s.next = u64::MAX;
    assert_eq!(s.enter(0x1000, 0x8000, 0x2005), Err(error(Cause::Capacity)));
    assert_eq!((s.depth, s.model.depth(), s.journal.used()), (0, 0, 0));
    s.next = 1;
    s.totals.entries = u64::MAX;
    assert_eq!(s.enter(0x1000, 0x8000, 0x2005), Err(error(Cause::Capacity)));
    assert_eq!((s.depth, s.model.depth(), s.journal.used()), (0, 0, 0));
}
#[test]
fn exit_capacity_refuses_before_receipt_consumption() {
    let (_c, client) = activate(prepared(limits()));
    let mut s = state(&client);
    enter(&mut s, 0x8000);
    s.totals.returns = u64::MAX;
    assert_eq!(
        s.finish(0x1012, 0x8000, 0x2005),
        Err(error(Cause::Capacity))
    );
    assert!(s.pairs[0].as_ref().unwrap().receipt.summary().is_some());
    assert_eq!(s.depth, 1);
}
#[test]
fn non_top_rsp_and_full_return_word_refuse_without_popping() {
    let (_c, client) = activate(prepared(limits()));
    let mut s = state(&client);
    enter(&mut s, 0x8000);
    enter(&mut s, 0x7ff0);
    assert_eq!(s.finish(0x1012, 0x8000, 0x2005), Err(error(Cause::Return)));
    assert_eq!(s.finish(0x1012, 0x7ff0, 0x2004), Err(error(Cause::Return)));
    assert_eq!(s.depth, 2);
    finish(&mut s, 0x7ff0);
    finish(&mut s, 0x8000);
    assert_eq!(s.finish(0x1012, 0x8000, 0x2005), Err(error(Cause::Return)));
}
#[test]
fn foreign_pair_and_dirty_unsampled_token_retain_receipt() {
    let (_c, client) = activate(prepared(limits()));
    let mut s = state(&client);
    enter(&mut s, 0x8000);
    let key = Arc::clone(&s.pairs[0].as_ref().unwrap().key);
    s.pairs[0].as_mut().unwrap().key = Arc::new(());
    assert_eq!(s.finish(0x1012, 0x8000, 0x2005), Err(error(Cause::Return)));
    s.pairs[0].as_mut().unwrap().key = key;
    s.pairs[0].as_mut().unwrap().slot.word ^= 1;
    assert_eq!(
        s.finish(0x1012, 0x8000, 0x2005),
        Err(error(Cause::Exit(IntervalExitError::TokenMismatch)))
    );
    assert!(s.pairs[0].as_ref().unwrap().receipt.summary().is_some());
    assert_eq!(s.depth, 1);
}
#[test]
fn controller_rejects_foreign_epoch_stale_index_and_process_without_history_change() {
    let mut p = prepared(limits());
    let e = p.stage(config(2)).unwrap();
    let (mut c, client) = activate(p);
    drop(client);
    let mut other = prepared(limits());
    let foreign = other.stage(config(2)).unwrap();
    assert_eq!(c.arm(&foreign), Err(error(Cause::Epoch)));
    assert!(c.history().unwrap().actions.is_empty());
    let wrong = IntervalEpoch {
        key: Arc::clone(&e.key),
        index: 99,
        generation: e.generation,
    };
    assert_eq!(c.arm(&wrong), Err(error(Cause::Epoch)));
    // Only this test owns the Arc; no runtime PID reset API exists.
    Arc::get_mut(&mut c.binding).unwrap().pid ^= 1;
    assert_eq!(c.arm(&e), Err(error(Cause::Process)));
}
#[test]
fn stage_slots_and_old_owner_lifetime_are_never_recycled() {
    let mut l = limits();
    l.epochs = 1;
    let mut p = prepared(l);
    let e = p.stage(config(1)).unwrap();
    let (mut c, _client) = activate(p);
    c.arm(&e).unwrap();
    c.disarm(&e).unwrap();
    drop(c.report(&e).unwrap());
    drop(e);
    assert!(matches!(
        c.stage(config(1)),
        Err(BridgeError {
            cause: Cause::Capacity
        })
    ));
    assert_eq!(c.binding.session.retained_epochs(), 1);
}
#[test]
fn controller_drop_closes_present_epoch_without_disarmed_or_unsampled_relabel() {
    let mut p = prepared(limits());
    let e = p.stage(config(2)).unwrap();
    let (mut c, client) = activate(p);
    c.arm(&e).unwrap();
    let mut s = state(&client);
    drop(c);
    assert_eq!(
        s.enter(0x1000, 0x8000, 0x2005),
        Err(error(Cause::Entry(IntervalEntryError::Model(
            EntryError::Generation(AdmissionRefusal::EpochClosed)
        ))))
    );
    assert_eq!((s.depth, s.journal.used()), (0, 0));
    let history = client.binding.session.snapshot().unwrap();
    assert_eq!(history.current, Some(e.generation()));
    assert_eq!(history.actions.len(), 1);
}
#[test]
fn packed_fields_reject_overflow_or_inconsistent_binding_without_truncation() {
    let mut p = prepared(limits());
    let e = p.stage(config(2)).unwrap();
    let g = e.generation();
    let make = |inv, prefix, binding| IntervalEntrySummary::Admitted {
        generation: g,
        invocation: inv,
        history_len: prefix,
        binding,
    };
    let bind = BindingChange::Published {
        action_index: 0,
        generation: g,
    };
    assert_eq!(
        packed(make(0, 1, bind), FUNCTION).unwrap(),
        (1, g.get(), 8193)
    );
    assert_eq!(packed(make(4095, 256, bind), FUNCTION).unwrap().2, 2101248);
    assert_eq!(
        packed(make(4096, 1, bind), FUNCTION),
        Err(error(Cause::Capacity))
    );
    assert_eq!(
        packed(make(0, 257, bind), FUNCTION),
        Err(error(Cause::Capacity))
    );
    assert_eq!(
        packed(make(0, 0, bind), FUNCTION),
        Err(error(Cause::Invariant))
    );
    assert_eq!(
        packed(make(0, 1, BindingChange::Initial), FUNCTION),
        Err(error(Cause::Invariant))
    );
}
#[test]
fn attach_duplicate_preflight_does_not_consume_registration_and_empty_detach_works() {
    std::thread::spawn(|| {
        let (_c, client) = activate(prepared(limits()));
        let stack = || ReadableStack {
            start: 0x7000,
            end: 0x9000,
        };
        // SAFETY: metadata-only; no callback dereferences these synthetic addresses.
        let mut t = unsafe { client.attach(1, stack(), IntervalJournal::allocate()) }.unwrap();
        assert!(matches!(
            unsafe { client.attach(2, stack(), IntervalJournal::allocate()) },
            Err(BridgeError {
                cause: Cause::Attachment
            })
        ));
        assert_eq!(t.detach().unwrap(), PairTotals::default());
        let mut next = unsafe { client.attach(2, stack(), IntervalJournal::allocate()) }.unwrap();
        assert_eq!(next.detach().unwrap(), PairTotals::default());
    })
    .join()
    .unwrap();
}
#[test]
fn outstanding_detach_and_drop_poison_retain_tls_pairs() {
    std::thread::spawn(|| {
        let (_c, client) = activate(prepared(limits()));
        // SAFETY: metadata-only; the test calls the pair seam, never native dispatch.
        let mut t = unsafe {
            client.attach(
                1,
                ReadableStack {
                    start: 0x7000,
                    end: 0x9000,
                },
                IntervalJournal::allocate(),
            )
        }
        .unwrap();
        STATE.with(|cell| enter(cell.borrow_mut().as_mut().unwrap(), 0x8000));
        assert_eq!(t.detach(), Err(error(Cause::Outstanding)));
        assert!(t.active);
        drop(t);
        STATE.with(|cell| {
            let storage = cell.borrow();
            let s = storage.as_ref().unwrap();
            assert_eq!(s.depth, 1);
            assert!(s.pairs[0].as_ref().unwrap().receipt.summary().is_some());
            assert_eq!(s.failure, Some(error(Cause::Outstanding)));
            assert_eq!(s.journal.page.0[1], 1);
        });
        assert!(POISONED.get());
    })
    .join()
    .unwrap();
}
#[test]
fn activation_refuses_existing_tls_attachment_without_resetting_it() {
    std::thread::spawn(|| {
        let (_c, client) = activate(prepared(limits()));
        // SAFETY: metadata-only synthetic attachment, no native address access.
        let mut t = unsafe {
            client.attach(
                1,
                ReadableStack {
                    start: 0x7000,
                    end: 0x9000,
                },
                IntervalJournal::allocate(),
            )
        }
        .unwrap();
        let p = prepared(limits());
        assert!(matches!(
            unsafe { p.activate() },
            Err(BridgeError {
                cause: Cause::Attachment
            })
        ));
        assert_eq!(t.detach().unwrap(), PairTotals::default());
    })
    .join()
    .unwrap();
}
