//! Real TLS/model metadata controls; no native execution or publication.
use super::*;
use liteinst2::contracts::{CodeIdentity, SourceIdentity};
use std::mem::MaybeUninit;

const ENTRIES: [u64; 2] = [0x1000, 0x1100];
const IDS: [FunctionId; 2] = [FunctionId(11), FunctionId(29)];
const WORDS: [u64; 4] = [0x9008, 0x9010, 0x9018, 0x9020];
struct Fixture {
    controller: EarlyEntryModuleSessionController,
    banks: Vec<IntervalEpochStorage>,
    epoch: IntervalEpoch,
}
fn with_state<T>(body: impl FnOnce(&mut NormalState, &mut PhysicalState) -> T) -> T {
    NORMAL.with(|normal| {
        PHYSICAL.with(|physical| {
            let mut normal = normal.borrow_mut();
            let mut physical = physical.borrow_mut();
            body(normal.0.as_mut().unwrap(), physical.as_mut().unwrap())
        })
    })
}
impl Fixture {
    fn new(k: usize, order: [usize; 2]) -> Self {
        assert!(!NORMAL_POISON.get());
        assert!(NORMAL.with(|c| c.borrow().0.is_none()));
        assert!(PHYSICAL.with(|c| c.borrow().is_none()));
        assert!(OBSERVER.with(|c| c.borrow().is_none()));
        let (site, writers) = site::ordinary::ModuleSite::synthetic_early(
            CodeIdentity {
                source: SourceIdentity([196; 32]),
                mapping: ENTRIES[0],
                generation: 1,
            },
            ENTRIES.map(|entry| (entry, entry + 32, vec![entry + 16, entry + 24])),
        );
        let mut p =
            PreparedEarlyEntryModuleSessionController::prepare(site, writers, 72, IDS, k).unwrap();
        let mut banks = p.prepare_epoch_storage().unwrap();
        // SAFETY: metadata only; synthetic site supplies no executable owner.
        let (mut controller, client) = unsafe { p.activate_concurrent() }.unwrap();
        let epoch = controller.stage_prepared(banks.pop().unwrap()).unwrap();
        let binding = Arc::clone(&client.shared.binding);
        let model = binding.session.register_thread(7).unwrap();
        let mut state = NormalState::new(
            binding,
            7,
            ReadableStack {
                start: 0x7000,
                end: 0x100000,
            },
            IntervalJournal::allocate(),
            model,
        );
        state.journal.header(state.tid, 0);
        let physical = PhysicalState {
            shared: client.shared,
            local: LocalState::new(order.map(|i| state.selection(i).unwrap()), WORDS),
        };
        NORMAL.with(|c| c.borrow_mut().0 = Some(Box::new(state)));
        PHYSICAL.with(|c| *c.borrow_mut() = Some(physical));
        Self {
            controller,
            banks,
            epoch,
        }
    }
    fn begin(&self) {
        with_state(|s, p| p.begin(s).unwrap());
    }
    fn visit(&self, entry: bool) {
        with_state(|s, p| {
            let b = p.active.as_ref().unwrap();
            let position = b.position;
            let selected = p.order[position % 2];
            let pc = ENTRIES[selected.index]
                + if entry {
                    0
                } else {
                    16 + (position % 2) as u64 * 8
                };
            let stamp = RawTimestamp {
                ticks: b.number * 1000 + position as u64 * 100 + u64::from(!entry) * 10,
                aux: 7,
            };
            p.visit(
                s,
                Visit {
                    selected,
                    pc,
                    rsp: 0x8008,
                    word: WORDS[position],
                    stamp,
                    entry,
                },
            )
            .unwrap();
        });
    }
    fn finish(&self) {
        with_state(|s, p| {
            let rows = p.returned(s).unwrap();
            let (out, journal) = EarlyOutput::allocate().unwrap();
            let sparse = s.transfer_into(out, journal).unwrap();
            p.complete(s, rows, sparse.as_ref()).unwrap();
        });
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        OBSERVER.with(|c| c.borrow_mut().take());
        PHYSICAL.with(|c| c.borrow_mut().take());
        // Explicit test-only teardown of nonexecuting metadata, not a native
        // detach/return acknowledgement. Drop cancels any unfinished model frame.
        NORMAL.with(|c| c.borrow_mut().0.take());
    }
}

// Literal pre-change public snapshot body, renamed only. It reads this fixture's
// actual TLS and supplies the complete old DTO, including every journal word.
fn original_snapshot() -> Result<QualificationSnapshot, BridgeError> {
    // Nested TLS closures return only status; the owned witness has one destination.
    let mut snapshot_result = Err(error(Cause::Attachment));
    NORMAL
        .try_with(|normal| {
            let storage = normal.try_borrow().map_err(|_| error(Cause::Attachment))?;
            let s = storage.0.as_ref().ok_or(error(Cause::Attachment))?;
            s.health()?;
            if s.actual_thread != thread::current().id() || s.tid != tid() {
                return Err(error(Cause::Identity));
            }
            PHYSICAL
                .try_with(|physical| {
                    let p = physical
                        .try_borrow()
                        .map_err(|_| error(Cause::Attachment))?;
                    let p = p.as_ref().ok_or(error(Cause::Attachment))?;
                    p.matches(s)?;
                    if p.active.is_some() {
                        p.shape(s)?;
                    } else {
                        drained(s)?;
                    }
                    let b = p.active.as_ref();
                    let pending = match (&s.pending, b.and_then(|b| b.pending_position)) {
                        (None, None) => None,
                        (Some(v), Some(position)) => Some(PendingSnapshot {
                            physical_batch: b.unwrap().number,
                            physical_position: position,
                            function: v.selected.function,
                            ordinal: v.ordinal,
                            entry_pc: v.entry_pc,
                            rsp: v.rsp,
                            word: v.word,
                            start: v.start,
                            summary: v.summary.map(owner_snapshot),
                            actual_summary: v.receipt.summary().map(owner_snapshot),
                            returned: v.returned,
                            slot: v.slot,
                        }),
                        _ => return Err(error(Cause::Invariant)),
                    };
                    snapshot_result = Ok(QualificationSnapshot {
                        binding_key: Arc::as_ptr(&s.binding.key) as usize,
                        pid: s.binding.pid,
                        tid: s.tid,
                        registration: s.registration,
                        completed_batches: p.batches,
                        completed_calls: p.calls,
                        active_batch: b.map(|b| b.number),
                        position: b.map(|b| b.position),
                        entry_seen: b.map_or([None; 4], |b| *b.seen),
                        pre_rets: b.map_or([None; 4], |b| *b.rows),
                        pending,
                        next_ordinal: s.next,
                        totals: s.totals,
                        interval_batch: s.cursor.number,
                        interval_cursor_totals: s.cursor.totals,
                        model_depth: s.model.depth(),
                        completed_sequence: s.model.completed_sequence(),
                        journal: s.journal.page.0,
                    });
                    Ok(())
                })
                .unwrap_or(Err(error(Cause::Attachment)))
        })
        .unwrap_or(Err(error(Cause::Attachment)))?;
    snapshot_result
}

fn compare_snapshots() -> QualificationSnapshot {
    let old = original_snapshot().unwrap();
    let mut destination = MaybeUninit::uninit();
    qualification_snapshot_into(&mut destination).unwrap();
    // SAFETY: successful helper initialized the complete destination.
    assert_eq!(unsafe { destination.assume_init_ref() }, &old);
    assert_eq!(qualification_snapshot().unwrap(), old);
    old
}
fn refusal(expected: Cause, sentinel: &QualificationSnapshot) {
    let mut destination = MaybeUninit::new(sentinel.clone());
    assert_eq!(
        qualification_snapshot_into(&mut destination),
        Err(error(expected))
    );
    // SAFETY: sentinel initialized this slot before the call; the helper only
    // writes a complete value, never a partially initialized payload.
    assert_eq!(unsafe { destination.assume_init_ref() }, sentinel);
    assert_eq!(original_snapshot(), Err(error(expected)));
    assert_eq!(qualification_snapshot(), Err(error(expected)));
}

#[test]
fn snapshot_destination_matches_original_tls_across_return_rearm_and_drain() {
    for k in [10, 1000] {
        for order in [[0, 1], [1, 0]] {
            let mut f = Fixture::new(k, order);
            assert_eq!(compare_snapshots().active_batch, None);
            f.controller.arm(&f.epoch).unwrap();
            f.begin();
            assert_eq!(compare_snapshots().position, Some(0));
            f.visit(true);
            let entered = compare_snapshots();
            assert_eq!(entered.entry_seen, [Some(1), None, None, None]);
            assert!(entered.pending.unwrap().returned.is_none());
            f.visit(false);
            let returned = compare_snapshots();
            assert!(returned.pending.unwrap().returned.is_some());
            f.controller.disarm(&f.epoch).unwrap();
            assert!(f.controller.report(&f.epoch).unwrap().is_none());
            let second = f.controller.stage_prepared(f.banks.pop().unwrap()).unwrap();
            f.controller.arm(&second).unwrap();
            assert_eq!(compare_snapshots(), returned);
            for position in 2..=4 {
                f.visit(false);
                let bypass = compare_snapshots();
                assert_eq!(bypass.position, Some(position));
                assert_eq!(bypass.pending, returned.pending);
                assert_eq!(bypass.journal, returned.journal);
                assert!(f.controller.report(&f.epoch).unwrap().is_none());
            }
            f.finish();
            let drained = compare_snapshots();
            assert_eq!((drained.active_batch, drained.pending), (None, None));
            assert_eq!((drained.completed_batches, drained.completed_calls), (1, 4));
            assert_eq!(drained.model_depth, 0);
            assert_eq!(
                f.controller
                    .report(&f.epoch)
                    .unwrap()
                    .unwrap()
                    .records()
                    .count(),
                1
            );
            f.controller.disarm(&second).unwrap();
            assert_eq!(
                f.controller
                    .report(&second)
                    .unwrap()
                    .unwrap()
                    .records()
                    .count(),
                0
            );
        }
    }
}

#[test]
fn snapshot_destination_preserves_sentinel_and_original_first_error() {
    let f = Fixture::new(10, [0, 1]);
    f.begin();
    let sentinel = compare_snapshots();
    NORMAL.with(|c| {
        let _borrow = c.borrow_mut();
        refusal(Cause::Attachment, &sentinel);
    });
    PHYSICAL.with(|c| {
        let _borrow = c.borrow_mut();
        refusal(Cause::Attachment, &sentinel);
    });
    with_state(|s, _| {
        s.failure = Some(error(Cause::Capacity));
        s.tid ^= 1;
    });
    refusal(Cause::Capacity, &sentinel); // health precedes wrong thread.
    with_state(|s, _| {
        s.failure = None;
        s.tid ^= 1;
        s.busy = true;
    });
    refusal(Cause::Outstanding, &sentinel);
    with_state(|s, _| {
        s.busy = false;
        s.tid ^= 1;
    });
    let physical = PHYSICAL.with(|c| c.borrow_mut().take());
    refusal(Cause::Identity, &sentinel); // identity precedes absent physical TLS.
    PHYSICAL.with(|c| *c.borrow_mut() = physical);
    with_state(|s, p| {
        s.tid ^= 1;
        s.next = 0;
        p.shared.failed.store(true, Ordering::Release);
    });
    refusal(Cause::Identity, &sentinel); // shared failure precedes invalid shape.
    with_state(|_, p| p.shared.failed.store(false, Ordering::Release));
    refusal(Cause::Invariant, &sentinel);
    with_state(|s, _| s.next = 1);
    assert_eq!(compare_snapshots(), sentinel);
    let normal = NORMAL.with(|c| c.borrow_mut().0.take());
    refusal(Cause::Attachment, &sentinel);
    NORMAL.with(|c| c.borrow_mut().0 = normal);
    for _ in 0..4 {
        f.visit(false);
    }
    f.finish();
    assert_eq!(compare_snapshots().completed_calls, 4);
}

#[test]
fn snapshot_observer_receives_complete_owned_copy_after_tls_borrows_end() {
    let mut f = Fixture::new(10, [1, 0]);
    f.controller.arm(&f.epoch).unwrap();
    f.begin();
    f.visit(true);
    let received = Rc::new(RefCell::new(Vec::with_capacity(2)));
    let observed = Rc::clone(&received);
    // SAFETY: pure metadata observer; only probes RefCell availability without
    // invoking or modifying the model, and copies the supplied owned witness.
    // It performs no controller/native action, wait, assertion or intentional unwind.
    unsafe {
        install_observer(move |kind, snapshot| {
            let normal_free = NORMAL.with(|c| c.try_borrow_mut().is_ok());
            let physical_free = PHYSICAL.with(|c| c.try_borrow_mut().is_ok());
            observed
                .borrow_mut()
                .push((kind, snapshot.clone(), normal_free, physical_free));
        })
    }
    .unwrap();
    let entry = original_snapshot().unwrap();
    after_published(PauseKind::AfterEntryPublished);
    f.visit(false);
    let returned = original_snapshot().unwrap();
    after_published(PauseKind::AfterPreRetPublished);
    OBSERVER.with(|c| c.borrow_mut().take());
    assert_eq!(
        *received.borrow(),
        vec![
            (PauseKind::AfterEntryPublished, entry, true, true),
            (PauseKind::AfterPreRetPublished, returned, true, true),
        ]
    );
    for _ in 0..3 {
        f.visit(false);
    }
    f.finish();
    f.controller.disarm(&f.epoch).unwrap();
    assert_eq!(
        f.controller
            .report(&f.epoch)
            .unwrap()
            .unwrap()
            .records()
            .count(),
        1
    );
}
