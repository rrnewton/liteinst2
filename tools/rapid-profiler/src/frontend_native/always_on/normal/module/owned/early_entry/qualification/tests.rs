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
            order: order.map(|i| state.selection(i).unwrap()),
            words: WORDS,
            batches: 0,
            calls: 0,
            active: None,
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

// Literal old binary encoder and its three helpers. The local constant restores
// its original early::JOURNAL name; its complete body/branches are unchanged.
mod typed_encoder_reference {
    use super::*;
    mod early {
        pub(super) const JOURNAL: usize = 128;
    }
    fn totals(t: NormalTotals) -> [u64; 5] {
        [
            t.entered,
            t.ret_observed,
            t.confirmed,
            t.completed,
            t.unsampled,
        ]
    }
    fn raw_owner(owner: RawIntervalOwner) -> [u64; 3] {
        match owner {
            RawIntervalOwner::Sampled {
                generation,
                invocation,
            } => [1, generation, invocation as u64],
            RawIntervalOwner::InitialDisarmed => [2, 0, 0],
            RawIntervalOwner::Removed { generation } => [3, generation, 0],
            RawIntervalOwner::FunctionClosed { generation } => [4, generation, 0],
        }
    }
    fn owner_words(o: OwnerSnapshot) -> [u64; 8] {
        let [kind, generation, invocation] = raw_owner(o.owner);
        let (binding, index, bound_generation) = match o.binding {
            HistoryBinding::Initial => (0, 0, 0),
            HistoryBinding::Published {
                action_index,
                generation,
            } => (1, action_index, generation.get()),
            HistoryBinding::Removed {
                action_index,
                generation,
            } => (2, action_index, generation.get()),
        };
        [
            kind,
            generation,
            invocation,
            o.history_len as u64,
            binding,
            index,
            bound_generation,
            o.closed_function.map_or(0, |f| f.0),
        ]
    }
    fn encode_into(
        kind: PauseKind,
        sequence: u64,
        s: &QualificationSnapshot,
        h: &mut [u64; early::JOURNAL],
    ) {
        h.fill(0);
        h[..15].copy_from_slice(&[
            0x6561_726c_796d_6f64,
            match kind {
                PauseKind::AfterEntryPublished => 1,
                PauseKind::AfterPreRetPublished => 2,
            },
            sequence,
            s.binding_key as u64,
            u64::from(s.pid),
            s.tid,
            s.registration,
            s.completed_batches,
            s.completed_calls,
            s.active_batch.unwrap(),
            s.position.unwrap() as u64,
            s.next_ordinal,
            s.model_depth as u64,
            s.completed_sequence,
            s.interval_batch,
        ]);
        h[15..20].copy_from_slice(&totals(s.totals));
        h[20..25].copy_from_slice(&totals(s.interval_cursor_totals));
        for (i, n) in s.entry_seen.iter().enumerate() {
            h[25 + i] = n.unwrap_or(0);
        }
        for (i, row) in s.pre_rets.iter().enumerate() {
            if let Some(r) = row {
                h[29 + i * 7..36 + i * 7].copy_from_slice(&[
                    r.batch,
                    r.position as u64,
                    r.function.0,
                    r.observed_ordinal.unwrap_or(0),
                    r.return_pc,
                    r.entry_rsp,
                    r.return_word,
                ]);
            }
        }
        if let Some(p) = s.pending {
            h[57..67].copy_from_slice(&[
                1,
                p.physical_batch,
                p.physical_position as u64,
                p.function.0,
                p.ordinal,
                p.entry_pc,
                p.rsp,
                p.word,
                p.start.ticks,
                u64::from(p.start.aux),
            ]);
            h[73] = p.slot.identity;
            h[74] = p.slot.word;
            if let Some(owner) = p.summary {
                h[75] = 1;
                h[76..84].copy_from_slice(&owner_words(owner));
            }
            if let Some(owner) = p.actual_summary {
                h[84] = 1;
                h[85..93].copy_from_slice(&owner_words(owner));
                let [_, generation, invocation] = raw_owner(owner.owner);
                h[71] = generation;
                h[72] = invocation;
            }
            if let Some(r) = p.returned {
                h[67] = 1;
                h[68] = r.return_pc;
                h[69] = r.end.ticks;
                h[70] = u64::from(r.end.aux);
                let [kind, generation, invocation] = raw_owner(r.owner);
                h[93..103].copy_from_slice(&[
                    r.ordinal,
                    r.entry_pc,
                    r.return_pc,
                    kind,
                    generation,
                    invocation,
                    r.start.ticks,
                    u64::from(r.start.aux),
                    r.end.ticks,
                    u64::from(r.end.aux),
                ]);
            }
        }
    }

    pub(super) fn header(
        kind: PauseKind,
        sequence: u64,
        snapshot: &QualificationSnapshot,
        out: &mut [u64; 128],
    ) {
        encode_into(kind, sequence, snapshot, out);
    }
}

fn encoded_words(header: &[u64; 128], journal: &[u64; 512]) -> [u64; 640] {
    let mut words = [0; 640];
    words[..128].copy_from_slice(header);
    words[128..].copy_from_slice(journal);
    words
}
fn expected_words(kind: PauseKind, sequence: u64, snapshot: &QualificationSnapshot) -> [u64; 640] {
    let mut header = [0; 128];
    typed_encoder_reference::header(kind, sequence, snapshot, &mut header);
    encoded_words(&header, &snapshot.journal)
}
fn flat_image(state: &FlatObserverState) -> ([u64; 640], bool, u64) {
    (
        encoded_words(&state.snapshot.header, &state.snapshot.journal),
        state.snapshot.active,
        state.sequence,
    )
}
fn flat_parity(state: &mut FlatObserverState, kind: PauseKind) -> QualificationSnapshot {
    let original = compare_snapshots();
    let expected = expected_words(kind, state.sequence + 1, &original);
    state.prepare(kind).unwrap();
    assert_eq!(
        encoded_words(&state.snapshot.header, &state.snapshot.journal),
        expected
    );
    assert!(state.snapshot.active);
    assert_eq!(state.snapshot.header[103..], [0; 25]);
    assert_eq!(compare_snapshots(), original);
    assert!(NORMAL.with(|c| c.try_borrow_mut().is_ok()));
    assert!(PHYSICAL.with(|c| c.try_borrow_mut().is_ok()));
    original
}
fn flat_refusal(state: &mut FlatObserverState, expected: Cause, sentinel: &QualificationSnapshot) {
    let before = flat_image(state);
    refusal(expected, sentinel);
    assert_eq!(
        state.prepare(PauseKind::AfterEntryPublished),
        Err(error(expected))
    );
    assert_eq!(flat_image(state), before);
}

#[test]
fn flat_witness_matches_typed_encoder_across_receipts_rearm_and_sparse_reset() {
    let mut cases = 0;
    for (k, mode) in [
        (10, 0),
        (10, 1),
        (10, 2),
        (10, 3),
        (10, 4),
        (1000, 0),
        (1000, 1),
        (1000, 2),
        (1000, 4),
    ] {
        for order in [[0, 1], [1, 0]] {
            for mask in [0b0101u8, 0b1111] {
                let mut f = Fixture::new(k, order);
                if mode != 0 {
                    f.controller.arm(&f.epoch).unwrap();
                }
                if mode == 1 {
                    f.controller.disarm(&f.epoch).unwrap();
                }
                if mode == 3 {
                    // Exhaust the actual twenty-record bank to obtain real
                    // FunctionClosed receipts, never fabricate their owner.
                    for _ in 0..5 {
                        f.begin();
                        for _ in 0..4 {
                            f.visit(true);
                            f.visit(false);
                        }
                        f.finish();
                    }
                }
                let mut flat = FlatObserverState::new();
                flat.snapshot.header.fill(u64::MAX);
                flat.snapshot.journal.fill(u64::MAX);
                f.begin();
                flat_parity(&mut flat, PauseKind::AfterEntryPublished);
                let mut second = None;
                for position in 0..4 {
                    let observed = mask & (1 << position) != 0;
                    if observed {
                        f.visit(true);
                        let s = flat_parity(&mut flat, PauseKind::AfterEntryPublished);
                        let p = s.pending.unwrap();
                        assert_eq!(p.summary, p.actual_summary);
                        match mode {
                            0 => assert_eq!(
                                p.summary.unwrap().owner,
                                RawIntervalOwner::InitialDisarmed
                            ),
                            1 => assert_eq!(
                                p.summary.unwrap().owner,
                                RawIntervalOwner::Removed {
                                    generation: f.epoch.generation().get(),
                                }
                            ),
                            2 | 4 => assert!(matches!(p.summary.unwrap().owner,
                                RawIntervalOwner::Sampled { generation, .. }
                                if generation == second.as_ref().unwrap_or(&f.epoch).generation().get())),
                            3 => assert_eq!(
                                p.summary.unwrap().owner,
                                RawIntervalOwner::FunctionClosed {
                                    generation: f.epoch.generation().get(),
                                }
                            ),
                            _ => unreachable!(),
                        }
                    }
                    let before = compare_snapshots();
                    f.visit(false);
                    let s = flat_parity(&mut flat, PauseKind::AfterPreRetPublished);
                    assert_eq!(s.position, Some(position + 1));
                    if !observed {
                        assert_eq!(s.pending, before.pending);
                        assert_eq!(s.journal, before.journal);
                    }
                    if mode == 4 && position == 0 {
                        f.controller.disarm(&f.epoch).unwrap();
                        assert!(f.controller.report(&f.epoch).unwrap().is_none());
                        let next = f.controller.stage_prepared(f.banks.pop().unwrap()).unwrap();
                        f.controller.arm(&next).unwrap();
                        assert_eq!(flat_parity(&mut flat, PauseKind::AfterPreRetPublished), s);
                        second = Some(next);
                    }
                }
                f.finish();
                let drained = compare_snapshots();
                assert_eq!(
                    (drained.active_batch, drained.pending, drained.model_depth),
                    (None, None, 0)
                );
                // Reuse the exact same private scratch after a dense returned
                // snapshot. Every absent row/owner/return and reserved cell
                // must be overwritten; no new allocation hides stale values.
                f.begin();
                let empty = flat_parity(&mut flat, PauseKind::AfterEntryPublished);
                assert_eq!(empty.entry_seen, [None; 4]);
                assert!(empty.pre_rets.iter().all(Option::is_none));
                assert!(empty.pending.is_none());
                assert_eq!(flat.snapshot.header[25..103], [0; 78]);
                for _ in 0..4 {
                    f.visit(false);
                    flat_parity(&mut flat, PauseKind::AfterPreRetPublished);
                }
                f.finish();
                if mode >= 2 {
                    f.controller
                        .disarm(second.as_ref().unwrap_or(&f.epoch))
                        .unwrap();
                }
                if mode != 0 {
                    assert_eq!(
                        f.controller
                            .report(&f.epoch)
                            .unwrap()
                            .unwrap()
                            .records()
                            .count(),
                        match mode {
                            1 => 0,
                            2 => mask.count_ones() as usize,
                            3 => 20,
                            4 => 1,
                            _ => unreachable!(),
                        }
                    );
                }
                if let Some(second) = second {
                    assert_eq!(
                        f.controller
                            .report(&second)
                            .unwrap()
                            .unwrap()
                            .records()
                            .count(),
                        mask.count_ones() as usize - 1
                    );
                }
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 36);
}

#[test]
fn flat_witness_copies_all_journal_words_and_keeps_actual_receipt_independent() {
    let f = Fixture::new(10, [1, 0]);
    f.begin();
    let mut flat = FlatObserverState::new();
    let initial = flat_parity(&mut flat, PauseKind::AfterEntryPublished);
    // Word zero is the fresh used coordinate: corrupting it must refuse. Every
    // other actual journal word, including unused tail511, remains observable.
    with_state(|s, _| s.journal.word(0, 1));
    flat_refusal(&mut flat, Cause::Invariant, &initial);
    with_state(|s, _| s.journal.word(0, 0));
    for index in 1..512 {
        let old = with_state(|s, _| {
            let old = s.journal.page.0[index];
            s.journal
                .word(index, old ^ (0x8000_0000_0000_0000 | index as u64));
            old
        });
        let actual = flat_parity(&mut flat, PauseKind::AfterEntryPublished);
        assert_ne!(actual.journal[index], old);
        assert_eq!(flat.snapshot.journal[index], actual.journal[index]);
        with_state(|s, _| s.journal.word(index, old));
    }
    with_state(|s, _| s.journal.page.0.fill(0));
    flat_parity(&mut flat, PauseKind::AfterEntryPublished);
    assert_eq!(flat.snapshot.journal, [0; 512]);
    with_state(|s, _| s.journal.page.0 = initial.journal);
    f.visit(true);
    let admitted = flat_parity(&mut flat, PauseKind::AfterEntryPublished);
    let original = admitted.pending.unwrap().summary;
    let generation = f.epoch.generation();
    for summary in [
        None,
        Some(IntervalEntrySummary::Unsampled {
            reason: UnsampledSummary::InitialDisarmed,
            history_len: usize::MAX,
            binding: BindingChange::Removed {
                action_index: usize::MAX,
                generation,
            },
        }),
        Some(IntervalEntrySummary::Unsampled {
            reason: UnsampledSummary::FunctionClosed {
                generation,
                function: FunctionId(u64::MAX),
            },
            history_len: usize::MAX,
            binding: BindingChange::Published {
                action_index: usize::MAX,
                generation,
            },
        }),
    ] {
        with_state(|s, _| s.pending.as_mut().unwrap().summary = summary);
        let actual = flat_parity(&mut flat, PauseKind::AfterEntryPublished);
        let p = actual.pending.unwrap();
        assert_eq!(p.summary, summary.map(owner_snapshot));
        assert_eq!(p.actual_summary, admitted.pending.unwrap().actual_summary);
        assert_ne!(p.summary, p.actual_summary);
        assert_eq!(flat.snapshot.header[84], 1);
        assert_eq!(flat.snapshot.header[85], 2);
        assert_eq!(&flat.snapshot.header[71..73], &[0, 0]);
    }
    with_state(|s, _| {
        s.pending.as_mut().unwrap().summary = Some(IntervalEntrySummary::Unsampled {
            reason: UnsampledSummary::InitialDisarmed,
            history_len: original.unwrap().history_len,
            binding: BindingChange::Initial,
        });
    });
    assert_eq!(
        flat_parity(&mut flat, PauseKind::AfterEntryPublished),
        admitted
    );
    f.visit(false);
    flat_parity(&mut flat, PauseKind::AfterPreRetPublished);
    // Consume the actual unsampled receipt through the real model seam. This
    // intentionally leaves diagnostic pending metadata, which the original
    // snapshot still accepts; only the actual receipt summary becomes absent.
    with_state(|s, _| {
        let p = s.pending.as_mut().unwrap();
        let raw = p.returned.unwrap();
        assert!(matches!(
            s.model
                .finish_interval(&mut p.receipt, &mut p.slot, raw.observation())
                .unwrap(),
            IntervalExit::Unsampled {
                reason: UnsampledSummary::InitialDisarmed,
                ..
            }
        ));
        assert!(p.receipt.summary().is_none());
    });
    let consumed = flat_parity(&mut flat, PauseKind::AfterPreRetPublished);
    assert!(consumed.pending.unwrap().summary.is_some());
    assert!(consumed.pending.unwrap().actual_summary.is_none());
    assert_eq!(flat.snapshot.header[75], 1);
    assert_eq!(flat.snapshot.header[84..93], [0; 9]);
    assert_eq!(flat.snapshot.header[71..73], [0; 2]);
    // Fixture teardown is the existing metadata-only cancellation contract;
    // no successful native detach or second receipt completion is invented.
}

#[test]
fn flat_witness_preserves_refusals_sequence_panic_and_borrow_boundary() {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    let f = Fixture::new(10, [0, 1]);
    let mut old_sequence = 0;
    let before_witness = [0xa5a5_a5a5_a5a5_a5a5; 640];
    let mut old_witness = before_witness;
    let witness = Rc::new(RefCell::new(before_witness));
    let output = Rc::clone(&witness);
    let calls = Rc::new(Cell::new(0));
    let called = Rc::clone(&calls);
    let mut adapter = EncodedObserver {
        state: FlatObserverState::new(),
        observer: move |header: &[u64; 128], journal: &[u64; 512]| {
            called.set(called.get() + 1);
            *output.borrow_mut() = encoded_words(header, journal);
        },
    };
    let inactive = compare_snapshots();
    let old_panic = catch_unwind(AssertUnwindSafe(|| {
        old_sequence += 1;
        old_witness = expected_words(PauseKind::AfterEntryPublished, old_sequence, &inactive);
    }));
    // Same call method as the production boxed adapter, but not installed:
    // intentional panic never violates the unsafe observer contract.
    let new_panic = catch_unwind(AssertUnwindSafe(|| {
        adapter.call(PauseKind::AfterEntryPublished)
    }));
    assert!(old_panic.is_err() && new_panic.is_err());
    assert_eq!((old_sequence, adapter.state.sequence), (1, 1));
    assert_eq!(old_witness, before_witness);
    assert_eq!(*witness.borrow(), before_witness);
    assert_eq!(calls.get(), 0);
    assert!(NORMAL.with(|c| c.try_borrow_mut().is_ok()));
    assert!(PHYSICAL.with(|c| c.try_borrow_mut().is_ok()));
    f.begin();
    with_state(|_, p| p.shared.failed.store(true, Ordering::Release));
    let before_refusal = flat_image(&adapter.state);
    assert_eq!(
        adapter.call(PauseKind::AfterEntryPublished),
        Err(error(Cause::Identity))
    );
    assert_eq!(flat_image(&adapter.state), before_refusal);
    assert_eq!(*witness.borrow(), before_witness);
    assert_eq!(calls.get(), 0);
    with_state(|_, p| p.shared.failed.store(false, Ordering::Release));
    let mut flat = adapter.state;
    let sentinel = flat_parity(&mut flat, PauseKind::AfterEntryPublished);
    NORMAL.with(|c| {
        let _hold = c.borrow_mut();
        flat_refusal(&mut flat, Cause::Attachment, &sentinel);
    });
    PHYSICAL.with(|c| {
        let _hold = c.borrow_mut();
        flat_refusal(&mut flat, Cause::Attachment, &sentinel);
    });
    with_state(|s, _| {
        s.failure = Some(error(Cause::Capacity));
        s.tid ^= 1;
    });
    flat_refusal(&mut flat, Cause::Capacity, &sentinel);
    with_state(|s, _| {
        s.failure = None;
        s.tid ^= 1;
        s.busy = true;
    });
    flat_refusal(&mut flat, Cause::Outstanding, &sentinel);
    with_state(|s, _| {
        s.busy = false;
        s.tid ^= 1;
    });
    let physical = PHYSICAL.with(|c| c.borrow_mut().take());
    flat_refusal(&mut flat, Cause::Identity, &sentinel);
    PHYSICAL.with(|c| *c.borrow_mut() = physical);
    with_state(|s, p| {
        s.tid ^= 1;
        s.next = 0;
        p.shared.failed.store(true, Ordering::Release);
    });
    flat_refusal(&mut flat, Cause::Identity, &sentinel);
    with_state(|_, p| p.shared.failed.store(false, Ordering::Release));
    flat_refusal(&mut flat, Cause::Invariant, &sentinel);
    with_state(|s, _| s.next = 1);
    let normal = NORMAL.with(|c| c.borrow_mut().0.take());
    flat_refusal(&mut flat, Cause::Attachment, &sentinel);
    NORMAL.with(|c| c.borrow_mut().0 = normal);
    assert_eq!(compare_snapshots(), sentinel);
    // A private adapter exercises overflow without violating an installed
    // observer's no-unwind contract. Debug panic/release wrap must match +=1.
    old_sequence = u64::MAX;
    flat.sequence = u64::MAX;
    let old_overflow = catch_unwind(AssertUnwindSafe(|| {
        old_sequence += 1;
        expected_words(PauseKind::AfterEntryPublished, old_sequence, &sentinel)
    }));
    let new_overflow = catch_unwind(AssertUnwindSafe(|| {
        flat.prepare(PauseKind::AfterEntryPublished)
    }));
    assert_eq!(old_overflow.is_err(), new_overflow.is_err());
    assert_eq!(old_sequence, flat.sequence);
    if let Ok(expected) = old_overflow {
        new_overflow.unwrap().unwrap();
        assert_eq!(
            encoded_words(&flat.snapshot.header, &flat.snapshot.journal),
            expected
        );
    }
    assert!(NORMAL.with(|c| c.try_borrow_mut().is_ok()));
    assert!(PHYSICAL.with(|c| c.try_borrow_mut().is_ok()));

    struct Dropped(Rc<Cell<usize>>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let received = Rc::new(RefCell::new(Vec::with_capacity(2)));
    let observed = Rc::clone(&received);
    // SAFETY: copied metadata only; probes availability without entering model,
    // controller or native code. Two preallocated records; no intentional unwind.
    unsafe {
        install_encoded_observer(move |header, journal| {
            let normal_free = NORMAL.with(|c| c.try_borrow_mut().is_ok());
            let physical_free = PHYSICAL.with(|c| c.try_borrow_mut().is_ok());
            observed.borrow_mut().push((
                encoded_words(header, journal),
                normal_free,
                physical_free,
            ));
        })
    }
    .unwrap();
    let factory_calls = Rc::new(Cell::new(0));
    let drops = Rc::new(Cell::new(0));
    for borrowed in [false, true] {
        let calls = Rc::clone(&factory_calls);
        let dropped = Dropped(Rc::clone(&drops));
        let make = move || -> Observer {
            calls.set(calls.get() + 1);
            Box::new(move |_| {
                let _keep = &dropped;
                Ok(())
            })
        };
        let result = if borrowed {
            OBSERVER.with(|c| {
                let _hold = c.borrow_mut();
                install_preparing_observer(make)
            })
        } else {
            install_preparing_observer(make)
        };
        assert_eq!(result, Err(error(Cause::Attachment)));
    }
    assert_eq!(factory_calls.get(), 0);
    assert_eq!(drops.get(), 2);
    let dropped = Dropped(Rc::clone(&drops));
    // SAFETY: rejected before the inert supplied callback can run.
    assert_eq!(
        unsafe {
            install_observer(move |_, _| {
                let _keep = &dropped;
            })
        },
        Err(error(Cause::Attachment))
    );
    assert_eq!(drops.get(), 3);
    let dropped = Dropped(Rc::clone(&drops));
    // SAFETY: rejected before this inert encoded callback can run.
    assert_eq!(
        unsafe {
            install_encoded_observer(move |_, _| {
                let _keep = &dropped;
            })
        },
        Err(error(Cause::Attachment))
    );
    assert_eq!(drops.get(), 4);
    f.visit(true);
    let entered = compare_snapshots();
    let (used, position) = with_state(|s, p| {
        let used = s.journal.used();
        s.journal.word(0, u64::MAX);
        let position = p.active.as_mut().unwrap().pending_position.take();
        (used, position)
    });
    flat_refusal(&mut flat, Cause::Invariant, &entered); // normal used before physical Pending.
    with_state(|s, _| s.journal.word(0, used as u64));
    flat_refusal(&mut flat, Cause::Return, &entered);
    with_state(|_, p| p.active.as_mut().unwrap().pending_position = position);
    assert_eq!(compare_snapshots(), entered);
    let first = expected_words(PauseKind::AfterEntryPublished, 1, &entered);
    after_published(PauseKind::AfterEntryPublished);
    f.visit(false);
    let second = expected_words(PauseKind::AfterPreRetPublished, 2, &compare_snapshots());
    after_published(PauseKind::AfterPreRetPublished);
    OBSERVER.with(|c| c.borrow_mut().take());
    assert_eq!(
        *received.borrow(),
        vec![(first, true, true), (second, true, true)]
    );
    for _ in 0..3 {
        f.visit(false);
    }
    f.finish();
    assert_eq!(compare_snapshots().completed_calls, 4);
}
