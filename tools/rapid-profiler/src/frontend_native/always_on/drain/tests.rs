//! Metadata-only controls; synthetic gate stores do not qualify native CALL/RET.
use super::super::gate::drain_tests as frames;
use super::*;
use crate::frontend::PayloadOutcome;

struct Fixture {
    thread: IntervalThread,
    controller: IntervalController,
    _frames: frames::FrameScope,
}
fn state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with(|cell| f(cell.borrow_mut().as_mut().unwrap()))
}
impl Fixture {
    fn new() -> Self {
        let frames = frames::FrameScope::new();
        let mut site = site::synthetic_site();
        let gate = frames::descriptor();
        let inner = Arc::get_mut(&mut site.site).unwrap();
        inner.terminal = gate.continuation();
        inner.gate = Some(gate);
        let p = PreparedIntervalController::new(
            site,
            71,
            FunctionId(11),
            Limits {
                epochs: 4,
                threads: 1,
                depth: 1,
                records_per_epoch: 16,
                actions: 32,
            },
        )
        .unwrap();
        // SAFETY: synthetic metadata only; no executable bytes, fork or callback.
        let (controller, client) = unsafe { p.activate() }.unwrap();
        let thread = unsafe {
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
        Self {
            thread,
            controller,
            _frames: frames,
        }
    }
    fn stage(&mut self) -> IntervalEpoch {
        self.controller
            .stage(Config {
                retained_per_function: 2,
                max_inflight: 1,
                max_invocations: 16,
            })
            .unwrap()
    }
    fn call(&self) -> Result<(), BridgeError> {
        let before = self.thread.totals()?;
        // Exact existing preflight: a full-buffer refusal never clears the latch.
        state(|s| s.timing.as_ref().unwrap().reserve(0))?;
        let previous = self.thread.finished.replace(None);
        let n = before.entries + 1;
        let start = RawTimestamp {
            ticks: n * 10,
            aux: 7,
        };
        let end = RawTimestamp {
            ticks: if n == 43 {
                start.ticks - 1
            } else {
                start.ticks + 3
            },
            aux: if n == 41 { 8 } else { 7 },
        };
        state(|s| {
            frames::begin(s, start);
            frames::complete(s, end);
            frames::resume(s);
        });
        let after = self.thread.totals()?;
        assert_eq!(before.entries.checked_add(1), Some(after.entries));
        assert_eq!(before.returns.checked_add(1), Some(after.returns));
        self.thread
            .finished
            .set(completed_checkpoint(previous, before, after));
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
struct Snapshot {
    cursor: Cursor,
    finished: Option<PairTotals>,
    totals: PairTotals,
    next: u64,
    sequence: u64,
    depth: (usize, usize),
    pairs: [bool; PAIRS],
    registration: u64,
    address: u64,
    failure: Option<BridgeError>,
    rows: Option<Vec<RawInterval>>,
    journal: [u64; 512],
    gate: [u64; 14],
}
fn snapshot(f: &Fixture) -> Snapshot {
    state(|s| Snapshot {
        cursor: f.thread.drain_cursor,
        finished: f.thread.finished.get(),
        totals: s.totals,
        next: s.next,
        sequence: s.model.completed_sequence(),
        depth: (s.depth, s.model.depth()),
        pairs: std::array::from_fn(|n| s.pairs[n].is_some()),
        registration: s.registration,
        address: s.journal.address(),
        failure: s.failure,
        rows: s.timing.as_ref().map(timing::Rows::snapshot),
        journal: s.journal.page.0,
        gate: frames::snapshot(),
    })
}
fn refuses_unchanged(f: &mut Fixture) {
    let before = snapshot(f);
    assert!(f.thread.drain_completed().is_err());
    assert_eq!(snapshot(f), before);
}
fn rows_replace(s: &mut State, rows: Vec<RawInterval>) {
    let mut replacement = timing::Rows::new();
    for row in rows {
        replacement.push(row).unwrap();
    }
    s.timing = Some(replacement);
}

#[test]
fn three_full_batches_keep_one_registration_lifetime_history_and_held_reports() {
    let mut f = Fixture::new();
    let a = f.stage();
    let b = f.stage();
    let c = f.stage();
    let mut held = None;
    let mut held_rows = Vec::new();
    let mut batches = Vec::new();
    let address = state(|s| s.journal.address());
    for n in 0..96 {
        if n == 8 {
            f.controller.arm(&a).unwrap();
        }
        if n == 32 {
            f.controller.arm(&b).unwrap();
            let report = f.controller.report(&a).unwrap().unwrap();
            held_rows = report.records().collect();
            held = Some(report);
        }
        if n == 64 {
            f.controller.disarm(&b).unwrap();
        }
        if n == 72 {
            f.controller.arm(&c).unwrap();
        }
        f.call().unwrap();
        if (n + 1) % 32 == 0 {
            let before = snapshot(&f);
            assert_eq!(f.call(), Err(error(Cause::Capacity)));
            assert_eq!(snapshot(&f), before);
            let history = f.controller.history().unwrap();
            let batch = f.thread.drain_completed().unwrap().unwrap();
            assert_eq!(batch.number(), batches.len() as u64 + 1);
            assert_eq!(batch.raw_range(), n - 31..n + 1);
            assert_eq!(batch.event_range(), (n - 31) * 2..(n + 1) * 2);
            assert_eq!(
                (batch.registration(), batch.install(), batch.function()),
                (1, 71, FunctionId(11))
            );
            assert_eq!((batch.pid(), batch.tid()), (std::process::id(), tid()));
            assert_eq!(batch.rows(), before.rows.as_ref().unwrap());
            assert_eq!(batch.journal(), before.journal);
            assert_eq!(batch.next_ordinal(), n + 2);
            assert_eq!(batch.completed_sequences().1, batch.totals().1.completed);
            assert_eq!(f.controller.history().unwrap(), history);
            assert!(f.thread.raw_intervals().unwrap().is_empty());
            assert_eq!(state(|s| s.journal.address()), address);
            assert_eq!(state(|s| s.journal.page.0), {
                let mut expected = [0; 512];
                expected[2] = tid();
                expected
            });
            batches.push(batch);
            let after = snapshot(&f);
            assert_eq!(f.thread.drain_completed().unwrap(), None);
            assert_eq!(snapshot(&f), after);
        }
    }
    f.controller.disarm(&c).unwrap();
    assert_eq!(
        held.as_ref().unwrap().records().collect::<Vec<_>>(),
        held_rows
    );
    assert_eq!(
        f.controller
            .report(&a)
            .unwrap()
            .unwrap()
            .records()
            .collect::<Vec<_>>(),
        held_rows
    );
    assert_eq!(held_rows.len(), 2);
    for (i, record) in held_rows.iter().enumerate() {
        assert_eq!(record.record.admission.invocation, i);
        assert_eq!(record.payload.unwrap().start_sequence, i as u64);
        assert_eq!(
            record.payload.unwrap().outcome,
            PayloadOutcome::Completed {
                completed_children: 0,
                end: Observation::Value((i as u64 + 9) * 10 + 3),
            }
        );
    }
    assert_eq!(f.controller.history().unwrap().actions.len(), 5);
    assert_eq!(
        f.thread.totals().unwrap(),
        PairTotals {
            entries: 96,
            returns: 96,
            completed: 6,
            unsampled: 90
        }
    );
    let mut concatenated = Vec::new();
    for batch in &batches {
        for row in batch.rows() {
            let n = row.ordinal - 1;
            let (owner, prefix, kind, generation, invocation, reason) = match n {
                0..=7 => (RawIntervalOwner::InitialDisarmed, 0, 3, 0, 0, 1),
                8..=9 => (
                    RawIntervalOwner::Sampled {
                        generation: a.generation().get(),
                        invocation: (n - 8) as usize,
                    },
                    1,
                    1,
                    a.generation().get(),
                    n - 7,
                    0,
                ),
                10..=31 => (
                    RawIntervalOwner::FunctionClosed {
                        generation: a.generation().get(),
                    },
                    1,
                    3,
                    a.generation().get(),
                    0,
                    3,
                ),
                32..=33 => (
                    RawIntervalOwner::Sampled {
                        generation: b.generation().get(),
                        invocation: (n - 32) as usize,
                    },
                    2,
                    1,
                    b.generation().get(),
                    n - 31,
                    0,
                ),
                34..=63 => (
                    RawIntervalOwner::FunctionClosed {
                        generation: b.generation().get(),
                    },
                    2,
                    3,
                    b.generation().get(),
                    0,
                    3,
                ),
                64..=71 => (
                    RawIntervalOwner::Removed {
                        generation: b.generation().get(),
                    },
                    3,
                    3,
                    b.generation().get(),
                    0,
                    2,
                ),
                72..=73 => (
                    RawIntervalOwner::Sampled {
                        generation: c.generation().get(),
                        invocation: (n - 72) as usize,
                    },
                    4,
                    1,
                    c.generation().get(),
                    n - 71,
                    0,
                ),
                _ => (
                    RawIntervalOwner::FunctionClosed {
                        generation: c.generation().get(),
                    },
                    4,
                    3,
                    c.generation().get(),
                    0,
                    3,
                ),
            };
            assert_eq!(row.owner, owner);
            let at = 4 + (n % 32) as usize * 14;
            let bits = invocation | (prefix << 13) | (reason << 22);
            let continuation = state(|s| s.binding.site.terminal);
            assert_eq!(
                &batch.journal()[at..at + 7],
                [kind, n + 1, 0x1000, 0x7ff8, continuation, generation, bits]
            );
            assert_eq!(
                &batch.journal()[at + 7..at + 14],
                [
                    kind + 1,
                    n + 1,
                    0x1012,
                    0x7ff8,
                    continuation,
                    generation,
                    bits
                ]
            );
            concatenated.push(row.ordinal);
        }
    }
    assert_eq!(concatenated, (1..=96).collect::<Vec<_>>());
    assert_eq!(batches[1].rows()[8].elapsed_ticks(), None); // AUX changed, copied unchanged.
    assert_eq!(batches[1].rows()[10].elapsed_ticks(), None); // Backwards clock, not repaired.
    assert_eq!(f.thread.detach().unwrap().returns, 96);
}

#[test]
fn failed_checkpoint_is_sticky_but_preflight_capacity_never_clears_it() {
    let mut f = Fixture::new();
    f.call().unwrap();
    f.thread.finished.set(None); // Failed post-preflight invocation.
    refuses_unchanged(&mut f);
    f.call().unwrap(); // A later successful synthetic pair does NOT repair it.
    assert_eq!(f.thread.finished.get(), None);
    refuses_unchanged(&mut f);
    f.thread.finished.set(Some(PairTotals::default()));
    refuses_unchanged(&mut f); // Stale successful checkpoint also refuses.
    f.thread.finished.set(Some(f.thread.totals().unwrap()));
    f.thread.drain_completed().unwrap().unwrap();
}

#[test]
fn report_ready_at_completed_gate_is_not_drain_authority() {
    let mut f = Fixture::new();
    let e = f.stage();
    f.controller.arm(&e).unwrap();
    let before = f.thread.totals().unwrap();
    f.thread.finished.set(None);
    state(|s| frames::begin(s, RawTimestamp { ticks: 1, aux: 1 }));
    refuses_unchanged(&mut f); // Both actual model and facade still have a live pair.
    f.controller.disarm(&e).unwrap();
    assert!(f.controller.report(&e).unwrap().is_none());
    state(|s| frames::complete(s, RawTimestamp { ticks: 2, aux: 1 }));
    let retained = f.controller.report(&e).unwrap().unwrap();
    let records = retained.records().collect::<Vec<_>>();
    // Isolate the gate check: even a synthetic matching latch cannot bless COMPLETED.
    f.thread.finished.set(Some(f.thread.totals().unwrap()));
    refuses_unchanged(&mut f);
    state(|s| frames::resume(s));
    let after = f.thread.totals().unwrap();
    f.thread
        .finished
        .set(completed_checkpoint(Some(before), before, after));
    f.thread.drain_completed().unwrap().unwrap();
    assert_eq!(retained.records().collect::<Vec<_>>(), records);
}

#[test]
fn old_inflight_owner_survives_rearm_and_drain_never_completes_it() {
    let mut f = Fixture::new();
    let a = f.stage();
    let b = f.stage();
    f.controller.arm(&a).unwrap();
    let before = f.thread.totals().unwrap();
    f.thread.finished.set(None);
    state(|s| frames::begin(s, RawTimestamp { ticks: 50, aux: 7 }));
    f.controller.arm(&b).unwrap();
    assert!(f.controller.report(&a).unwrap().is_none());
    refuses_unchanged(&mut f);
    assert_eq!(f.controller.owner(&a).unwrap().reservations(), 1);
    state(|s| {
        frames::complete(s, RawTimestamp { ticks: 60, aux: 7 });
        frames::resume(s);
    });
    let after = f.thread.totals().unwrap();
    f.thread
        .finished
        .set(completed_checkpoint(Some(before), before, after));
    let retained = f.controller.report(&a).unwrap().unwrap();
    let records = retained.records().collect::<Vec<_>>();
    f.call().unwrap();
    let history = f.controller.history().unwrap();
    let batch = f.thread.drain_completed().unwrap().unwrap();
    assert_eq!(
        batch.rows().iter().map(|row| row.owner).collect::<Vec<_>>(),
        [
            RawIntervalOwner::Sampled {
                generation: a.generation().get(),
                invocation: 0
            },
            RawIntervalOwner::Sampled {
                generation: b.generation().get(),
                invocation: 0
            },
        ]
    );
    assert_eq!(retained.records().collect::<Vec<_>>(), records);
    assert_eq!(f.controller.history().unwrap(), history);
    assert!(f.controller.report(&b).unwrap().is_none()); // Draining did not close current B.
    f.controller.disarm(&b).unwrap();
}

#[test]
fn hidden_pair_is_refused_even_when_both_depths_are_zero() {
    let mut f = Fixture::new();
    f.call().unwrap();
    let before = snapshot(&f);
    state(|s| frames::begin(s, RawTimestamp { ticks: 20, aux: 7 }));
    let active = snapshot(&f);
    state(|s| {
        assert_eq!(s.model.depth(), 0); // Initial-disarmed receipt still owns a Pair.
        s.pairs[PAIRS - 1] = s.pairs[0].take();
        s.depth = 0;
        s.totals = before.totals;
        s.next = before.next;
        s.journal.page.0 = before.journal;
    });
    let hidden = snapshot(&f);
    // Exact cause matters: without the hidden-slot check the later gate error is different.
    assert_eq!(f.thread.drain_completed(), Err(error(Cause::Outstanding)));
    assert_eq!(snapshot(&f), hidden);
    state(|s| {
        s.pairs[0] = s.pairs[PAIRS - 1].take();
        s.depth = active.depth.0;
        s.totals = active.totals;
        s.next = active.next;
        s.journal.page.0 = active.journal;
        frames::complete(s, RawTimestamp { ticks: 23, aux: 7 });
        frames::resume(s);
    });
    f.thread.finished.set(completed_checkpoint(
        before.finished,
        before.totals,
        f.thread.totals().unwrap(),
    ));
    assert_eq!(f.thread.drain_completed().unwrap().unwrap().rows().len(), 2);
}

#[test]
fn malformed_join_or_counter_never_consumes_any_buffer() {
    let mut f = Fixture::new();
    f.call().unwrap();
    f.call().unwrap();
    for index in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 17, 511] {
        let old = state(|s| {
            let old = s.journal.page.0[index];
            s.journal.word(index, old ^ 1);
            old
        });
        refuses_unchanged(&mut f);
        state(|s| s.journal.word(index, old));
    }
    for which in 0..7 {
        let original = state(|s| s.timing.as_ref().unwrap().snapshot());
        let mut changed = original.clone();
        match which {
            0 => changed[1].ordinal = changed[0].ordinal,
            1 => changed[0].entry_pc += 1,
            2 => changed[0].return_pc += 1,
            3 => changed[0].owner = RawIntervalOwner::Removed { generation: 1 },
            4 => {
                changed.pop();
            }
            5 => changed.push(changed[0]),
            _ => changed.swap(0, 1),
        }
        state(|s| rows_replace(s, changed));
        refuses_unchanged(&mut f);
        state(|s| rows_replace(s, original));
    }
    let cursor = f.thread.drain_cursor;
    f.thread.drain_cursor.number = u64::MAX;
    refuses_unchanged(&mut f);
    f.thread.drain_cursor = cursor;
    f.thread.drain_cursor.totals.returns = 3;
    refuses_unchanged(&mut f);
    f.thread.drain_cursor = cursor;
    let old = state(|s| {
        s.next += 1;
        s.next - 1
    });
    refuses_unchanged(&mut f);
    state(|s| s.next = old);
    // Balanced near-overflow totals still cannot wrap absolute event offsets.
    let totals = state(|s| s.totals);
    let latch = f.thread.finished.get();
    state(|s| {
        s.totals = PairTotals {
            entries: u64::MAX - 1,
            returns: u64::MAX - 1,
            completed: 0,
            unsampled: u64::MAX - 1,
        };
        s.next = u64::MAX;
    });
    f.thread.finished.set(Some(state(|s| s.totals)));
    refuses_unchanged(&mut f);
    state(|s| {
        s.totals = totals;
        s.next = old;
    });
    f.thread.finished.set(latch);
    assert_eq!(f.thread.drain_completed().unwrap().unwrap().rows().len(), 2);
}

#[test]
fn attachment_health_profile_and_allocation_refusals_are_atomic() {
    let mut f = Fixture::new();
    f.call().unwrap();
    f.thread.active = false;
    refuses_unchanged(&mut f);
    f.thread.active = true;
    let pid = f.thread.pid;
    f.thread.pid = 0;
    refuses_unchanged(&mut f);
    f.thread.pid = pid;
    f.thread.registration += 1;
    refuses_unchanged(&mut f);
    f.thread.registration -= 1;
    let key = Arc::clone(&f.thread.key);
    f.thread.key = Arc::new(());
    refuses_unchanged(&mut f);
    f.thread.key = key;
    POISONED.set(true);
    refuses_unchanged(&mut f);
    POISONED.set(false);
    state(|s| s.failure = Some(error(Cause::Return)));
    refuses_unchanged(&mut f);
    state(|s| s.failure = None);
    state(|s| s.depth = 1);
    refuses_unchanged(&mut f);
    state(|s| s.depth = 0);
    let rows = state(|s| s.timing.take());
    refuses_unchanged(&mut f);
    state(|s| s.timing = rows);
    STATE.with(|cell| {
        let _held = cell.borrow();
        assert_eq!(f.thread.drain_completed(), Err(error(Cause::Attachment)));
    });
    for slot in [0, 1] {
        FAIL_RESERVE.set(Some(slot));
        refuses_unchanged(&mut f);
        FAIL_RESERVE.set(None);
    }
    assert_eq!(f.thread.drain_completed().unwrap().unwrap().rows().len(), 1);
    f.thread.detach().unwrap();
    // Existing fixed profile has no gate/timing authority, even with an empty buffer.
    let p = PreparedIntervalController::new(
        site::synthetic_site(),
        71,
        FunctionId(11),
        Limits {
            epochs: 1,
            threads: 1,
            depth: 1,
            records_per_epoch: 1,
            actions: 2,
        },
    )
    .unwrap();
    let (_controller, client) = unsafe { p.activate() }.unwrap();
    let mut thread = unsafe {
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
    assert_eq!(thread.drain_completed(), Err(error(Cause::ClockProfile)));
    thread.detach().unwrap();
}
