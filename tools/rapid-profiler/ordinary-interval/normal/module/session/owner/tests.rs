//! Fabricated facts and simulated tokens exercise production validation helpers.
//! These controls never attach a native thread or qualify actual Arc/return custody.
use super::*;
use rapid_profiler::frontend::{Action, ActionKind, Payload};
use rapid_profiler::frontend_native::{
    EpochStorageReclaimError, HistoryBinding, NormalModuleRecord, NormalRecord, RawTimestamp,
};
use rapid_profiler::generation::{Admission, Epoch, GenerationId, Record};
use shared::epoch_storage::{Identity, Slot};
use std::panic::{AssertUnwindSafe, catch_unwind};

fn refuse(body: impl FnOnce()) {
    assert!(catch_unwind(AssertUnwindSafe(body)).is_err());
}
struct Batch {
    meta: check::Metadata,
    rows: Vec<NormalModuleRecord>,
    journal: [u64; 512],
    bindings: Vec<HistoryBinding>,
    high: u64,
}
fn journal(rows: &[NormalModuleRecord]) -> [u64; 512] {
    let mut p = [0; 512];
    p[..4].copy_from_slice(&[rows.len() as u64 * 2, 0, 12, 0]);
    for (i, row) in rows.iter().enumerate() {
        let r = row.record;
        let (raw, pre) = (r.raw, r.history_prefix);
        let (kind, g, slot, reason) = match raw.owner {
            RawIntervalOwner::Sampled {
                generation,
                invocation,
            } => (1, generation, invocation as u64 + 1, 0),
            RawIntervalOwner::FunctionClosed { generation } => (3, generation, 0, 3),
            _ => panic!(),
        };
        let bits = slot | ((pre & 511) << 13) | (reason << 22) | ((pre >> 9) << 24);
        let at = 4 + 14 * i;
        p[at..at + 7].copy_from_slice(&[
            kind,
            raw.ordinal,
            raw.entry_pc,
            r.entry_rsp,
            r.return_word,
            g,
            bits,
        ]);
        p[at + 7..at + 14].copy_from_slice(&[
            kind + 1,
            raw.ordinal,
            raw.return_pc,
            r.entry_rsp,
            r.return_word,
            g,
            bits,
        ]);
    }
    p
}
fn fixture(k: usize, hot: usize) -> (check::Population, Vec<Batch>, [GenerationId; 2]) {
    let ids = std::array::from_fn(|_| {
        Epoch::new(
            &FUNCTIONS,
            Config {
                retained_per_function: k,
                max_inflight: 1,
                max_invocations: k * 2,
            },
        )
        .unwrap()
        .id()
    });
    let p = check::Population {
        k,
        hot,
        generations: ids.map(|id| id.get()),
        entries: [0x1000, 0x1080],
        ends: [0x1050, 0x10c0],
        returns: [vec![0x1040], vec![0x10b0]],
        id: worker::Identity {
            pid: 11,
            tid: 12,
            cpu: 1,
            stack: (0x8000, 0xa000),
            caller: (0x2000, 0x3000),
        },
        rows: Vec::with_capacity(k + 3),
        totals: NormalTotals::default(),
        batches: 0,
    };
    let mut batches = Vec::new();
    let mut ordinal = 1usize;
    let mut totals = NormalTotals::default();
    let h = k.div_ceil(4);
    for n in 1..=h + 2 {
        let count = if n <= h {
            (k - (n - 1) * 4).min(4)
        } else if n == h + 1 {
            1
        } else {
            2
        };
        let before = totals;
        let mut rows = Vec::new();
        let mut bindings = Vec::new();
        for i in 0..count {
            let f = if ordinal == k + 1 || ordinal == k + 3 {
                1 - hot
            } else {
                hot
            };
            let second = ordinal == k + 3;
            let generation = ids[usize::from(second)];
            let closed = ordinal == k + 2;
            let prefix = if second { 2 } else { 1 };
            rows.push(NormalModuleRecord {
                function: FUNCTIONS[f],
                record: NormalRecord {
                    raw: RawInterval {
                        ordinal: ordinal as u64,
                        entry_pc: p.entries[f],
                        return_pc: p.returns[f][0],
                        owner: if closed {
                            RawIntervalOwner::FunctionClosed {
                                generation: generation.get(),
                            }
                        } else {
                            RawIntervalOwner::Sampled {
                                generation: generation.get(),
                                invocation: if second { 0 } else { ordinal - 1 },
                            }
                        },
                        start: RawTimestamp {
                            ticks: if ordinal == 1 { u64::MAX } else { 0 },
                            aux: 3,
                        },
                        end: RawTimestamp {
                            ticks: 0,
                            aux: if ordinal == k + 3 { u32::MAX } else { 3 },
                        },
                    },
                    entry_rsp: 0x9008,
                    return_word: 0x2005,
                    history_prefix: prefix,
                    acknowledgement: if i + 1 == count {
                        NormalAcknowledgement::CallerCheckpoint
                    } else {
                        NormalAcknowledgement::NextEntry {
                            ordinal: ordinal as u64 + 1,
                        }
                    },
                },
            });
            bindings.push(HistoryBinding::Published {
                action_index: prefix - 1,
                generation,
            });
            totals.entered += 1;
            totals.ret_observed += 1;
            totals.confirmed += 1;
            totals.completed += u64::from(!closed);
            totals.unsampled += u64::from(closed);
            ordinal += 1;
        }
        let meta = check::Metadata {
            identity: identity(p.entries[0]),
            functions: FUNCTIONS,
            entries: p.entries,
            pid: 11,
            tid: 12,
            registration: 1,
            install: INSTALL,
            number: n as u64,
            totals: (before, totals),
            sequences: (before.completed, totals.completed),
            next: ordinal as u64,
        };
        batches.push(Batch {
            meta,
            journal: journal(&rows),
            rows,
            bindings,
            high: if n == h + 2 { 3 } else { 1 },
        });
    }
    (p, batches, ids)
}
fn join(p: &mut check::Population, b: &Batch) {
    p.join(b.meta, &b.rows, &b.journal, &b.bindings, b.high);
}
fn observation(seen: super::super::check::Seen, generation: GenerationId) -> RecordObservation {
    let RawIntervalOwner::Sampled { invocation, .. } = seen.row.record.raw.owner else {
        panic!()
    };
    let raw = seen.row.record.raw;
    let a = Admission {
        generation,
        invocation,
        function: seen.row.function,
        entry_value: raw.start.ticks,
    };
    let end = if raw.start.aux != raw.end.aux {
        Observation::Unavailable(1)
    } else if raw.end.ticks < raw.start.ticks {
        Observation::Unavailable(2)
    } else {
        Observation::Value(raw.end.ticks)
    };
    RecordObservation {
        record: Record {
            admission: a,
            terminal: Some(Terminal::Completed {
                value: invocation as u64,
                disposition: Disposition::Retained {
                    rank: seen.rank.unwrap(),
                },
            }),
        },
        payload: Some(Payload {
            admission: a,
            thread: 1,
            start_sequence: seen.sequence,
            outcome: PayloadOutcome::Completed {
                end,
                completed_children: 0,
            },
        }),
    }
}

// Independent complete table: production constructs these fields from Engine,
// worker messages and actual completed operations, not from this fixture.
fn phase_fixture(k: usize, phase: usize) -> check::PhaseState {
    let k = k as u64;
    let h = k.div_ceil(4);
    let (
        n,
        confirmed,
        completed,
        unsampled,
        batches,
        banks,
        current,
        history,
        reports,
        copies,
        refusals,
        a_slot,
        b_slot,
        a_index,
        a_output,
        checkpoints,
        reclaimed,
        b_report,
        detach,
        joins,
    ) = match phase {
        0 => (k, k, k, 0, h, 2, 17, 1, 0, 0, 0, 1, 0, 0, 0, h, 0, 0, 0, 0),
        1 => (
            k + 1,
            k + 1,
            k + 1,
            0,
            h + 1,
            2,
            17,
            1,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            h + 1,
            0,
            0,
            0,
            0,
        ),
        2 => (
            k + 2,
            k + 1,
            k + 1,
            0,
            h + 1,
            2,
            17,
            1,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            h + 1,
            0,
            0,
            0,
            0,
        ),
        3 => (
            k + 2,
            k + 1,
            k + 1,
            0,
            h + 1,
            1,
            29,
            2,
            1,
            1,
            2,
            1,
            1,
            1,
            1,
            h + 1,
            0,
            0,
            0,
            0,
        ),
        4 => (
            k + 3,
            k + 2,
            k + 1,
            1,
            h + 1,
            2,
            0,
            3,
            1,
            1,
            2,
            0,
            1,
            0,
            0,
            h + 1,
            1,
            1,
            0,
            0,
        ),
        5 => (
            k + 3,
            k + 3,
            k + 2,
            1,
            h + 2,
            3,
            0,
            3,
            2,
            1,
            2,
            0,
            0,
            0,
            0,
            h + 3,
            1,
            2,
            1,
            1,
        ),
        _ => panic!(),
    };
    check::PhaseState {
        totals: NormalTotals {
            entered: n,
            ret_observed: n,
            confirmed,
            completed,
            unsampled,
        },
        batches,
        banks,
        current,
        history,
        reports,
        copies,
        refusals,
        a_slot,
        b_slot,
        a_index,
        a_output,
        checkpoints,
        reclaimed,
        b_report,
        detach,
        joins,
    }
}

#[test]
fn owner_phases_require_two_refusals_and_reclaim_before_checkpoint() {
    for k in [10, 1000] {
        for phase in 0..6 {
            let expected = phase_fixture(k, phase);
            expected.check(k, phase, [17, 29]);
            let mut changed = expected;
            changed.checkpoints += 1;
            refuse(|| changed.check(k, phase, [17, 29]));
            let mut changed = expected;
            changed.totals.confirmed += 1;
            refuse(|| changed.check(k, phase, [17, 29]));
        }
        for refusals in [0, 1, 3] {
            let mut changed = phase_fixture(k, 3);
            changed.refusals = refusals;
            refuse(|| changed.check(k, 3, [17, 29]));
        }
        for alter in 0..4 {
            let mut changed = phase_fixture(k, 4);
            match alter {
                0 => changed.reclaimed = 0,
                1 => changed.b_slot = 0,
                2 => changed.b_report = 2,
                _ => changed.a_slot = 1,
            }
            refuse(|| changed.check(k, 4, [17, 29]));
        }
    }
}
#[test]
fn owner_population_preserves_hot_cold_slots_ranks_and_sequences() {
    for k in [10, 1000] {
        for hot in [0, 1] {
            let (mut p, batches, ids) = fixture(k, hot);
            for b in &batches {
                join(&mut p, b);
            }
            assert_eq!(p.totals, check::expected_totals(k, 5));
            assert_eq!(p.rows.len(), k + 3);
            assert_eq!(p.rows[k + 1].rank, None);
            assert_eq!((p.rows[k].rank, p.rows[k + 2].rank), (Some(0), Some(0)));
            assert_eq!(
                (p.rows[k + 1].sequence, p.rows[k + 2].sequence),
                (k as u64 + 1, k as u64 + 1)
            );
            for (i, s) in p.rows.iter().enumerate().filter(|(_, s)| s.rank.is_some()) {
                let row = observation(*s, ids[usize::from(i == k + 2)]);
                super::super::check::sample(&row, *s);
                let mut changed = row;
                changed.payload.as_mut().unwrap().start_sequence += 1;
                refuse(|| {
                    super::super::check::sample(&changed, *s);
                });
            }
        }
    }
    for mutation in 0..8 {
        let (mut p, mut batches, _) = fixture(10, 0);
        for b in &batches[..4] {
            join(&mut p, b);
        }
        let b = &mut batches[4];
        match mutation {
            0 => b.rows[0].function = FUNCTIONS[1],
            1 => {
                b.rows[0].record.raw.owner = RawIntervalOwner::Sampled {
                    generation: p.generations[0],
                    invocation: 11,
                }
            }
            2 => {
                b.rows[1].record.raw.owner = RawIntervalOwner::Sampled {
                    generation: p.generations[1],
                    invocation: 1,
                }
            }
            3 => b.rows[1].record.history_prefix = 1,
            4 => b.rows[0].record.acknowledgement = NormalAcknowledgement::CallerCheckpoint,
            5 => b.rows[1].record.entry_rsp = 0x8008,
            6 => b.meta.sequences.0 += 1,
            _ => b.high = 2,
        }
        b.journal = journal(&b.rows);
        refuse(|| join(&mut p, b));
    }
}
#[test]
fn owner_snapshot_refusals_keep_all_retained_state() {
    struct Token {
        generation: u64,
        address: Box<u64>,
    }
    impl Identity for Token {
        fn generation(&self) -> u64 {
            self.generation
        }
    }
    let (mut p, batches, ids) = fixture(10, 0);
    for b in &batches[..4] {
        join(&mut p, b);
    }
    let records = p
        .rows
        .iter()
        .map(|s| observation(*s, ids[0]))
        .collect::<Vec<_>>();
    let mut slot = Slot::new(Token {
        generation: ids[0].get(),
        address: Box::new(17),
    });
    let address = slot.epoch().address.as_ref() as *const u64;
    slot.copied(ids[0].get(), 0, format!("REPORT,{},11\n", ids[0].get()));
    slot.emit(|_| Ok(())).unwrap();
    let held = check::Held {
        slot: slot.snapshot(),
        reports: vec![(ids[0].get(), records)],
        history: vec![check::HistorySnapshot {
            number: 1,
            range: 0..1,
            before: HistoryBinding::Initial,
            after: HistoryBinding::Published {
                action_index: 0,
                generation: ids[0],
            },
            actions: vec![Action {
                kind: ActionKind::Published,
                generation: ids[0],
                function: None,
                current: Some(ids[0]),
                group: None,
            }],
        }],
        banks: 1,
        current: Some(1),
        worker: WorkerState {
            totals: check::expected_totals(10, 2),
            checkpoints: 4,
        },
    };
    for _ in 0..2 {
        let bank: Option<()> = slot
            .reclaim(|t| Err((EpochStorageReclaimError::SharedOwner, t)))
            .unwrap();
        assert!(bank.is_none());
        assert_eq!(slot.epoch().address.as_ref() as *const u64, address);
        let mut after = held.clone();
        after.slot = slot.snapshot();
        held.unchanged(&after);
    }
    for mutation in 0..7 {
        let mut changed = held.clone();
        match mutation {
            0 => changed.slot.generation += 1,
            1 => changed.slot.copied.as_mut().unwrap().1 += 1,
            2 => changed.slot.copied.as_mut().unwrap().2.push('x'),
            3 => changed.reports[0].1[0].payload.as_mut().unwrap().thread = 2,
            4 => changed.history[0].actions.clear(),
            5 => changed.banks += 1,
            _ => changed.worker.checkpoints += 1,
        }
        refuse(|| held.unchanged(&changed));
    }
    let bank = slot.reclaim(|t| Ok(t.address)).unwrap().unwrap();
    assert_eq!(bank.as_ref() as *const u64, address);
}
#[test]
fn owner_completion_refuses_wrong_identity_missing_calls_and_renewed_deadline() {
    for mutation in 0..5 {
        let (mut p, mut b, _) = fixture(10, 1);
        match mutation {
            0 => b[0].meta.tid += 1,
            1 => b[0].meta.functions.swap(0, 1),
            2 => b[0].meta.entries.swap(0, 1),
            3 => {
                b[0].rows.pop();
            }
            _ => b[0].journal[511] = 1,
        }
        refuse(|| join(&mut p, &b[0]));
    }
    let mut completed = phase_fixture(10, 5);
    completed.totals.completed -= 1;
    refuse(|| completed.check(10, 5, [17, 29]));
    let start = Instant::now();
    let deadline = Deadline::new(start);
    assert!(deadline.check_at(start).is_ok());
    assert!(deadline.check_at(start + Duration::from_secs(15)).is_err());
    let mut renewed = deadline;
    renewed.end += Duration::from_nanos(1);
    assert!(renewed.check_at(start).is_err());
    // The actual transport helper returns the unsent object, including timeout.
    let (tx, rx) = mpsc::sync_channel(1);
    tx.send(Box::new(1)).unwrap();
    drop(rx);
    let retained = Box::new(2);
    let pointer = retained.as_ref() as *const i32;
    let (_, returned) = send_owned(&tx, retained, deadline).unwrap_err();
    assert_eq!(returned.as_ref() as *const i32, pointer);
}
