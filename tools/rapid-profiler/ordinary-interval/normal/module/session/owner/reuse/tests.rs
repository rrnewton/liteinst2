//! Fabricated metadata exercises actual validators; no native owner or receipt is invented.
//! Real Epoch values supply generation IDs only. Actual return/Arc custody remains UNRUN.
use super::*;
use rapid_profiler::frontend::Payload;
use rapid_profiler::frontend_native::{
    HistoryBinding, NormalModuleRecord, NormalRecord, RawTimestamp,
};
use rapid_profiler::generation::{Admission, Epoch, GenerationId, Record};
use shared::epoch_storage::{OutputSnapshot, SlotSnapshot};
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
fn fixture(k: usize, hot: usize) -> (check::Population, Vec<Batch>, [GenerationId; 3]) {
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
        rows: Vec::with_capacity(k + 5),
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
            4
        };
        let before = totals;
        let mut rows = Vec::new();
        let mut bindings = Vec::new();
        for i in 0..count {
            let f = if ordinal == k + 1 || ordinal == k + 3 || ordinal == k + 5 {
                1 - hot
            } else {
                hot
            };
            let epoch = if ordinal <= k + 2 {
                0
            } else if ordinal == k + 3 {
                1
            } else {
                2
            };
            let generation = ids[epoch];
            let closed = ordinal == k + 2;
            let prefix = epoch as u64 + 1;
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
                                invocation: match epoch {
                                    0 => ordinal - 1,
                                    1 => 0,
                                    _ => ordinal - k - 4,
                                },
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
            high: if n == h + 2 { 4 } else { 1 },
        });
    }
    (p, batches, ids)
}
fn join(p: &mut check::Population, b: &Batch) {
    p.join(b.meta, &b.rows, &b.journal, &b.bindings, b.high);
}
fn observation(
    seen: super::super::super::check::Seen,
    generation: GenerationId,
) -> RecordObservation {
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

fn reports(p: &check::Population, ids: [GenerationId; 3]) -> Vec<(u64, Vec<RecordObservation>)> {
    ids.into_iter()
        .map(|id| {
            let rows = p
                .rows
                .iter()
                .filter_map(|s| match s.row.record.raw.owner {
                    RawIntervalOwner::Sampled { generation, .. } if generation == id.get() => {
                        Some(observation(*s, id))
                    }
                    _ => None,
                })
                .collect();
            (id.get(), rows)
        })
        .collect()
}
fn complete(k: usize, hot: usize) -> (check::Population, [GenerationId; 3]) {
    let (mut p, batches, ids) = fixture(k, hot);
    for b in &batches {
        join(&mut p, b);
    }
    (p, ids)
}
fn final_batch_mutation(change: impl FnOnce(&mut check::Population, &mut Batch)) {
    let (mut p, mut batches, _) = fixture(10, 0);
    for b in &batches[..4] {
        join(&mut p, b);
    }
    let b = &mut batches[4];
    change(&mut p, b);
    b.journal = journal(&b.rows);
    refuse(|| join(&mut p, b));
}
#[test]
fn recycled_population_requires_new_generation_and_both_function_rank_zero() {
    for k in [10, 1000] {
        for hot in [0, 1] {
            let (p, ids) = complete(k, hot);
            assert_eq!(p.totals, check::expected_totals(k, 7));
            assert_eq!(p.rows.len(), k + 5);
            assert_eq!(p.rows[k + 1].rank, None);
            assert_eq!((p.rows[k + 3].rank, p.rows[k + 4].rank), (Some(0), Some(0)));
            assert_eq!(
                (p.rows[k + 3].sequence, p.rows[k + 4].sequence),
                (k as u64 + 2, k as u64 + 3)
            );
            let copies = reports(&p, ids);
            assert_eq!(
                copies.iter().map(|r| r.1.len()).collect::<Vec<_>>(),
                vec![k + 1, 1, 2]
            );
            for (g, rows) in &copies {
                super::super::super::check::report_shape(*g, rows, k * 2);
                for row in rows {
                    let s = p
                        .rows
                        .iter()
                        .find(|s| {
                            s.row.record.raw.owner
                                == RawIntervalOwner::Sampled {
                                    generation: *g,
                                    invocation: row.record.admission.invocation,
                                }
                        })
                        .unwrap();
                    super::super::super::check::sample(row, *s);
                }
            }
            for mutation in 0..6 {
                let mut changed = copies[2].1.clone();
                match mutation {
                    0 => {
                        changed[0].record.terminal = Some(Terminal::Completed {
                            value: 0,
                            disposition: Disposition::Retained { rank: 1 },
                        })
                    }
                    1 => changed[1].record.admission.function = FUNCTIONS[hot],
                    2 => changed[0].payload.as_mut().unwrap().start_sequence -= 1,
                    3 => {
                        changed[1].payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                            end: Observation::Value(1),
                            completed_children: 0,
                        }
                    }
                    4 => changed[0].record.admission.generation = ids[0],
                    _ => changed[0].payload.as_mut().unwrap().admission.invocation = 1,
                }
                refuse(|| {
                    super::super::super::check::report_shape(copies[2].0, &changed, k * 2);
                    for (row, s) in changed.iter().zip(&p.rows[k + 3..]) {
                        super::super::super::check::sample(row, *s);
                    }
                });
            }
        }
    }
    for mutation in 0..6 {
        final_batch_mutation(|p, b| match mutation {
            0 => {
                b.rows[2].record.raw.owner = RawIntervalOwner::Sampled {
                    generation: p.generations[0],
                    invocation: 0,
                }
            }
            1 => {
                b.rows[3].record.raw.owner = RawIntervalOwner::Sampled {
                    generation: p.generations[2],
                    invocation: 0,
                }
            }
            2 => b.rows[2].function = FUNCTIONS[1],
            3 => b.rows[2].record.history_prefix = 2,
            4 => b.bindings[2] = b.bindings[1],
            _ => b.meta.sequences.1 += 1,
        });
    }
}
#[test]
fn recycled_transfer_checks_every_journal_word_and_final_four_acknowledgements() {
    // Mutation reaches the actual shared all-512-word validator through Population::join.
    for word in 0..512 {
        let (mut p, mut batches, _) = fixture(10, 0);
        for b in &batches[..4] {
            join(&mut p, b);
        }
        batches[4].journal[word] ^= 1;
        refuse(|| join(&mut p, &batches[4]));
    }
    for mutation in 0..14 {
        final_batch_mutation(|_, b| match mutation {
            0..=2 => {
                b.rows[mutation].record.acknowledgement = NormalAcknowledgement::CallerCheckpoint
            }
            3 => {
                b.rows[3].record.acknowledgement = NormalAcknowledgement::NextEntry { ordinal: 16 }
            }
            4 => {
                b.rows[0].record.acknowledgement = NormalAcknowledgement::NextEntry { ordinal: 14 }
            }
            5 => b.rows[2].record.raw.return_pc = 0x10b0, // Otherwise legal RET of the wrong function.
            6 => b.rows[2].record.return_word = 0x3000,
            7 => b.rows[2].record.entry_rsp = 0x8008,
            8 => b.rows.swap(1, 2),
            9 => {
                b.rows.pop();
            }
            10 => b.rows[2] = b.rows[1],
            11 => b.meta.tid += 1,
            12 => b.high = 3,
            _ => b.meta.totals.1.completed -= 1,
        });
    }
}
#[test]
fn old_report_copy_remains_exact_after_restage_and_new_completions() {
    let (p, ids) = complete(10, 0);
    let copies = reports(&p, ids);
    // Data-only snapshot: no Slot token, loaded owner, SDK receipt or Report is fabricated.
    let old = check::OldCopy {
        slot: SlotSnapshot {
            generation: ids[0].get(),
            copied: Some((
                ids[0].get(),
                0,
                format!("REPORT,{},11\n", ids[0].get()),
                OutputSnapshot::Emitted,
            )),
        },
        report: copies[0].clone(),
    };
    for len in 1..=3 {
        old.check(&copies[..len]);
    }
    for mutation in 0..9 {
        let mut changed = old.clone();
        match mutation {
            0 => changed.slot.generation = ids[2].get(),
            1 => changed.slot.copied.as_mut().unwrap().0 = ids[2].get(),
            2 => changed.slot.copied.as_mut().unwrap().1 = 2,
            3 => changed.slot.copied.as_mut().unwrap().2.push('x'),
            4 => changed.slot.copied.as_mut().unwrap().3 = OutputSnapshot::Pending,
            5 => changed.slot.copied.as_mut().unwrap().3 = OutputSnapshot::Failed("sticky".into()),
            6 => changed.report.1[0].payload.as_mut().unwrap().thread += 1,
            7 => {
                changed.report.1[0].payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                    end: Observation::Value(0),
                    completed_children: 0,
                }
            }
            _ => changed.slot.copied = None,
        }
        refuse(|| changed.check(&copies));
    }
    let mut changed = copies.clone();
    changed.swap(0, 2);
    refuse(|| old.check(&changed));
    let mut changed = copies.clone();
    changed[0].1.pop();
    refuse(|| old.check(&changed));
    old.check(&copies); // Growing B/C copies cannot refresh or replace A's original pin.
}
// Independent phase observations, not PhaseState::expected used as test input.
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
        c_slot,
        a_index,
        a_output,
        checkpoints,
        reclaimed,
        restaged,
        b_report,
        c_report,
        stable,
        detach,
        joins,
    ) = match phase {
        0 => (
            k, k, k, 0, h, 2, 17, 1, 0, 0, 0, 1, 0, 0, 0, 0, h, 0, 0, 0, 0, 0, 0, 0,
        ),
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
            0,
            h + 1,
            0,
            0,
            0,
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
            0,
            h + 1,
            0,
            0,
            0,
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
            0,
            1,
            1,
            h + 1,
            0,
            0,
            0,
            0,
            1,
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
            29,
            2,
            1,
            1,
            2,
            0,
            1,
            0,
            1,
            1,
            h + 1,
            1,
            0,
            0,
            0,
            1,
            0,
            0,
        ),
        5 => (
            k + 3,
            k + 2,
            k + 1,
            1,
            h + 1,
            1,
            41,
            3,
            1,
            1,
            2,
            0,
            1,
            1,
            1,
            1,
            h + 1,
            1,
            1,
            1,
            0,
            1,
            0,
            0,
        ),
        6 => (
            k + 5,
            k + 4,
            k + 3,
            1,
            h + 1,
            2,
            0,
            4,
            2,
            1,
            2,
            0,
            0,
            1,
            1,
            1,
            h + 1,
            1,
            1,
            2,
            1,
            1,
            0,
            0,
        ),
        7 => (
            k + 5,
            k + 5,
            k + 4,
            1,
            h + 2,
            3,
            0,
            4,
            3,
            1,
            2,
            0,
            0,
            0,
            1,
            1,
            h + 3,
            1,
            1,
            2,
            2,
            1,
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
        c_slot,
        a_index,
        a_output,
        checkpoints,
        reclaimed,
        restaged,
        b_report,
        c_report,
        stable,
        detach,
        joins,
    }
}
#[test]
fn reuse_phase_order_and_generation_bound_slot_state_are_exact() {
    for k in [10, 1000] {
        for phase in 0..8 {
            let expected = phase_fixture(k, phase);
            expected.check(k, phase, [17, 29, 41]);
            refuse(|| expected.check(k, (phase + 1) % 8, [17, 29, 41]));
            for field in 0..13 {
                let mut bad = expected;
                match field {
                    0 => bad.totals.confirmed += 1,
                    1 => bad.banks += 1,
                    2 => bad.current += 1,
                    3 => bad.history += 1,
                    4 => bad.copies += 1,
                    5 => bad.refusals += 1,
                    6 => bad.a_slot ^= 1,
                    7 => bad.c_slot ^= 1,
                    8 => bad.checkpoints += 1,
                    9 => bad.b_report = (bad.b_report + 1) % 3,
                    10 => bad.c_report = (bad.c_report + 1) % 3,
                    11 => bad.stable ^= 1,
                    _ => bad.restaged ^= 1,
                }
                refuse(|| bad.check(k, phase, [17, 29, 41]));
            }
        }
    }
    let empty_c = SlotSnapshot {
        generation: 41,
        copied: None,
    };
    check::before_restage([None, Some(29), None], Some(1), 2, 0, 1, [17, 29]);
    check::after_restage(
        [Some(41), Some(29), None],
        Some(0),
        1,
        0,
        1,
        [17, 29, 41],
        &empty_c,
    );
    for slots in [
        [Some(17), Some(29), None],
        [None, Some(29), Some(47)],
        [None, None, None],
    ] {
        refuse(|| check::before_restage(slots, Some(1), 2, 0, 1, [17, 29]));
    }
    refuse(|| check::before_restage([None, Some(29), None], Some(0), 2, 0, 1, [17, 29]));
    refuse(|| check::before_restage([None, Some(29), None], Some(1), 1, 0, 1, [17, 29]));
    for g in [17, 29] {
        refuse(|| {
            check::after_restage(
                [Some(g), Some(29), None],
                Some(0),
                1,
                0,
                1,
                [17, 29, g],
                &empty_c,
            )
        });
    }
    refuse(|| {
        check::after_restage(
            [None, Some(29), Some(41)],
            Some(2),
            1,
            0,
            1,
            [17, 29, 41],
            &empty_c,
        )
    });
    refuse(|| {
        check::after_restage(
            [Some(41), Some(29), None],
            Some(0),
            2,
            0,
            1,
            [17, 29, 41],
            &empty_c,
        )
    });
    let stale = SlotSnapshot {
        generation: 41,
        copied: Some((17, 0, "REPORT,17,11\n".into(), OutputSnapshot::Emitted)),
    };
    refuse(|| {
        check::after_restage(
            [Some(41), Some(29), None],
            Some(0),
            1,
            0,
            1,
            [17, 29, 41],
            &stale,
        )
    });
}
#[test]
fn reuse_deadline_and_channel_refusals_retain_owned_values() {
    let start = Instant::now();
    let deadline = Deadline::new(start);
    assert!(deadline.check_at(start).is_ok());
    assert!(
        deadline
            .check_at(start + Duration::from_secs(15) - Duration::from_nanos(1))
            .is_ok()
    );
    assert!(deadline.check_at(start + Duration::from_secs(15)).is_err());
    assert!(deadline.check_at(start - Duration::from_nanos(1)).is_err());
    let mut renewed = deadline;
    renewed.end += Duration::from_nanos(1);
    assert!(renewed.check_at(start).is_err());
    let value = Arc::new(input::Record::new(1, b"a,b,c").unwrap());
    let pointer = Arc::as_ptr(&value);
    // Real accepted input ownership, never a simulated epoch/SDK receipt.
    let mut retained = Some(value);
    let refusal: Result<(), &str> =
        shared::epoch_storage::transfer(&mut retained, |v| Err(("refused", v)));
    assert_eq!(refusal, Err("refused"));
    assert_eq!(Arc::as_ptr(retained.as_ref().unwrap()), pointer);
    retained.as_ref().unwrap().check();
    let (tx, rx) = mpsc::sync_channel(1);
    tx.send(Arc::new(input::Record::new(2, b"x,y").unwrap()))
        .unwrap();
    let expired = Deadline::new(start - Duration::from_secs(16));
    let (_, returned) = send_owned(&tx, retained.take().unwrap(), expired).unwrap_err();
    assert_eq!(Arc::as_ptr(&returned), pointer);
    assert_eq!(rx.try_recv().unwrap().id, 2); // No replacement/discard of the full queue's value.
    drop(rx);
    let (_, returned) = send_owned(&tx, returned, Deadline::new(Instant::now())).unwrap_err();
    assert_eq!(Arc::as_ptr(&returned), pointer);
    returned.check();
    let mut retained = Some(returned);
    let moved = shared::epoch_storage::transfer(&mut retained, Ok::<_, (&str, Arc<input::Record>)>)
        .unwrap();
    assert!(retained.is_none());
    assert_eq!(Arc::as_ptr(&moved), pointer);
    moved.check();
}
