//! Fabricated copies exercise production joins; no opaque owner/native authority.
use super::*;
use crate::oracle::native_ordinary::normal_caller::{JournalReady, module::Function, rust_invoke};
use rapid_profiler::frontend::Payload;
use rapid_profiler::frontend_native::{NormalRecord, RawInterval, RawTimestamp};
use rapid_profiler::generation::{Admission, Config, Epoch, Record};
use std::panic::{AssertUnwindSafe, catch_unwind};
fn refuses(f: impl FnOnce()) {
    assert!(catch_unwind(AssertUnwindSafe(f)).is_err());
}
fn ready(subset: u8, k: usize, operation: usize) -> (Ready, GenerationId) {
    let selections =
        [0x3080, 0x3000, 0x30c0, 0x3040].map(|elf_va| copied::Selection { elf_va, extent: 6 });
    let case = copied::Case::new(subset, k, operation, 0, selections);
    let ids: Vec<_> = case
        .table()
        .iter()
        .map(|(i, _)| FunctionId(copied::FUNCTION_IDS[*i]))
        .collect();
    let id = Epoch::new(
        &ids,
        Config {
            retained_per_function: k,
            max_inflight: 1,
            max_invocations: case.n() * k,
        },
    )
    .unwrap()
    .id();
    let plan = rust_invoke::admit(&[
        0x53, 0x48, 0x89, 0xcb, 0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6, 0xff, 0xd0,
        0x48, 0x89, 0x03, 0x5b, 0xc3,
    ])
    .unwrap();
    let functions = case
        .table()
        .iter()
        .map(|(_, s)| {
            let entry = s.elf_va;
            Function {
                entry,
                heads: vec![entry, entry + 5],
                returns: vec![entry + 5],
                boundaries: vec![(entry, entry), (entry + 5, entry + 5)],
            }
        })
        .collect();
    (
        Ready {
            caller: 0x1080,
            caller_immutable: vec![],
            functions,
            immutable: vec![],
            original_sources: vec![],
            journal: Some(JournalReady {
                address: 0x7000,
                a_generation: id.get(),
                b_generation: None,
                helper_tid: None,
            }),
            case,
            plan,
        },
        id,
    )
}
fn row(r: &Ready, id: GenerationId, clock: usize) -> (NormalModuleRecord, RecordObservation) {
    let (start, end, observation) = match clock {
        0 => (
            RawTimestamp { ticks: 0, aux: 1 },
            RawTimestamp {
                ticks: u64::MAX,
                aux: 1,
            },
            Observation::Value(u64::MAX),
        ),
        1 => (
            RawTimestamp { ticks: 0, aux: 1 },
            RawTimestamp { ticks: 0, aux: 1 },
            Observation::Value(0),
        ),
        2 => (
            RawTimestamp { ticks: 1, aux: 1 },
            RawTimestamp { ticks: 0, aux: 2 },
            Observation::Unavailable(1),
        ),
        _ => (
            RawTimestamp { ticks: 1, aux: 1 },
            RawTimestamp { ticks: 0, aux: 1 },
            Observation::Unavailable(2),
        ),
    };
    let row = NormalModuleRecord {
        function: FunctionId(r.case.function_id()),
        record: NormalRecord {
            raw: RawInterval {
                ordinal: 1,
                entry_pc: r.target().entry,
                return_pc: r.target().returns[0],
                owner: RawIntervalOwner::Sampled {
                    generation: id.get(),
                    invocation: 0,
                },
                start,
                end,
            },
            entry_rsp: 0x8ff8,
            return_word: 0x108f,
            history_prefix: 1,
            acknowledgement: NormalAcknowledgement::CallerCheckpoint,
        },
    };
    let a = Admission {
        generation: id,
        function: row.function,
        invocation: 0,
        entry_value: start.ticks,
    };
    (
        row,
        RecordObservation {
            record: Record {
                admission: a,
                terminal: Some(Terminal::Completed {
                    value: 0,
                    disposition: Disposition::Retained { rank: 0 },
                }),
            },
            payload: Some(Payload {
                admission: a,
                thread: 1,
                start_sequence: 0,
                outcome: PayloadOutcome::Completed {
                    end: observation,
                    completed_children: 0,
                },
            }),
        },
    )
}
fn meta(r: &Ready) -> Metadata {
    Metadata {
        identity: identity(r.functions[0].entry),
        functions: functions(r),
        entries: r.functions.iter().map(|f| f.entry).collect(),
        pid: 17,
        tid: 17,
        registration: 1,
        install: INSTALL,
        number: 1,
        next: 2,
        sequences: (0, 1),
        totals: (NormalTotals::default(), totals(1)),
    }
}
#[test]
fn leaf_set_batch_joins_all_identity_rank_sequence_and_journal_words() {
    for subset in [1, 3, 7, 15] {
        for k in [10, 1000] {
            for operation in 0..4 {
                if subset & (1 << operation) == 0 {
                    continue;
                }
                let (r, id) = ready(subset, k, operation);
                let m = meta(&r);
                metadata(&r, 17, m.clone());
                for field in 0..14 {
                    let mut bad = m.clone();
                    match field {
                        0 => bad.identity.mapping += 1,
                        1 => bad.functions[0].0 += 1,
                        2 => bad.entries[0] += 1,
                        3 => bad.pid += 1,
                        4 => bad.tid += 1,
                        5 => bad.registration += 1,
                        6 => bad.install += 1,
                        7 => bad.number += 1,
                        8 => bad.next += 1,
                        9 => bad.sequences.0 += 1,
                        10 => bad.sequences.1 += 1,
                        11 => bad.totals.0.entered += 1,
                        12 => bad.totals.1.unsampled += 1,
                        _ => {
                            bad.functions.pop();
                        }
                    }
                    refuses(|| metadata(&r, 17, bad));
                }
                for clock in 0..4 {
                    let (row, record) = row(&r, id, clock);
                    let words =
                        copied::journal_words(&r, 17, 0x9008, &[row.record.raw.return_pc], false);
                    rows(&r, 0x9008, 17, &[row], &words);
                    records(&r, &[row], id.get(), &[record]);
                    for field in 0..10 {
                        let mut bad = row;
                        match field {
                            0 => bad.function.0 += 1,
                            1 => bad.record.raw.ordinal += 1,
                            2 => bad.record.raw.entry_pc += 1,
                            3 => bad.record.raw.return_pc -= 1,
                            4 => {
                                bad.record.raw.owner = RawIntervalOwner::Sampled {
                                    generation: id.get(),
                                    invocation: 1,
                                }
                            }
                            5 => bad.record.entry_rsp += 8,
                            6 => bad.record.return_word += 1,
                            7 => bad.record.history_prefix = 0,
                            8 => {
                                bad.record.acknowledgement =
                                    NormalAcknowledgement::NextEntry { ordinal: 2 }
                            }
                            _ => {
                                bad.record.raw.owner = RawIntervalOwner::FunctionClosed {
                                    generation: id.get(),
                                }
                            }
                        }
                        refuses(|| rows(&r, 0x9008, 17, &[bad], &words));
                    }
                    if clock == 0 {
                        for i in 0..512 {
                            let mut bad = words;
                            bad[i] ^= 1;
                            refuses(|| rows(&r, 0x9008, 17, &[row], &bad));
                        }
                    }
                    refuses(|| rows(&r, 0x9008, 17, &[], &words));
                    refuses(|| rows(&r, 0x9008, 17, &[row, row], &words));
                }
            }
        }
    }
}
#[test]
fn leaf_set_history_report_and_reclaim_require_complete_state() {
    for subset in [1, 3, 7, 15] {
        for k in [10, 1000] {
            let operation = (0..4).find(|i| subset & (1 << i) != 0).unwrap();
            let (r, id) = ready(subset, k, operation);
            for clock in 0..4 {
                let (row, record) = row(&r, id, clock);
                records(&r, &[row], id.get(), &[record]);
                for field in 0..12 {
                    let mut bad = record;
                    match field {
                        0 => bad.record.admission.function.0 += 1,
                        1 => bad.record.admission.invocation = 1,
                        2 => bad.record.admission.entry_value ^= 1,
                        3 => bad.record.terminal = None,
                        4 => {
                            bad.record.terminal = Some(Terminal::Completed {
                                value: 1,
                                disposition: Disposition::Retained { rank: 0 },
                            })
                        }
                        5 => {
                            bad.record.terminal = Some(Terminal::Completed {
                                value: 0,
                                disposition: Disposition::Retained { rank: 1 },
                            })
                        }
                        6 => bad.payload = None,
                        7 => bad.payload.as_mut().unwrap().thread = 2,
                        8 => bad.payload.as_mut().unwrap().start_sequence = 1,
                        9 => bad.payload.as_mut().unwrap().admission.invocation = 1,
                        10 => {
                            bad.payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                                end: Observation::Unavailable(9),
                                completed_children: 0,
                            }
                        }
                        _ => {
                            bad.payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                                end: Observation::Value(0),
                                completed_children: 1,
                            }
                        }
                    }
                    refuses(|| records(&r, &[row], id.get(), &[bad]));
                }
                refuses(|| records(&r, &[row], id.get(), &[]));
                refuses(|| records(&r, &[row], id.get(), &[record, record]));
                refuses(|| records(&r, &[row], id.get() + 1, &[record]));
            }
            let s = Stream {
                pid: 17,
                install: INSTALL,
                identity: identity(r.functions[0].entry),
                functions: functions(&r),
                entries: r.functions.iter().map(|f| f.entry).collect(),
                format: HistoryFormat::AbsoluteV1,
            };
            stream(&r, 17, &s);
            for field in 0..6 {
                let mut bad = s.clone();
                match field {
                    0 => bad.pid += 1,
                    1 => bad.install += 1,
                    2 => bad.identity.mapping += 1,
                    3 => bad.functions[0].0 += 1,
                    4 => bad.entries[0] += 1,
                    _ => {
                        bad.functions.pop();
                    }
                }
                refuses(|| stream(&r, 17, &bad));
            }
            let bound = HistoryBinding::Published {
                action_index: 0,
                generation: id,
            };
            let removed = HistoryBinding::Removed {
                action_index: 1,
                generation: id,
            };
            for published in [true, false] {
                let c = Chunk {
                    number: if published { 1 } else { 2 },
                    range: if published { 0..1 } else { 1..2 },
                    before: if published {
                        HistoryBinding::Initial
                    } else {
                        bound
                    },
                    after: if published { bound } else { removed },
                    actions: vec![Action {
                        kind: if published {
                            ActionKind::Published
                        } else {
                            ActionKind::Removed
                        },
                        generation: id,
                        function: None,
                        current: published.then_some(id),
                        group: None,
                    }],
                };
                chunk(id, published, &c);
                for field in 0..9 {
                    let mut bad = c.clone();
                    match field {
                        0 => bad.number += 1,
                        1 => bad.range.start += 1,
                        2 => bad.range.end += 1,
                        3 => bad.before = removed,
                        4 => bad.after = HistoryBinding::Initial,
                        5 => bad.actions[0].function = Some(FunctionId(r.case.function_id())),
                        6 => bad.actions[0].current = if published { None } else { Some(id) },
                        7 => bad.actions[0].kind = ActionKind::Deferred,
                        _ => bad.actions.clear(),
                    };
                    refuses(|| chunk(id, published, &bad));
                }
            }
            let w = Window {
                number: 2,
                range: 2..2,
                before: removed,
                after: removed,
                actions: vec![],
                status: ControllerStatus::Ready,
                current: None,
                enabled: vec![true],
                failed: None,
            };
            closed(removed, &w);
            for field in 0..7 {
                let mut bad = w.clone();
                match field {
                    0 => bad.number += 1,
                    1 => bad.range.end += 1,
                    2 => bad.before = bound,
                    3 => bad.after = bound,
                    4 => bad.current = Some(id),
                    5 => bad.enabled[0] = false,
                    _ => bad.failed = Some(id),
                }
                refuses(|| closed(removed, &bad));
            }
            banks(2, false);
            banks(3, true);
            refuses(|| banks(3, false));
            refuses(|| banks(2, true));
            watermark(1);
            refuses(|| watermark(0));
            refuses(|| watermark(2));
        }
    }
}
