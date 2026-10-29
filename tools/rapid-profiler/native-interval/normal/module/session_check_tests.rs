//! Fabricated copies exercise production joins; no executable/receipt authority.
use super::super::{Metadata, metadata};
use super::*;
use crate::oracle::native_ordinary::normal_caller::{JournalReady, module::Function};
use rapid_profiler::frontend::Payload;
use rapid_profiler::frontend_native::{NormalRecord, RawInterval, RawTimestamp};
use rapid_profiler::generation::{Admission, Config, Epoch, Record};
use std::panic::{AssertUnwindSafe, catch_unwind};
fn refuses(f: impl FnOnce()) {
    assert!(catch_unwind(AssertUnwindSafe(f)).is_err());
}
fn fixture(k: usize) -> (Ready, Vec<NormalModuleRecord>, Vec<RecordObservation>) {
    let id = Epoch::new(
        &FUNCTIONS,
        Config {
            retained_per_function: k,
            max_inflight: 1,
            max_invocations: k * 2,
        },
    )
    .unwrap()
    .id();
    let case = Case::new_session(0, k, 6, 6, 0);
    let ready = Ready {
        caller: 0x1000,
        caller_immutable: Vec::new(),
        functions: [0x3000, 0x3040].map(|entry| Function {
            entry,
            heads: vec![entry, entry + 5],
            returns: vec![entry + 5],
            boundaries: vec![(entry, entry), (entry + 5, entry + 5)],
        }),
        immutable: Vec::new(),
        original_source: Vec::new(),
        journal: Some(JournalReady {
            address: 0x7000,
            a_generation: id.get(),
            b_generation: None,
            helper_tid: None,
        }),
        case,
    };
    let rows: Vec<_> = (0..4)
        .map(|i| NormalModuleRecord {
            function: FUNCTIONS[i % 2],
            record: NormalRecord {
                raw: RawInterval {
                    ordinal: i as u64 + 1,
                    entry_pc: ready.target(i).entry,
                    return_pc: ready.target(i).returns[0],
                    owner: if i < case.admitted() {
                        RawIntervalOwner::Sampled {
                            generation: id.get(),
                            invocation: i,
                        }
                    } else {
                        RawIntervalOwner::FunctionClosed {
                            generation: id.get(),
                        }
                    },
                    start: RawTimestamp {
                        ticks: 10 + i as u64 * 10,
                        aux: 3,
                    },
                    end: RawTimestamp {
                        ticks: 15 + i as u64 * 10,
                        aux: 3,
                    },
                },
                entry_rsp: 0x9008 - 64,
                return_word: 0x1000 + bytes::CONTINUATIONS[i],
                history_prefix: 1,
                acknowledgement: if i == 3 {
                    NormalAcknowledgement::CallerCheckpoint
                } else {
                    NormalAcknowledgement::NextEntry {
                        ordinal: i as u64 + 2,
                    }
                },
            },
        })
        .collect();
    let records = rows[..case.admitted()]
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let admission = Admission {
                generation: id,
                function: row.function,
                invocation: i,
                entry_value: row.record.raw.start.ticks,
            };
            RecordObservation {
                record: Record {
                    admission,
                    terminal: Some(Terminal::Completed {
                        value: i as u64,
                        disposition: Disposition::Retained { rank: i / 2 },
                    }),
                },
                payload: Some(Payload {
                    admission,
                    thread: 1,
                    start_sequence: i as u64,
                    outcome: PayloadOutcome::Completed {
                        end: Observation::Value(row.record.raw.end.ticks),
                        completed_children: 0,
                    },
                }),
            }
        })
        .collect();
    (ready, rows, records)
}
fn meta(r: &Ready) -> Metadata {
    Metadata {
        identity: identity(r.functions[0].entry),
        functions: FUNCTIONS,
        entries: r.functions.each_ref().map(|f| f.entry),
        pid: 17,
        tid: 17,
        registration: 1,
        install: INSTALL,
        number: 1,
        next: 5,
        sequences: (0, r.case.admitted() as u64),
        totals: (NormalTotals::default(), totals(r.case, 4)),
    }
}

fn stream_copy(r: &Ready) -> Stream {
    Stream {
        pid: 17,
        install: INSTALL,
        identity: identity(r.functions[0].entry),
        functions: FUNCTIONS,
        entries: r.functions.each_ref().map(|f| f.entry),
        format: HistoryFormat::AbsoluteV1,
    }
}
#[test]
fn module_session_batch_checks_history_and_every_journal_word() {
    for k in [10, 1000] {
        let (ready, rows, _) = fixture(k);
        let stream = stream_copy(&ready);
        super::stream(&ready, 17, &stream);
        watermark(&ready, Some(1));
        metadata(&ready, 17, meta(&ready));
        let returns: Vec<_> = rows.iter().map(|r| r.record.raw.return_pc).collect();
        let words = native_module::journal_words(&ready, 17, 0x9008, &returns, false);
        super::super::rows(&ready, 0x9008, 17, &rows, &words);
        for i in 0..512 {
            let mut bad = words;
            bad[i] ^= 1;
            refuses(|| super::super::rows(&ready, 0x9008, 17, &rows, &bad));
        }
        for i in 0..4 {
            let mut bad = rows.clone();
            bad[i].record.history_prefix = 0;
            refuses(|| super::super::rows(&ready, 0x9008, 17, &bad, &words));
            bad = rows.clone();
            bad[i].record.raw.owner = RawIntervalOwner::FunctionClosed {
                generation: ready.journal.as_ref().unwrap().a_generation,
            };
            refuses(|| super::super::rows(&ready, 0x9008, 17, &bad, &words));
        }
        for field in 0..6 {
            let mut bad = stream.clone();
            match field {
                0 => bad.pid += 1,
                1 => bad.install += 1,
                2 => bad.identity.mapping += 1,
                3 => bad.functions.swap(0, 1),
                4 => bad.entries.swap(0, 1),
                _ => bad.format = HistoryFormat::LegacyV1,
            };
            refuses(|| super::stream(&ready, 17, &bad));
        }
        for bad in [None, Some(0), Some(2)] {
            refuses(|| watermark(&ready, bad));
        }
        let mut old = ready.clone();
        old.case = Case::new(0, 16, 6, 6, 0);
        refuses(|| super::stream(&old, 17, &stream));
        refuses(|| watermark(&old, Some(1)));
    }
}
#[test]
fn module_session_report_reclaim_requires_exact_payloads_and_closed_history() {
    for k in [10, 1000] {
        let (ready, rows, records) = fixture(k);
        let generation = records[0].record.admission.generation;
        super::super::records(&ready, &rows, generation.get(), &records);
        for i in 0..4 {
            for field in 0..8 {
                let mut bad = records.clone();
                let r = &mut bad[i];
                match field {
                    0 => r.record.admission.function = FUNCTIONS[(i + 1) % 2],
                    1 => r.record.admission.invocation += 1,
                    2 => r.record.admission.entry_value += 1,
                    3 => {
                        r.record.terminal = Some(Terminal::Completed {
                            value: i as u64,
                            disposition: Disposition::Retained { rank: i / 2 + 1 },
                        })
                    }
                    4 => r.payload.as_mut().unwrap().start_sequence += 1,
                    5 => r.payload.as_mut().unwrap().thread += 1,
                    6 => {
                        r.payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                            end: Observation::Value(999),
                            completed_children: 0,
                        }
                    }
                    _ => r.payload = None,
                };
                refuses(|| super::super::records(&ready, &rows, generation.get(), &bad));
            }
        }
        refuses(|| super::super::records(&ready, &rows, generation.get(), &records[..3]));
        let bound = HistoryBinding::Published {
            action_index: 0,
            generation,
        };
        let removed = HistoryBinding::Removed {
            action_index: 1,
            generation,
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
                    generation,
                    function: None,
                    current: published.then_some(generation),
                    group: None,
                }],
            };
            chunk(generation, published, &c);
            for field in 0..9 {
                let mut bad = c.clone();
                match field {
                    0 => bad.number += 1,
                    1 => bad.range.start += 1,
                    2 => bad.range.end += 1,
                    3 => bad.before = removed,
                    4 => bad.after = HistoryBinding::Initial,
                    5 => bad.actions[0].kind = ActionKind::FailedAfter,
                    6 => bad.actions[0].function = Some(FUNCTIONS[1]),
                    7 => bad.actions[0].current = if published { None } else { Some(generation) },
                    _ => bad.actions.push(bad.actions[0]),
                };
                refuses(|| chunk(generation, published, &bad));
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
        banks(2, false);
        banks(3, true);
        for field in 0..9 {
            let mut bad = w.clone();
            match field {
                0 => bad.number += 1,
                1 => bad.range.end += 1,
                2 => bad.before = bound,
                3 => bad.after = bound,
                4 => bad.actions.push(Action {
                    kind: ActionKind::Removed,
                    generation,
                    function: None,
                    current: None,
                    group: None,
                }),
                5 => bad.current = Some(generation),
                6 => bad.enabled[0] = false,
                7 => bad.status = ControllerStatus::TerminalFailure,
                _ => bad.failed = Some(generation),
            };
            refuses(|| closed(removed, &bad));
        }
        refuses(|| banks(2, true));
        refuses(|| banks(3, false));
    }
}
