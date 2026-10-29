//! Fabricated copies exercise production joins; no executable/receipt authority.
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
            max_invocations: 32,
        },
    )
    .unwrap()
    .id();
    let case = Case::new(0, k, 6, 6, 0);
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
#[test]
fn module_rows_join_function_owner_ack_and_all_512_words() {
    for k in [1, 16] {
        for order in [0, 1] {
            let (mut ready, mut rows, _) = fixture(k);
            ready.case = Case::new(0, k, 6, 6, order);
            for (i, r) in rows.iter_mut().enumerate() {
                r.function = FUNCTIONS[ready.case.function(i)];
                r.record.raw.entry_pc = ready.target(i).entry;
                r.record.raw.return_pc = ready.target(i).returns[0];
            }
            let returns = rows
                .iter()
                .map(|r| r.record.raw.return_pc)
                .collect::<Vec<_>>();
            let words = native_module::journal_words(&ready, 17, 0x9008, &returns, false);
            metadata(&ready, 17, meta(&ready));
            super::rows(&ready, 0x9008, 17, &rows, &words);
            for field in 0..12 {
                let mut m = meta(&ready);
                match field {
                    0 => m.identity.mapping += 1,
                    1 => m.functions.swap(0, 1),
                    2 => m.entries.swap(0, 1),
                    3 => m.pid += 1,
                    4 => m.tid += 1,
                    5 => m.registration += 1,
                    6 => m.install += 1,
                    7 => m.number += 1,
                    8 => m.next += 1,
                    9 => m.sequences.0 += 1,
                    10 => m.sequences.1 += 1,
                    _ => m.totals.1.unsampled += 1,
                };
                refuses(|| metadata(&ready, 17, m));
            }
            for i in 0..4 {
                for field in 0..8 {
                    let mut bad = rows.clone();
                    let r = &mut bad[i];
                    match field {
                        0 => r.function = FUNCTIONS[ready.case.function((i + 1) % 4)],
                        1 => r.record.raw.ordinal += 1,
                        2 => r.record.raw.entry_pc += 1,
                        3 => r.record.raw.return_pc = ready.target((i + 1) % 4).returns[0],
                        4 => {
                            r.record.raw.owner = RawIntervalOwner::FunctionClosed { generation: 0 }
                        }
                        5 => r.record.entry_rsp += 8,
                        6 => r.record.return_word += 1,
                        _ => {
                            r.record.acknowledgement =
                                NormalAcknowledgement::NextEntry { ordinal: 999 }
                        }
                    };
                    refuses(|| super::rows(&ready, 0x9008, 17, &bad, &words));
                }
            }
            for i in 0..512 {
                let mut bad = words;
                bad[i] ^= 1;
                refuses(|| super::rows(&ready, 0x9008, 17, &rows, &bad));
            }
            refuses(|| super::rows(&ready, 0x9008, 17, &rows[..3], &words));
            assert_eq!(
                (
                    totals(ready.case, 3).completed,
                    totals(ready.case, 3).unsampled
                ),
                if k == 1 { (2, 1) } else { (3, 0) }
            );
        }
    }
}
#[test]
fn module_report_keeps_global_slots_and_function_local_ranks() {
    for k in [1, 16] {
        let (ready, mut rows, records) = fixture(k);
        let generation = ready.journal.as_ref().unwrap().a_generation;
        super::records(&ready, &rows, generation, &records);
        for i in 0..records.len() {
            for field in 0..7 {
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
                    _ => r.payload = None,
                };
                refuses(|| super::records(&ready, &rows, generation, &bad));
            }
        }
        refuses(|| super::records(&ready, &rows, generation + 1, &records));
        refuses(|| super::records(&ready, &rows, generation, &records[..records.len() - 1]));
        // Preserve old native raw-clock unavailability semantics, not a new
        // elapsed-time gate or suppression of either timestamp.
        rows[0].record.raw.end.aux += 1;
        let mut bad = records.clone();
        refuses(|| super::records(&ready, &rows, generation, &bad));
        bad[0].payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
            end: Observation::Unavailable(1),
            completed_children: 0,
        };
        super::records(&ready, &rows, generation, &bad);
    }
}
