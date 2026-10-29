//! Fabricated copies call the real one-call predicates; no native authority.
use super::*;
use crate::oracle::native_ordinary::normal_caller::{JournalReady, module::Function, rust_invoke};
use rapid_profiler::frontend::{Action, Payload};
use rapid_profiler::frontend_native::{NormalRecord, RawInterval, RawTimestamp};
use rapid_profiler::generation::{Admission, Config, Epoch, Record};
use std::panic::{AssertUnwindSafe, catch_unwind};
fn refuses(f: impl FnOnce()) {
    assert!(catch_unwind(AssertUnwindSafe(f)).is_err());
}
#[test]
fn one_call_metadata_payload_report_and_history_are_exact() {
    for function in 0..2 {
        for order in 0..2 {
            for clock in 0..4 {
                let id = Epoch::new(
                    &FUNCTIONS,
                    Config {
                        retained_per_function: 16,
                        max_inflight: 1,
                        max_invocations: 32,
                    },
                )
                .unwrap()
                .id();
                let plan = rust_invoke::admit(&[
                    0x53, 0x48, 0x89, 0xcb, 0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6,
                    0xff, 0xd0, 0x48, 0x89, 0x03, 0x5b, 0xc3,
                ])
                .unwrap();
                let ready = Ready {
                    caller: 0x1080,
                    caller_immutable: vec![],
                    functions: [0x3000, 0x3040].map(|entry| Function {
                        entry,
                        heads: vec![entry, entry + 5],
                        returns: vec![entry + 5],
                        boundaries: vec![(entry, entry), (entry + 5, entry + 5)],
                    }),
                    immutable: vec![],
                    original_source: vec![],
                    journal: Some(JournalReady {
                        address: 0x7000,
                        a_generation: id.get(),
                        b_generation: None,
                        helper_tid: None,
                    }),
                    case: copied::Case::new(function, 0, 6, 6, order),
                    plan,
                };
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
                        RawTimestamp { ticks: 0, aux: 1 },
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
                    function: FUNCTIONS[ready.case.selected()],
                    record: NormalRecord {
                        raw: RawInterval {
                            ordinal: 1,
                            entry_pc: ready.target().entry,
                            return_pc: ready.target().returns[0],
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
                let record = RecordObservation {
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
                };
                let meta = Metadata {
                    identity: identity(0x3000),
                    functions: FUNCTIONS,
                    entries: [0x3000, 0x3040],
                    pid: 17,
                    tid: 17,
                    registration: 1,
                    install: INSTALL,
                    number: 1,
                    next: 2,
                    sequences: (0, 1),
                    totals: (NormalTotals::default(), totals(1)),
                };
                let words =
                    copied::journal_words(&ready, 17, 0x9008, &[row.record.raw.return_pc], false);
                metadata(&ready, 17, meta);
                rows(&ready, 0x9008, 17, &[row], &words);
                records(&ready, &[row], id.get(), &[record]);
                for field in 0..13 {
                    let mut m = meta;
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
                        11 => m.totals.0.entered += 1,
                        _ => m.totals.1.unsampled += 1,
                    };
                    refuses(|| metadata(&ready, 17, m));
                }
                for field in 0..9 {
                    let mut bad = row;
                    match field {
                        0 => bad.function = FUNCTIONS[1 - ready.case.selected()],
                        1 => bad.record.raw.ordinal += 1,
                        2 => bad.record.raw.entry_pc += 1,
                        3 => {
                            bad.record.raw.return_pc =
                                ready.functions[1 - ready.case.selected()].returns[0]
                        }
                        4 => {
                            bad.record.raw.owner = RawIntervalOwner::Sampled {
                                generation: id.get(),
                                invocation: 1,
                            }
                        }
                        5 => bad.record.entry_rsp += 8,
                        6 => bad.record.return_word += 1,
                        7 => bad.record.history_prefix = 0,
                        _ => {
                            bad.record.acknowledgement =
                                NormalAcknowledgement::NextEntry { ordinal: 2 }
                        }
                    };
                    refuses(|| rows(&ready, 0x9008, 17, &[bad], &words));
                }
                for i in 0..512 {
                    let mut bad = words;
                    bad[i] ^= 1;
                    refuses(|| rows(&ready, 0x9008, 17, &[row], &bad));
                }
                refuses(|| rows(&ready, 0x9008, 17, &[], &words));
                refuses(|| rows(&ready, 0x9008, 17, &[row, row], &words));
                for field in 0..10 {
                    let mut bad = record;
                    match field {
                        0 => bad.record.admission.function = FUNCTIONS[1 - ready.case.selected()],
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
                        _ => {
                            bad.payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                                end: observation,
                                completed_children: 1,
                            }
                        }
                    };
                    refuses(|| records(&ready, &[row], id.get(), &[bad]));
                }
                refuses(|| records(&ready, &[row], id.get(), &[]));
                refuses(|| records(&ready, &[row], id.get(), &[record, record]));
                let h = ControllerSnapshot {
                    status: ControllerStatus::Ready,
                    current: None,
                    enabled: vec![true],
                    retained_failed_generation: None,
                    actions: vec![
                        Action {
                            kind: ActionKind::Published,
                            generation: id,
                            function: None,
                            current: Some(id),
                            group: None,
                        },
                        Action {
                            kind: ActionKind::Removed,
                            generation: id,
                            function: None,
                            current: None,
                            group: None,
                        },
                    ],
                };
                history(&h, id.get());
                for field in 0..7 {
                    let mut bad = h.clone();
                    match field {
                        0 => bad.current = Some(id),
                        1 => bad.enabled[0] = false,
                        2 => bad.retained_failed_generation = Some(id),
                        3 => bad.actions.swap(0, 1),
                        4 => bad.actions[1].current = Some(id),
                        5 => bad.actions[1].function = Some(row.function),
                        _ => {
                            bad.actions.pop();
                        }
                    };
                    refuses(|| history(&bad, id.get()));
                }
            }
        }
    }
}
