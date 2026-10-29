//! Fabricated copy controls, not loaded modules, callbacks or native returns.
use super::*;
use check::{Error, Expected};
use rapid_profiler::frontend::{Action, ActionKind, ControllerSnapshot, ControllerStatus, Payload};
use rapid_profiler::frontend_native::{NormalModuleRecord, NormalRecord, RawTimestamp};
use rapid_profiler::generation::{Admission, Epoch, Record};
const ENTRIES: [u64; 2] = [0x1000, 0x1080];
const RETURNS: [[u64; 2]; 2] = [[0x1023, 0x1047], [0x1097, 0x10a8]];
struct Fixture {
    k: usize,
    generation: rapid_profiler::generation::GenerationId,
    rows: Vec<NormalModuleRecord>,
    records: Vec<RecordObservation>,
    history: ControllerSnapshot,
}
impl Fixture {
    fn new(k: usize) -> Self {
        let generation = Epoch::new(
            &FUNCTIONS,
            Config {
                retained_per_function: k,
                max_inflight: 1,
                max_invocations: 32,
            },
        )
        .unwrap()
        .id();
        let rows: Vec<_> = (0..CALLS)
            .map(|i| NormalModuleRecord {
                function: FUNCTIONS[i % 2],
                record: NormalRecord {
                    raw: RawInterval {
                        ordinal: i as u64 + 1,
                        entry_pc: ENTRIES[i % 2],
                        return_pc: RETURNS[i % 2][(i / 2) % 2],
                        owner: if i < 2 * k {
                            RawIntervalOwner::Sampled {
                                generation: generation.get(),
                                invocation: i,
                            }
                        } else {
                            RawIntervalOwner::FunctionClosed {
                                generation: generation.get(),
                            }
                        },
                        start: RawTimestamp {
                            ticks: i as u64 * 100,
                            aux: 3,
                        },
                        end: RawTimestamp {
                            ticks: i as u64 * 100 + 90,
                            aux: 3,
                        },
                    },
                    entry_rsp: 0x7ff8,
                    return_word: 0x2100,
                    history_prefix: 1,
                    acknowledgement: if i + 1 == CALLS {
                        NormalAcknowledgement::CallerCheckpoint
                    } else {
                        NormalAcknowledgement::NextEntry {
                            ordinal: i as u64 + 2,
                        }
                    },
                },
            })
            .collect();
        let records = rows[..2 * k]
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let admission = Admission {
                    generation,
                    function: r.function,
                    invocation: i,
                    entry_value: r.record.raw.start.ticks,
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
                            end: Observation::Value(r.record.raw.end.ticks),
                            completed_children: 0,
                        },
                    }),
                }
            })
            .collect();
        let history = ControllerSnapshot {
            status: ControllerStatus::Ready,
            current: None,
            enabled: vec![true],
            retained_failed_generation: None,
            actions: vec![
                Action {
                    kind: ActionKind::Published,
                    generation,
                    function: None,
                    current: Some(generation),
                    group: None,
                },
                Action {
                    kind: ActionKind::Removed,
                    generation,
                    function: None,
                    current: None,
                    group: None,
                },
            ],
        };
        Self {
            k,
            generation,
            rows,
            records,
            history,
        }
    }
    fn expected(&self) -> Expected<'_> {
        Expected {
            identity: identity(ENTRIES[0]),
            pid: 17,
            entries: ENTRIES,
            ends: [0x1050, 0x10b0],
            returns: [&RETURNS[0], &RETURNS[1]],
            generation: self.generation.get(),
            k: self.k,
            stack: (0x7000, 0x9000),
            caller: (0x2000, 0x3000),
        }
    }
    fn words(&self) -> [u64; 512] {
        let mut words = [0; 512];
        words[..4].copy_from_slice(&[64, 0, 17, 0]);
        for (i, row) in self.rows.iter().enumerate() {
            let r = row.record;
            let (kind, bits) = if i < self.k * 2 {
                (1, (i as u64 + 1) | (1 << 13))
            } else {
                (3, (1 << 13) | (3 << 22))
            };
            for event in 0..2 {
                let at = 4 + 14 * i + 7 * event;
                words[at..at + 7].copy_from_slice(&[
                    kind + event as u64,
                    i as u64 + 1,
                    if event == 0 {
                        ENTRIES[i % 2]
                    } else {
                        r.raw.return_pc
                    },
                    r.entry_rsp,
                    r.return_word,
                    self.generation.get(),
                    bits,
                ]);
            }
        }
        words
    }
}
#[test]
fn module_keeps_all_csv_and_length_inputs_and_per_function_counters() {
    let data = Data::new();
    data.check(0, 0);
    for i in 0..16 {
        assert_eq!(case(2 * i), (0, csv::CASES[i].0.len(), csv::CASES[i].1));
        let c = cases::CASES[i % 8];
        assert_eq!(case(2 * i + 1), (1, c.bound, c.expected));
        assert_eq!(
            &data.input[2 * i][16..16 + csv::CASES[i].0.len()],
            csv::CASES[i].0
        );
        assert_eq!(&data.input[2 * i + 1][16..80], cases::input(c));
    }
    assert_eq!(
        totals(32, 32, 16),
        NormalTotals {
            entered: 32,
            ret_observed: 32,
            confirmed: 32,
            completed: 32,
            unsampled: 0
        }
    );
    assert_eq!(
        totals(32, 32, 1),
        NormalTotals {
            entered: 32,
            ret_observed: 32,
            confirmed: 32,
            completed: 2,
            unsampled: 30
        }
    );
    assert_eq!(totals(2, 1, 1).completed, 1);
    assert_eq!(totals(3, 2, 1).completed, 2);
}
#[test]
fn module_batch_requires_function_entry_return_owner_and_final_ack_joins() {
    for k in [16, 1] {
        let f = Fixture::new(k);
        let e = f.expected();
        let m = check::metadata(e);
        assert_eq!(check::batch(e, m, &f.rows, &f.words()), Ok(()));
        assert_eq!(
            check::batch(e, m, &f.rows[..31], &f.words()),
            Err(Error::Population)
        );
        for change in 0..7 {
            let mut rows = f.rows.clone();
            match change {
                0 => rows[0].function = FUNCTIONS[1],
                1 => rows[0].record.raw.entry_pc = ENTRIES[1],
                2 => rows[0].record.raw.return_pc = RETURNS[1][0],
                3 => {
                    rows[1].record.raw.owner = RawIntervalOwner::FunctionClosed {
                        generation: f.generation.get(),
                    }
                }
                4 => rows[0].record.history_prefix = 2,
                5 => {
                    rows[31].record.acknowledgement =
                        NormalAcknowledgement::NextEntry { ordinal: 33 }
                }
                _ => rows[0].record.acknowledgement = NormalAcknowledgement::CallerCheckpoint,
            }
            assert_eq!(check::batch(e, m, &rows, &f.words()), Err(Error::Record));
        }
        let mut m = m;
        m.functions.swap(0, 1);
        assert_eq!(
            check::batch(e, m, &f.rows, &f.words()),
            Err(Error::Identity)
        );
    }
}
#[test]
fn module_requires_both_ret_populations_and_all_512_words_for_each_k() {
    for k in [16, 1] {
        let f = Fixture::new(k);
        let e = f.expected();
        let m = check::metadata(e);
        for word in 0..512 {
            let mut words = f.words();
            words[word] ^= 1;
            assert_eq!(check::batch(e, m, &f.rows, &words), Err(Error::Journal));
        }
        for missing in 0..2 {
            let mut rows = f.rows.clone();
            for r in rows.iter_mut().filter(|r| r.function == FUNCTIONS[missing]) {
                r.record.raw.return_pc = RETURNS[missing][0];
            }
            assert_eq!(check::batch(e, m, &rows, &f.words()), Err(Error::Coverage));
        }
    }
}
#[test]
fn module_report_keeps_global_slots_and_function_local_ranks() {
    for k in [16, 1] {
        let f = Fixture::new(k);
        let validate = |records: &[RecordObservation], h: &ControllerSnapshot| {
            check::report(f.expected(), &f.rows, f.generation.get(), records, h)
        };
        assert_eq!(validate(&f.records, &f.history), Ok(()));
        assert_eq!(
            validate(&f.records[..f.records.len() - 1], &f.history),
            Err(Error::Population)
        );
        for change in 0..7 {
            let mut records = f.records.clone();
            match change {
                0 => records[1].record.admission.function = FUNCTIONS[0],
                1 => records[1].record.admission.invocation = 0,
                2 => {
                    records[1].record.terminal = Some(Terminal::Completed {
                        value: 1,
                        disposition: Disposition::Retained { rank: 1 },
                    })
                }
                3 => records[1].payload.as_mut().unwrap().admission.function = FUNCTIONS[0],
                4 => records[1].payload.as_mut().unwrap().start_sequence = 0,
                5 => records[0].payload = None,
                _ => records.swap(0, 1),
            }
            assert_eq!(validate(&records, &f.history), Err(Error::Report));
        }
        let mut h = f.history.clone();
        h.actions.swap(0, 1);
        assert_eq!(validate(&f.records, &h), Err(Error::History));
    }
}
