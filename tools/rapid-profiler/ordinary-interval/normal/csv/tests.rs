//! Fabricated immutable data controls; never create a native attachment or call.
use super::*;
use check::{Error, Expected, Metadata};
use rapid_profiler::frontend::{Action, ActionKind, ControllerSnapshot, ControllerStatus, Payload};
use rapid_profiler::frontend_native::{NormalRecord, RawTimestamp};
use rapid_profiler::generation::{Admission, Epoch, Record};
const RETURNS: [u64; 2] = [0x1023, 0x1047];
struct Fixture {
    generation: rapid_profiler::generation::GenerationId,
    rows: Vec<NormalRecord>,
    records: Vec<RecordObservation>,
    history: ControllerSnapshot,
}
impl Fixture {
    fn new() -> Self {
        let generation = Epoch::new(&[FUNCTION], CONFIG).unwrap().id();
        let rows: Vec<_> = (0..CALLS)
            .map(|i| NormalRecord {
                raw: RawInterval {
                    ordinal: i as u64 + 1,
                    entry_pc: 0x1000,
                    return_pc: RETURNS[i % 2],
                    owner: RawIntervalOwner::Sampled {
                        generation: generation.get(),
                        invocation: i,
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
            })
            .collect();
        let records = rows
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let admission = Admission {
                    generation,
                    function: FUNCTION,
                    invocation: i,
                    entry_value: r.raw.start.ticks,
                };
                RecordObservation {
                    record: Record {
                        admission,
                        terminal: Some(Terminal::Completed {
                            value: i as u64,
                            disposition: Disposition::Retained { rank: i },
                        }),
                    },
                    payload: Some(Payload {
                        admission,
                        thread: 1,
                        start_sequence: i as u64,
                        outcome: PayloadOutcome::Completed {
                            end: Observation::Value(r.raw.end.ticks),
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
            generation,
            rows,
            records,
            history,
        }
    }
    fn expected(&self) -> Expected<'_> {
        Expected {
            pid: 17,
            tid: 17,
            entry: 0x1000,
            end: 0x1050,
            returns: &RETURNS,
            generation: self.generation.get(),
            stack: (0x7000, 0x9000),
            caller: (0x2000, 0x3000),
        }
    }
    fn words(&self) -> [u64; 512] {
        let mut words = [0; 512];
        words[..4].copy_from_slice(&[32, 0, 17, 0]);
        for (i, r) in self.rows.iter().enumerate() {
            for event in 0..2 {
                let at = 4 + 14 * i + 7 * event;
                words[at..at + 7].copy_from_slice(&[
                    event as u64 + 1,
                    i as u64 + 1,
                    if event == 0 { 0x1000 } else { r.raw.return_pc },
                    r.entry_rsp,
                    r.return_word,
                    self.generation.get(),
                    (i as u64 + 1) | (1 << 13),
                ]);
            }
        }
        words
    }
    fn batch(&self, m: Metadata, rows: &[NormalRecord], words: &[u64]) -> check::Check {
        check::batch(self.expected(), m, rows, words)
    }
}

#[test]
fn csv_corpus_and_guarded_results_keep_every_literal_case() {
    assert_eq!(CASES.len(), 16);
    assert_eq!(CASES[0], (&b""[..], 1));
    assert_eq!(CASES.iter().map(|c| c.1).sum::<u64>(), 33);
    let mut data = Data::new();
    assert_eq!(data.check(0, 0), Ok(()));
    for (i, &(bytes, expected)) in CASES.iter().enumerate() {
        assert!(!bytes.contains(&b'\n') && !bytes.contains(&b'\r'));
        assert_eq!(&data.input[i][16..16 + bytes.len()], bytes);
        data.results[0].values[i] = expected;
        assert_eq!(data.check(i + 1, 0), Ok(()));
    }
    for (i, &(_, value)) in CASES.iter().enumerate() {
        data.results[1].values[i] = value;
    }
    assert_eq!(data.check(16, 16), Ok(()));
    data.results[1].values.swap(2, 3); // Same aggregate, wrong individual results.
    assert_eq!(data.check(16, 16), Err(Error::Value));
    data.results[1].values.swap(2, 3);
    data.input[0][0] ^= 1;
    assert_eq!(data.check(16, 16), Err(Error::Input));
    data.input[0][0] ^= 1;
    data.results[1].after[0] ^= 1;
    assert_eq!(data.check(16, 16), Err(Error::Input));
}
#[test]
fn csv_batch_refuses_identity_owner_acknowledgement_and_stack_corruption() {
    let f = Fixture::new();
    let m = check::metadata(f.expected());
    assert_eq!(f.batch(m, &f.rows, &f.words()), Ok(()));
    for change in 0..8 {
        let mut bad = m;
        match change {
            0 => bad.legacy = false,
            1 => bad.pid += 1,
            2 => bad.registration += 1,
            3 => bad.install += 1,
            4 => bad.number += 1,
            5 => bad.next += 1,
            6 => bad.totals.1.confirmed -= 1,
            _ => bad.sequences.0 += 1,
        }
        assert_eq!(f.batch(bad, &f.rows, &f.words()), Err(Error::Identity));
    }
    assert_eq!(
        f.batch(m, &f.rows[..15], &f.words()),
        Err(Error::Population)
    );
    for change in 0..8 {
        let mut rows = f.rows.clone();
        match change {
            0 => rows[0].raw.ordinal += 1,
            1 => rows[0].raw.entry_pc += 1,
            2 => {
                rows[0].raw.owner = RawIntervalOwner::FunctionClosed {
                    generation: f.generation.get(),
                }
            }
            3 => rows[0].history_prefix = 2,
            4 => rows[0].acknowledgement = NormalAcknowledgement::CallerCheckpoint,
            5 => rows[15].acknowledgement = NormalAcknowledgement::NextEntry { ordinal: 17 },
            6 => rows[0].entry_rsp = 0x7008,
            _ => rows[0].return_word = 0x3000,
        }
        let error = if change < 6 {
            Error::Record
        } else {
            Error::Stack
        };
        assert_eq!(f.batch(m, &rows, &f.words()), Err(error));
    }
}
#[test]
fn csv_all_return_roles_and_every_journal_word_are_mandatory() {
    let mut f = Fixture::new();
    let m = check::metadata(f.expected());
    for word in 0..512 {
        let mut words = f.words();
        words[word] ^= 1;
        assert_eq!(f.batch(m, &f.rows, &words), Err(Error::Journal));
    }
    let mut rows = f.rows.clone();
    for r in &mut rows {
        r.raw.return_pc = RETURNS[0];
    }
    assert_eq!(f.batch(m, &rows, &f.words()), Err(Error::Coverage));
    // Raw zero and full-width differences remain observations, not estimates.
    f.rows[0].raw.end.ticks = 0;
    f.rows[1].raw.start.ticks = 0;
    f.rows[1].raw.end.ticks = u64::MAX;
    assert_eq!(f.batch(m, &f.rows, &f.words()), Ok(()));
    f.rows[0].raw.start.ticks = 1;
    assert_eq!(f.batch(m, &f.rows, &f.words()), Err(Error::Clock));
    f.rows[0].raw.start.ticks = 0;
    f.rows[0].raw.end.aux += 1;
    assert_eq!(f.batch(m, &f.rows, &f.words()), Err(Error::Clock));
}
#[test]
fn csv_report_history_requires_all_slots_payloads_and_two_actions() {
    let f = Fixture::new();
    let validate = |records: &[RecordObservation], h: &ControllerSnapshot| {
        check::report(f.expected(), &f.rows, f.generation.get(), records, h)
    };
    assert_eq!(validate(&f.records, &f.history), Ok(()));
    assert_eq!(
        validate(&f.records[..15], &f.history),
        Err(Error::Population)
    );
    for change in 0..6 {
        let mut records = f.records.clone();
        match change {
            0 => records.swap(0, 1),
            1 => records[0].payload = None,
            2 => {
                records[0].record.terminal = Some(Terminal::Completed {
                    value: 1,
                    disposition: Disposition::Retained { rank: 0 },
                })
            }
            3 => {
                records[0].record.terminal = Some(Terminal::Completed {
                    value: 0,
                    disposition: Disposition::Retained { rank: 1 },
                })
            }
            4 => records[0].payload.as_mut().unwrap().start_sequence = 1,
            _ => {
                records[0].payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                    end: Observation::Value(90),
                    completed_children: 1,
                }
            }
        }
        assert_eq!(validate(&records, &f.history), Err(Error::Report));
    }
    for change in 0..5 {
        let mut h = f.history.clone();
        match change {
            0 => {
                h.actions.pop();
            }
            1 => h.actions.swap(0, 1),
            2 => h.actions[1].current = Some(f.generation),
            3 => h.current = Some(f.generation),
            _ => h.enabled[0] = false,
        }
        assert_eq!(validate(&f.records, &h), Err(Error::History));
    }
}
#[test]
fn csv_failed_real_storage_postflight_withholds_transfer() {
    let mut data = Data::new();
    for leg in data.results.iter_mut() {
        for (i, value) in leg.values.iter_mut().enumerate() {
            *value = CASES[i].1;
        }
    }
    let transfers = std::cell::Cell::new(0);
    assert_eq!(
        after_postflight(|| data.check(16, 16), || transfers.set(transfers.get() + 1)),
        Ok(())
    );
    assert_eq!(transfers.get(), 1);
    data.input[15][95] ^= 1;
    assert_eq!(
        after_postflight(|| data.check(16, 16), || transfers.set(transfers.get() + 1)),
        Err(Error::Input)
    );
    assert_eq!(transfers.get(), 1);
    data.input[15][95] ^= 1;
    data.results[1].values[15] = u64::MAX;
    assert_eq!(
        after_postflight(|| data.check(16, 16), || transfers.set(transfers.get() + 1)),
        Err(Error::Value)
    );
    assert_eq!(transfers.get(), 1);
}

#[test]
fn csv_output_keeps_all_cases_and_full_width_endpoint_words() {
    let mut f = Fixture::new();
    f.rows[0].raw.end.ticks = 0;
    f.rows[1].raw.start.ticks = 0;
    f.rows[1].raw.end.ticks = u64::MAX;
    assert_eq!(
        f.batch(check::metadata(f.expected()), &f.rows, &f.words()),
        Ok(())
    );
    let mut data = Data::new();
    for leg in data.results.iter_mut() {
        for (i, value) in leg.values.iter_mut().enumerate() {
            *value = CASES[i].1;
        }
    }
    let text = output(&data, &f.rows, f.expected(), 3, 0x2080);
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines.len(), 18);
    assert_eq!(lines[0], HEADER);
    for (i, line) in lines[1..17].iter().enumerate() {
        let fields: Vec<u64> = line.split(',').map(|s| s.parse().unwrap()).collect();
        assert_eq!(fields.len(), 17);
        assert_eq!(
            &fields[..5],
            &[
                i as u64 + 1,
                CASES[i].0.len() as u64,
                CASES[i].1,
                CASES[i].1,
                CASES[i].1
            ]
        );
        assert_eq!(
            fields[15..],
            if i == 15 { [2, 0] } else { [1, i as u64 + 2] }
        );
    }
    assert_eq!(lines[2].split(',').nth(12), Some("18446744073709551615"));
    assert!(lines[17].contains("declared_returns=2 observed_returns=2 pid=17 tid=17 cpu=3"));
    assert!(lines[17].contains("caller_entry=8320"));
    assert!(text.ends_with('\n') && text.len() <= OUTPUT_CAP);
}

#[test]
fn csv_mapping_classes_keep_private_source_and_shared_images_distinct() {
    let maps = "1000-2000 r-xp 00000000 00:00 1 /source\n\
                3000-4000 r-xs 00000000 00:00 2 /image\n\
                5000-6000 rw-p 00000000 00:00 0 [stack]\n";
    for (address, mode, end) in [
        (0x1000, "r-xp", 0x2000),
        (0x3000, "r-xs", 0x4000),
        (0x5000, "rw-p", 0x6000),
    ] {
        assert_eq!(mapping_in(maps, address, mode), Some((address, end)));
        assert_eq!(mapping_in(maps, end - 1, mode), Some((address, end)));
        assert_eq!(mapping_in(maps, end, mode), None);
        for wrong in [
            "r-xp", "r-xs", "rw-p", "rw-s", "rwxp", "rwxs", "r--p", "---p",
        ] {
            if wrong != mode {
                assert_eq!(mapping_in(maps, address, wrong), None);
            }
        }
    }
    assert_eq!(mapping_in(maps, 0x2000, "r-xp"), None);
    assert_eq!(mapping_in("", 0x1000, "r-xp"), None);
    let overlapping = format!("{maps}1000-1800 r-xp 00000000 00:00 1 /duplicate\n");
    assert_eq!(mapping_in(&overlapping, 0x1000, "r-xp"), None);
    assert_eq!(
        mapping_in(&maps.replace("r-xs", "rwxs"), 0x3000, "r-xs"),
        None
    );
}
